//! RLP encoding and decoding specialized for the shapes a trie witness actually contains.
//!
//! `alloy_rlp` handles every legal RLP encoding, and pays for that generality twice over: its
//! decoder branches through the full header space on each item, and its encoder writes through
//! `&mut dyn BufMut`, so every byte costs a virtual call. Trie nodes use a handful of shapes —
//! 16-child lists, 32-byte digest references, short strings, the empty string — and each is
//! reachable in a comparison or two. The functions here take those paths directly and fall back
//! to `alloy_rlp` for anything else, so behaviour is identical and only the common cases get
//! faster.
//!
//! Every specialization is checked against `alloy_rlp` in this module's tests, since agreeing
//! with the general implementation on all inputs is the whole correctness requirement.

use bytes::Buf;

use crate::Error;

/// The RLP encoding of an empty node reference.
pub(crate) const NULL_NODE_REF_SLICE: &[u8] = &[alloy_rlp::EMPTY_STRING_CODE];

/// Splits the first `cnt` bytes off `buf`.
///
/// # Safety
///
/// `buf` must hold at least `cnt` bytes.
#[inline(always)]
pub(crate) unsafe fn advance_unchecked<'a>(buf: &mut &'a [u8], cnt: usize) -> &'a [u8] {
    let bytes = &buf[..cnt];
    buf.advance(cnt);
    bytes
}

/// Decodes and advances past one RLP item, returning its full encoding and payload. Common
/// single-byte headers are handled directly, with the generic decoder as a fallback.
#[inline(always)]
pub(crate) fn decode_rlp_item<'a>(buf: &mut &'a [u8]) -> Result<(&'a [u8], &'a [u8]), Error> {
    let item_start = *buf;
    if item_start.first() == Some(&alloy_rlp::EMPTY_STRING_CODE) {
        *buf = &item_start[1..];
        return Ok((&item_start[..1], &item_start[1..1]));
    }
    if item_start.first() == Some(&(alloy_rlp::EMPTY_STRING_CODE + 32)) {
        let item = item_start.get(..33).ok_or(alloy_rlp::Error::InputTooShort)?;
        *buf = &item_start[33..];
        return Ok((item, &item[1..]));
    }
    if let Some(code @ 0x81..=0xb7) = item_start.first().copied() {
        let payload_length = usize::from(code - alloy_rlp::EMPTY_STRING_CODE);
        let item = item_start.get(..payload_length + 1).ok_or(alloy_rlp::Error::InputTooShort)?;
        let payload = &item[1..];
        if payload_length == 1 && payload[0] < alloy_rlp::EMPTY_STRING_CODE {
            return Err(alloy_rlp::Error::NonCanonicalSingleByte.into());
        }
        *buf = &item_start[payload_length + 1..];
        return Ok((item, payload));
    }

    let alloy_rlp::Header { payload_length, .. } = alloy_rlp::Header::decode(buf)?;
    // SAFETY: the header was decoded, so the item contains its declared payload.
    let payload = unsafe { advance_unchecked(buf, payload_length) };
    let item_length = item_start.len() - buf.len();
    Ok((&item_start[..item_length], payload))
}

/// Decodes an MPT node header, specializing the canonical list headers used by resolved nodes.
/// The generic decoder remains the fallback for strings and larger lists.
#[inline(always)]
pub(crate) fn decode_node_header(buf: &mut &[u8]) -> Result<alloy_rlp::Header, Error> {
    let input = *buf;
    match input.first().copied() {
        Some(code @ alloy_rlp::EMPTY_LIST_CODE..=0xf7) => {
            let payload_length = usize::from(code - alloy_rlp::EMPTY_LIST_CODE);
            if input.len() < payload_length + 1 {
                return Err(alloy_rlp::Error::InputTooShort.into());
            }
            *buf = &input[1..];
            Ok(alloy_rlp::Header { list: true, payload_length })
        }
        Some(0xf8) => {
            let payload_length = usize::from(*input.get(1).ok_or(alloy_rlp::Error::InputTooShort)?);
            if payload_length < 56 {
                return Err(alloy_rlp::Error::NonCanonicalSize.into());
            }
            if input.len() < payload_length + 2 {
                return Err(alloy_rlp::Error::InputTooShort.into());
            }
            *buf = &input[2..];
            Ok(alloy_rlp::Header { list: true, payload_length })
        }
        Some(0xf9) => {
            let high = *input.get(1).ok_or(alloy_rlp::Error::InputTooShort)?;
            let low = *input.get(2).ok_or(alloy_rlp::Error::InputTooShort)?;
            if high == 0 {
                return Err(alloy_rlp::Error::LeadingZero.into());
            }
            let payload_length = (usize::from(high) << 8) | usize::from(low);
            if input.len() < payload_length + 3 {
                return Err(alloy_rlp::Error::InputTooShort.into());
            }
            *buf = &input[3..];
            Ok(alloy_rlp::Header { list: true, payload_length })
        }
        _ => alloy_rlp::Header::decode(buf).map_err(Into::into),
    }
}

/// Whether `slice` is the RLP encoding of an empty node reference: a single `EMPTY_STRING_CODE`
/// byte. Written as an explicit pattern match because comparing against [`NULL_NODE_REF_SLICE`]
/// with `==` compiles to a `memcmp` call, whose overhead dwarfs this one-byte check — and trie
/// decoding performs it for every branch child.
#[inline(always)]
pub(crate) fn is_null_ref(slice: &[u8]) -> bool {
    matches!(slice, [byte] if *byte == alloy_rlp::EMPTY_STRING_CODE)
}

/// Writes an RLP header with the given base code (`EMPTY_LIST_CODE` for lists,
/// `EMPTY_STRING_CODE` for strings). Emits the same bytes as [`alloy_rlp::Header::encode`], but
/// is generic over the output buffer: `alloy_rlp` encoding goes through `&mut dyn BufMut`, and
/// the resulting per-write dynamic dispatch is expensive in the zkVM.
#[inline]
pub(crate) fn encode_header<B: alloy_rlp::BufMut>(
    base_code: u8,
    payload_length: usize,
    out: &mut B,
) {
    if payload_length < 56 {
        out.put_u8(base_code + payload_length as u8);
    } else {
        let len_be = payload_length.to_be_bytes();
        let num_len_bytes = alloy_rlp::length_of_length(payload_length) - 1;
        out.put_u8(base_code + 55 + num_len_bytes as u8);
        out.put_slice(&len_be[len_be.len() - num_len_bytes..]);
    }
}

/// RLP-encodes a byte slice as a string. Emits the same bytes as `Encodable for [u8]`, without
/// dynamic dispatch (see [`encode_header`]).
#[inline]
pub(crate) fn encode_slice<B: alloy_rlp::BufMut>(bytes: &[u8], out: &mut B) {
    if let [byte] = bytes {
        if *byte < alloy_rlp::EMPTY_STRING_CODE {
            out.put_u8(*byte);
            return;
        }
    }
    encode_header(alloy_rlp::EMPTY_STRING_CODE, bytes.len(), out);
    out.put_slice(bytes);
}

#[cfg(test)]
mod tests;
