//! Differential tests: every specialization here must agree with `alloy_rlp`.
//!
//! The specializations exist only to reach common encodings in fewer instructions, so the
//! property that matters is indistinguishability from the general implementation. Each test
//! sweeps a leading byte across the whole `u8` range — the dimension that selects which
//! specialized arm runs — against payload lengths straddling the header-form boundaries (1-byte,
//! 2-byte and 3-byte length prefixes), which covers each arm and its fallback.
//!
//! The sweeps also vary the bytes following the lead (see [`Filler`]). For the forms that carry a
//! multi-byte length those bytes *are* the declared length, so a fixed filler would pin each such
//! arm to one length value and leave its canonicality rules unexercised.
//!
//! Errors are compared as accept-or-reject rather than by variant: the decoder's contract is
//! that it rejects what `alloy_rlp` rejects, and the specific variant reaching the caller is not
//! part of it.

use alloc::vec::Vec;

use super::*;

/// Payload lengths that straddle every header form: single byte, `0x81..=0xb7` short string,
/// `0xb8`/`0xf8` one-byte length, and `0xb9`/`0xf9` two-byte length.
const LENS: [usize; 14] = [0, 1, 2, 31, 32, 33, 54, 55, 56, 57, 254, 255, 256, 300];

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect()
}

/// Filler bytes to sweep after the leading byte. For the header forms that carry a multi-byte
/// length, those bytes *are* the declared length, so varying them is what reaches the canonicality
/// rules: `Zeros` produces a length with a leading zero and a long-form length below 56, `Ones`
/// produces a maximal one, and `Pattern` covers the mid-range. Holding this constant would leave
/// each multi-byte-length arm tested at a single declared length.
#[derive(Copy, Clone, Debug)]
enum Filler {
    Pattern,
    Zeros,
    Ones,
}

const FILLERS: [Filler; 3] = [Filler::Pattern, Filler::Zeros, Filler::Ones];

/// Lengths that straddle where a header gains length bytes, plus a few interior values.
const EXTRAS: [usize; 11] = [0, 1, 2, 3, 32, 33, 55, 56, 57, 258, 300];

/// A leading byte followed by `extra` filler bytes. Most combinations are invalid RLP, which is
/// the point: the specialized decoder must reject exactly what `alloy_rlp` rejects.
fn synthetic(lead: u8, extra: usize, filler: Filler) -> Vec<u8> {
    let mut buf = Vec::with_capacity(extra + 1);
    buf.push(lead);
    match filler {
        Filler::Pattern => buf.extend(payload(extra)),
        Filler::Zeros => buf.resize(extra + 1, 0x00),
        Filler::Ones => buf.resize(extra + 1, 0xff),
    }
    buf
}

#[test]
fn decode_node_header_matches_alloy() {
    let mut checked = 0u32;
    for filler in FILLERS {
        for lead in 0..=u8::MAX {
            for extra in EXTRAS {
                let input = synthetic(lead, extra, filler);

                let mut ours = input.as_slice();
                let got = decode_node_header(&mut ours);

                let mut theirs = input.as_slice();
                let want = alloy_rlp::Header::decode(&mut theirs);

                match (got, want) {
                    (Ok(got), Ok(want)) => {
                        assert_eq!(
                            got.list, want.list,
                            "lead={lead:#04x} extra={extra} {filler:?}"
                        );
                        assert_eq!(
                            got.payload_length, want.payload_length,
                            "lead={lead:#04x} extra={extra} {filler:?}"
                        );
                        assert_eq!(
                            ours.len(),
                            theirs.len(),
                            "advance: lead={lead:#04x} extra={extra} {filler:?}"
                        );
                    }
                    (Err(_), Err(_)) => {}
                    (got, want) => panic!(
                        "accept/reject disagreement: lead={lead:#04x} extra={extra} {filler:?} \
                         ours={:?} alloy={:?}",
                        got.map(|h| (h.list, h.payload_length)),
                        want.map(|h| (h.list, h.payload_length)),
                    ),
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 6000, "expected a broad sweep, ran {checked}");
}

#[test]
fn decode_node_header_accepts_every_well_formed_list() {
    for len in LENS {
        let mut encoded = Vec::new();
        alloy_rlp::Header { list: true, payload_length: len }.encode(&mut encoded);
        encoded.extend(payload(len));

        let mut ours = encoded.as_slice();
        let got = decode_node_header(&mut ours).expect("well-formed list header");
        assert!(got.list, "len={len}");
        assert_eq!(got.payload_length, len, "len={len}");
        assert_eq!(ours.len(), len, "header not fully consumed: len={len}");
    }
}

/// Reference implementation of [`decode_rlp_item`] built directly on `alloy_rlp`.
fn reference_item<'a>(buf: &mut &'a [u8]) -> Result<(&'a [u8], &'a [u8]), alloy_rlp::Error> {
    let start = *buf;
    let alloy_rlp::Header { payload_length, .. } = alloy_rlp::Header::decode(buf)?;
    if buf.len() < payload_length {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    let header_length = start.len() - buf.len();
    let payload = &start[header_length..header_length + payload_length];
    *buf = &start[header_length + payload_length..];
    Ok((&start[..header_length + payload_length], payload))
}

#[test]
fn decode_rlp_item_matches_alloy() {
    for filler in FILLERS {
        for lead in 0..=u8::MAX {
            for extra in EXTRAS {
                let input = synthetic(lead, extra, filler);

                let mut ours = input.as_slice();
                let got = decode_rlp_item(&mut ours);

                let mut theirs = input.as_slice();
                let want = reference_item(&mut theirs);

                match (got, want) {
                    (Ok((item, pay)), Ok((ref_item, ref_pay))) => {
                        assert_eq!(
                            item, ref_item,
                            "item: lead={lead:#04x} extra={extra} {filler:?}"
                        );
                        assert_eq!(
                            pay, ref_pay,
                            "payload: lead={lead:#04x} extra={extra} {filler:?}"
                        );
                        assert_eq!(
                            ours.len(),
                            theirs.len(),
                            "advance: lead={lead:#04x} extra={extra} {filler:?}"
                        );
                    }
                    (Err(_), Err(_)) => {}
                    (got, want) => panic!(
                        "accept/reject disagreement: lead={lead:#04x} extra={extra} {filler:?} \
                         ours_ok={} alloy_ok={}",
                        got.is_ok(),
                        want.is_ok(),
                    ),
                }
            }
        }
    }
}

#[test]
fn decode_rlp_item_round_trips_every_string_length() {
    for len in LENS {
        let bytes = payload(len);
        let mut encoded = Vec::new();
        alloy_rlp::Encodable::encode(&bytes.as_slice(), &mut encoded);

        let mut ours = encoded.as_slice();
        let (item, pay) = decode_rlp_item(&mut ours).expect("well-formed string");
        assert_eq!(item, encoded.as_slice(), "len={len}");
        assert_eq!(pay, bytes.as_slice(), "len={len}");
        assert!(ours.is_empty(), "len={len}");
    }
}

#[test]
fn encode_header_matches_alloy() {
    for list in [false, true] {
        let base_code =
            if list { alloy_rlp::EMPTY_LIST_CODE } else { alloy_rlp::EMPTY_STRING_CODE };
        for payload_length in (0usize..600).chain([1000, 65_535, 65_536, 1 << 20]) {
            let mut ours = Vec::new();
            encode_header(base_code, payload_length, &mut ours);

            let mut theirs = Vec::new();
            alloy_rlp::Header { list, payload_length }.encode(&mut theirs);

            assert_eq!(ours, theirs, "list={list} payload_length={payload_length}");
        }
    }
}

#[test]
fn encode_slice_matches_alloy() {
    // Single-byte strings are the only case with a special encoding, so sweep all of them.
    for byte in 0..=u8::MAX {
        let bytes = [byte];
        let mut ours = Vec::new();
        encode_slice(&bytes, &mut ours);

        let mut theirs = Vec::new();
        alloy_rlp::Encodable::encode(&bytes.as_slice(), &mut theirs);

        assert_eq!(ours, theirs, "byte={byte:#04x}");
    }

    for len in LENS {
        let bytes = payload(len);
        let mut ours = Vec::new();
        encode_slice(&bytes, &mut ours);

        let mut theirs = Vec::new();
        alloy_rlp::Encodable::encode(&bytes.as_slice(), &mut theirs);

        assert_eq!(ours, theirs, "len={len}");
    }
}

#[test]
fn is_null_ref_matches_slice_equality() {
    for filler in FILLERS {
        for lead in 0..=u8::MAX {
            for extra in 0usize..3 {
                let input = synthetic(lead, extra, filler);
                assert_eq!(
                    is_null_ref(&input),
                    input.as_slice() == NULL_NODE_REF_SLICE,
                    "lead={lead:#04x} extra={extra} {filler:?}"
                );
            }
        }
    }
    assert!(is_null_ref(NULL_NODE_REF_SLICE));
    assert!(!is_null_ref(&[]));
}
