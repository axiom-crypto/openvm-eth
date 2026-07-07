//! Hex-prefix (HP) helpers and nibble utilities for MPT paths.
use core::cmp;
use smallvec::SmallVec;

/// Compact vector for nibble sequences used in key traversal.
pub(crate) type Nibbles = SmallVec<[u8; 64]>;

// Hex-prefix (HP) encoding flags for MPT paths
pub(crate) const HP_FLAG_ODD: u8 = 0x10; // path has odd number of nibbles; low nibble of first byte is data
pub(crate) const HP_FLAG_LEAF: u8 = 0x20; // node is a leaf (vs extension)

/// A cursor over the nibbles of a lookup key. Trie traversal tracks a nibble offset into the raw
/// key bytes and computes nibbles by shift/mask on demand, instead of materializing the nibble
/// array up front.
#[derive(Copy, Clone, Debug)]
pub(crate) struct KeyNibbles<'k> {
    key: &'k [u8],
    /// Position of the cursor, in nibbles from the start of `key`.
    offset: usize,
}

impl<'k> KeyNibbles<'k> {
    #[inline(always)]
    pub(crate) fn new(key: &'k [u8]) -> Self {
        Self { key, offset: 0 }
    }

    /// Number of nibbles remaining after the cursor.
    #[inline(always)]
    pub(crate) fn len(&self) -> usize {
        2 * self.key.len() - self.offset
    }

    #[inline(always)]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The `i`-th nibble after the cursor.
    #[inline(always)]
    pub(crate) fn nib(&self, i: usize) -> u8 {
        let j = self.offset + i;
        let byte = self.key[j / 2];
        if j % 2 == 0 {
            byte >> 4
        } else {
            byte & 0x0f
        }
    }

    /// Splits off the first nibble, like `slice::split_first`.
    #[inline(always)]
    pub(crate) fn split_first(&self) -> Option<(u8, Self)> {
        if self.is_empty() {
            None
        } else {
            Some((self.nib(0), self.advanced(1)))
        }
    }

    /// The cursor advanced by `n` nibbles.
    #[inline(always)]
    pub(crate) fn advanced(&self, n: usize) -> Self {
        debug_assert!(n <= self.len());
        Self { key: self.key, offset: self.offset + n }
    }
}

/// Returns the length of the common prefix (in nibbles) between a nibble slice and the key
/// nibbles at the cursor.
#[inline]
pub(crate) fn lcp_key(nibs: &[u8], key: KeyNibbles<'_>) -> usize {
    let max = cmp::min(nibs.len(), key.len());
    for (i, &nib) in nibs[..max].iter().enumerate() {
        if nib != key.nib(i) {
            return i;
        }
    }
    max
}

/// Decodes a compact hex-prefix-encoded path (as used in MPT leaf/extension nodes)
/// into its nibble sequence. This allocates a `SmallVec` with the exact nibble capacity.
#[inline]
pub(crate) fn prefix_to_nibs(encoded_path: &[u8]) -> Nibbles {
    if encoded_path.is_empty() {
        return SmallVec::new();
    }

    let first_byte = encoded_path[0];
    let is_odd = (first_byte & HP_FLAG_ODD) != 0;
    // Nibble count: if odd, first byte contains 1 nibble of data; otherwise, first byte
    // contains only flags. Remaining bytes always contain two nibbles each.
    let nib_count = 2 * (encoded_path.len() - 1) + if is_odd { 1 } else { 0 };
    let mut nibs = SmallVec::with_capacity(nib_count);

    // Handle the first nibble if odd length
    if is_odd {
        nibs.push(first_byte & 0x0f);
    }

    // Process remaining bytes, starting from index 1
    for &byte in &encoded_path[1..] {
        nibs.push(byte >> 4); // High nibble
        nibs.push(byte & 0x0f); // Low nibble
    }

    nibs
}

/// Returns the number of nibbles encoded in a compact hex-prefix path.
#[inline]
pub(crate) fn encoded_path_nibble_count(encoded_path: &[u8]) -> usize {
    if encoded_path.is_empty() {
        return 0;
    }
    let is_odd = (encoded_path[0] & HP_FLAG_ODD) != 0;
    2 * (encoded_path.len() - 1) + if is_odd { 1 } else { 0 }
}

/// Compares a compact hex-prefix path with the key nibbles at the cursor for equality, without
/// allocating.
#[inline]
pub(crate) fn encoded_path_eq_key(encoded_path: &[u8], key: KeyNibbles<'_>) -> bool {
    let nib_count = encoded_path_nibble_count(encoded_path);
    if nib_count != key.len() {
        return false;
    }
    encoded_path_matches_key(encoded_path, nib_count, key)
}

/// If `encoded_path` is a prefix of the key nibbles at the cursor, returns the cursor advanced
/// past it.
#[inline]
pub(crate) fn encoded_path_strip_prefix_key<'k>(
    encoded_path: &[u8],
    key: KeyNibbles<'k>,
) -> Option<KeyNibbles<'k>> {
    let nib_count = encoded_path_nibble_count(encoded_path);
    if nib_count > key.len() {
        return None;
    }
    encoded_path_matches_key(encoded_path, nib_count, key).then(|| key.advanced(nib_count))
}

/// Whether the first `nib_count` key nibbles at the cursor equal the path's nibbles. The caller
/// must have checked `nib_count <= key.len()`. After the path's optional odd leading nibble its
/// data is whole bytes, so when the cursor is byte-aligned there — always the case for leaves in
/// tries keyed by whole-byte keys — this is a direct byte comparison.
#[inline]
fn encoded_path_matches_key(encoded_path: &[u8], nib_count: usize, key: KeyNibbles<'_>) -> bool {
    if nib_count == 0 {
        return true;
    }

    let first = encoded_path[0];
    let is_odd = (first & HP_FLAG_ODD) != 0;
    let start = usize::from(is_odd);
    if is_odd && key.nib(0) != (first & 0x0f) {
        return false;
    }

    let path_data = &encoded_path[1..];
    if (key.offset + start) % 2 == 0 {
        let key_start = (key.offset + start) / 2;
        return key.key[key_start..key_start + path_data.len()] == *path_data;
    }

    // The path's byte boundaries are misaligned with the key's (possible for extension paths);
    // compare nibble by nibble.
    for (j, &byte) in path_data.iter().enumerate() {
        let i = start + 2 * j;
        if key.nib(i) != (byte >> 4) || key.nib(i + 1) != (byte & 0x0f) {
            return false;
        }
    }
    true
}

/// Encodes the key nibbles remaining after the cursor into hex-prefix format in the bump arena.
/// For whole-byte keys the remaining-length parity always matches the cursor parity, so after the
/// optional odd leading nibble this is a direct copy of the key's bytes.
#[inline]
pub(crate) fn encoded_path_from_key<'a>(
    bump: &'a bumpalo::Bump,
    key: KeyNibbles<'_>,
    is_leaf: bool,
) -> &'a [u8] {
    let remaining = key.len();
    let is_odd = !remaining.is_multiple_of(2);
    let start = usize::from(is_odd);
    debug_assert!(
        (key.offset + start).is_multiple_of(2),
        "cursor over whole-byte keys is always byte-aligned after the odd nibble"
    );

    let mut prefix = if is_leaf { HP_FLAG_LEAF } else { 0x00 };
    if is_odd {
        prefix |= HP_FLAG_ODD | key.nib(0);
    }

    let encoded = bump.alloc_slice_fill_copy(1 + remaining / 2, 0);
    encoded[0] = prefix;
    encoded[1..].copy_from_slice(&key.key[(key.offset + start) / 2..]);
    encoded
}

/// Encodes nibbles into the standard hex-prefix format directly into the bump arena.
#[inline]
pub(crate) fn to_encoded_path_with_bump<'a>(
    bump: &'a bumpalo::Bump,
    nibs: &[u8],
    is_leaf: bool,
) -> &'a [u8] {
    let is_odd = !nibs.len().is_multiple_of(2);
    let encoded_len = 1 + (nibs.len() / 2);
    let mut encoded = bumpalo::collections::Vec::with_capacity_in(encoded_len, bump);

    let mut prefix = if is_leaf { 0x20 } else { 0x00 };
    if is_odd {
        prefix |= 0x10;
        encoded.push(prefix | nibs[0]);
        for i in (1..nibs.len()).step_by(2) {
            encoded.push((nibs[i] << 4) | nibs[i + 1]);
        }
    } else {
        encoded.push(prefix);
        for i in (0..nibs.len()).step_by(2) {
            encoded.push((nibs[i] << 4) | nibs[i + 1]);
        }
    }

    encoded.into_bump_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoded_path_nibble_count() {
        assert_eq!(encoded_path_nibble_count(&[]), 0);
        // ODD+LEAF with one nibble 0xA
        assert_eq!(encoded_path_nibble_count(&[HP_FLAG_ODD | HP_FLAG_LEAF | 0x0a]), 1);
        // EVEN+EXT with 2 bytes => 4 nibbles
        assert_eq!(encoded_path_nibble_count(&[0x00, 0xab, 0xcd]), 4);
    }

    /// Collects the nibbles remaining after a cursor, for assertions.
    fn nibs_of(key: KeyNibbles<'_>) -> Vec<u8> {
        (0..key.len()).map(|i| key.nib(i)).collect()
    }

    #[test]
    fn test_key_nibbles_cursor() {
        let key = KeyNibbles::new(&[0x12, 0x34]);
        assert_eq!(key.len(), 4);
        assert_eq!(nibs_of(key), vec![1, 2, 3, 4]);

        let (first, rest) = key.split_first().unwrap();
        assert_eq!(first, 1);
        assert_eq!(nibs_of(rest), vec![2, 3, 4]);

        let empty = key.advanced(4);
        assert!(empty.is_empty());
        assert!(empty.split_first().is_none());
    }

    #[test]
    fn test_eq_and_strip_prefix() {
        // path [1, 2, 3] as HP: ODD + EXT, first byte 0x10 | 0x1, then 0x23
        let path = [HP_FLAG_ODD | 0x01, 0x23];
        // key nibbles [1, 2, 3]: cursor at offset 1 into bytes [0x01, 0x23]
        let key = KeyNibbles::new(&[0x01, 0x23]).advanced(1);
        assert!(encoded_path_eq_key(&path, key));
        assert!(encoded_path_strip_prefix_key(&path, key).unwrap().is_empty());

        // key nibbles [1, 2, 3, 4, 5]: cursor at offset 1 into bytes [0x01, 0x23, 0x45]
        let key_longer = KeyNibbles::new(&[0x01, 0x23, 0x45]).advanced(1);
        assert!(!encoded_path_eq_key(&path, key_longer));
        let tail = encoded_path_strip_prefix_key(&path, key_longer).unwrap();
        assert_eq!(nibs_of(tail), vec![4, 5]);

        // key nibbles [1, 2, 4]
        let key_mismatch = KeyNibbles::new(&[0x01, 0x24]).advanced(1);
        assert!(encoded_path_strip_prefix_key(&path, key_mismatch).is_none());

        // even-length path [2, 3] against a misaligned (odd-offset) cursor
        let even_path = [0x00, 0x23];
        let key_misaligned = KeyNibbles::new(&[0x02, 0x34]).advanced(1);
        let tail = encoded_path_strip_prefix_key(&even_path, key_misaligned).unwrap();
        assert_eq!(nibs_of(tail), vec![4]);
        assert!(encoded_path_strip_prefix_key(
            &even_path,
            KeyNibbles::new(&[0x02, 0x44]).advanced(1)
        )
        .is_none());
    }

    #[test]
    fn test_encoded_path_from_key() {
        let bump = bumpalo::Bump::new();

        let key = KeyNibbles::new(&[0xab, 0xcd]);
        // leaf with an even remainder
        assert_eq!(encoded_path_from_key(&bump, key, true), &[0x20, 0xab, 0xcd]);
        // extension with an odd remainder
        assert_eq!(encoded_path_from_key(&bump, key.advanced(1), false), &[0x1b, 0xcd]);
        // leaf with an odd remainder
        assert_eq!(encoded_path_from_key(&bump, key.advanced(3), true), &[0x3d]);
        // empty remainder
        assert_eq!(encoded_path_from_key(&bump, key.advanced(4), true), &[0x20]);
    }

    #[test]
    fn test_lcp_key() {
        let key = KeyNibbles::new(&[0xab, 0xcd]);
        assert_eq!(lcp_key(&[], key), 0);
        assert_eq!(lcp_key(&[0xa], key), 1);
        assert_eq!(lcp_key(&[0xa, 0xb, 0xd], key), 2);
        assert_eq!(lcp_key(&[0xa, 0xb, 0xc, 0xd], key), 4);
        assert_eq!(lcp_key(&[0xa, 0xb, 0xc, 0xd, 0xe], key), 4);
        assert_eq!(lcp_key(&[0xb, 0xc], key.advanced(1)), 2);
    }

    #[test]
    fn test_to_encoded_path() {
        let bump = bumpalo::Bump::new();

        // extension node with an even path length
        let nibbles = vec![0x0a, 0x0b, 0x0c, 0x0d];
        assert_eq!(to_encoded_path_with_bump(&bump, &nibbles, false), vec![0x00, 0xab, 0xcd]);
        // extension node with an odd path length
        let nibbles = vec![0x0a, 0x0b, 0x0c];
        assert_eq!(to_encoded_path_with_bump(&bump, &nibbles, false), vec![0x1a, 0xbc]);
        // leaf node with an even path length
        let nibbles = vec![0x0a, 0x0b, 0x0c, 0x0d];
        assert_eq!(to_encoded_path_with_bump(&bump, &nibbles, true), vec![0x20, 0xab, 0xcd]);
        // leaf node with an odd path length
        let nibbles = vec![0x0a, 0x0b, 0x0c];
        assert_eq!(to_encoded_path_with_bump(&bump, &nibbles, true), vec![0x3a, 0xbc]);
    }
}
