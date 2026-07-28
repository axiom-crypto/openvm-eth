//! Hash operations.

use crate::types::{ZkvmKeccak256Hash, ZkvmRipemd160Hash, ZkvmSha256Hash};

/// Compute the Keccak-256 hash of `data` into `output`.
#[inline]
pub fn keccak256(data: &[u8], output: &mut ZkvmKeccak256Hash) {
    openvm_keccak256::set_keccak256(data, &mut output.data);
}

/// Compute the SHA-256 hash of `data` into `output`.
#[inline]
pub fn sha256(data: &[u8], output: &mut ZkvmSha256Hash) {
    #[cfg(not(openvm_intrinsics))]
    use openvm_sha2::Digest;
    output.data = openvm_sha2::Sha256::digest(data).into();
}

/// Compute the RIPEMD-160 hash of `data` into `output`.
///
/// The 20-byte digest is written to `output.data[12..]`; the first 12 bytes
/// are zeroed, matching the EVM word layout.
#[inline]
pub fn ripemd160(data: &[u8], output: &mut ZkvmRipemd160Hash) {
    use ripemd::Digest;
    let mut hasher = ripemd::Ripemd160::new();
    hasher.update(data);
    output.data[..12].fill(0);
    hasher.finalize_into((&mut output.data[12..]).into());
}
