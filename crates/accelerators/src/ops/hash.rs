//! Hash operations.

/// Compute the Keccak-256 hash of `data`.
#[inline]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    openvm_keccak256::keccak256(data)
}

/// Compute the SHA-256 hash of `data`.
#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    #[cfg(not(openvm_intrinsics))]
    use openvm_sha2::Digest;
    openvm_sha2::Sha256::digest(data).into()
}

/// Compute the RIPEMD-160 hash of `data`.
///
/// The 20-byte digest is written to the final 20 bytes; the first 12 bytes are
/// zeroed, matching the EVM word layout.
#[inline]
pub fn ripemd160(data: &[u8]) -> [u8; 32] {
    use ripemd::Digest;
    let mut hasher = ripemd::Ripemd160::new();
    hasher.update(data);

    let mut output = [0; 32];
    hasher.finalize_into((&mut output[12..]).into());
    output
}
