//! Hash operations.

// `Digest` provides the sha2 method resolution on the host; under
// `openvm_intrinsics` the methods are inherent and the re-export does not
// exist.
#[cfg(not(openvm_intrinsics))]
use openvm_sha2::Digest as _;

use crate::types::{ZkvmKeccak256Hash, ZkvmSha256Hash};

/// Compute the Keccak-256 hash of `data` into `output`.
#[inline]
pub fn keccak256(data: &[u8], output: &mut ZkvmKeccak256Hash) {
    openvm_keccak256::set_keccak256(data, &mut output.data);
}

/// Compute the SHA-256 hash of `data` into `output`.
#[inline]
pub fn sha256(data: &[u8], output: &mut ZkvmSha256Hash) {
    output.data = openvm_sha2::Sha256::digest(data).into();
}
