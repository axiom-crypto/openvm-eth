//! Hash operations.

use crate::types::ZkvmKeccak256Hash;

/// Compute the Keccak-256 hash of `data` into `output`.
#[inline]
pub fn keccak256(data: &[u8], output: &mut ZkvmKeccak256Hash) {
    openvm_keccak256::set_keccak256(data, &mut output.data);
}
