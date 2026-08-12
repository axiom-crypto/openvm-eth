//! Keccak-256 accelerator.

use crate::types::{zkvm_status, ZkvmBytes, ZKVM_EFAIL, ZKVM_EOK};

pub type zkvm_keccak256_hash = ZkvmBytes<32>;

/// Compute the Keccak-256 hash of `data[..len]` into `output`.
///
/// A NULL `data` pointer is accepted only when `len == 0`.
///
/// # Safety
///
/// - `data`, if non-NULL, must be valid for reads of `len` bytes.
/// - `output`, if non-NULL, must be valid for writes of one [`zkvm_keccak256_hash`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_keccak256(
    data: *const u8,
    len: usize,
    output: *mut zkvm_keccak256_hash,
) -> zkvm_status {
    if output.is_null() || (data.is_null() && len != 0) {
        return ZKVM_EFAIL;
    }
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let data = if len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(data, len) } };
    let value = zkvm_keccak256_hash { data: openvm_keccak256::keccak256(data) };
    // SAFETY: `output` is non-NULL and valid for writes. All input reads are complete, so
    // overlapping input/output storage is supported.
    unsafe { output.write(value) };
    ZKVM_EOK
}
