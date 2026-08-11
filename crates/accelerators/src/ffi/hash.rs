//! C ABI for the hash accelerators.

use crate::{
    ops,
    types::{ZkvmKeccak256Hash, ZkvmRipemd160Hash, ZkvmSha256Hash, ZkvmStatus},
};

/// Compute the Keccak-256 hash of `data[..len]` into `output`.
///
/// Returns [`ZkvmStatus::Fail`] if `output` is NULL, or if `data` is NULL
/// with a non-zero `len`; a NULL `data` with `len == 0` hashes the empty
/// input.
///
/// # Safety
///
/// - `data`, if non-NULL, must be valid for reads of `len` bytes.
/// - `output`, if non-NULL, must be valid for writes of 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_keccak256(
    data: *const u8,
    len: usize,
    output: *mut ZkvmKeccak256Hash,
) -> ZkvmStatus {
    if output.is_null() || (data.is_null() && len != 0) {
        return ZkvmStatus::Fail;
    }
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let data = if len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(data, len) } };
    let value = ZkvmKeccak256Hash { data: ops::keccak256(data) };
    // SAFETY: `output` is non-NULL and valid for writes. All input reads are complete, so
    // overlapping input/output storage is supported.
    unsafe { output.write(value) };
    ZkvmStatus::Ok
}

/// Compute the SHA-256 hash of `data[..len]` into `output`.
///
/// Returns [`ZkvmStatus::Fail`] if `output` is NULL, or if `data` is NULL
/// with a non-zero `len`; a NULL `data` with `len == 0` hashes the empty
/// input.
///
/// # Safety
///
/// - `data`, if non-NULL, must be valid for reads of `len` bytes.
/// - `output`, if non-NULL, must be valid for writes of 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_sha256(
    data: *const u8,
    len: usize,
    output: *mut ZkvmSha256Hash,
) -> ZkvmStatus {
    if output.is_null() || (data.is_null() && len != 0) {
        return ZkvmStatus::Fail;
    }
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let data = if len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(data, len) } };
    let value = ZkvmSha256Hash { data: ops::sha256(data) };
    // SAFETY: see `zkvm_keccak256`.
    unsafe { output.write(value) };
    ZkvmStatus::Ok
}

/// Compute the RIPEMD-160 hash of `data[..len]` into `output`.
///
/// The 20-byte digest is written to `output.data[12..]`; the first 12 bytes
/// are zeroed.
///
/// Returns [`ZkvmStatus::Fail`] if `output` is NULL, or if `data` is NULL
/// with a non-zero `len`; a NULL `data` with `len == 0` hashes the empty
/// input.
///
/// # Safety
///
/// - `data`, if non-NULL, must be valid for reads of `len` bytes.
/// - `output`, if non-NULL, must be valid for writes of 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_ripemd160(
    data: *const u8,
    len: usize,
    output: *mut ZkvmRipemd160Hash,
) -> ZkvmStatus {
    if output.is_null() || (data.is_null() && len != 0) {
        return ZkvmStatus::Fail;
    }
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let data = if len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(data, len) } };
    let value = ZkvmRipemd160Hash { data: ops::ripemd160(data) };
    // SAFETY: see `zkvm_keccak256`.
    unsafe { output.write(value) };
    ZkvmStatus::Ok
}
