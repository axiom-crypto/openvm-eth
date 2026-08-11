//! C ABI for the BN254 (alt_bn128) accelerators.

use crate::{
    ops,
    types::{ZkvmBn254G1Point, ZkvmBn254PairingPair, ZkvmBn254Scalar, ZkvmStatus},
};

/// BN254 G1 point addition (precompile 0x06, EIP-196).
///
/// Returns [`ZkvmStatus::Fail`] if any pointer is NULL or an input point is
/// malformed.
///
/// # Safety
///
/// - `p1` and `p2`, if non-NULL, must be valid for reads of 64 bytes.
/// - `result`, if non-NULL, must be valid for writes of 64 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bn254_g1_add(
    p1: *const ZkvmBn254G1Point,
    p2: *const ZkvmBn254G1Point,
    result: *mut ZkvmBn254G1Point,
) -> ZkvmStatus {
    if p1.is_null() || p2.is_null() || result.is_null() {
        return ZkvmStatus::Fail;
    }
    // SAFETY: the non-NULL inputs are valid for reads. Copy before writing to support overlap.
    let (p1, p2) = unsafe { (p1.read(), p2.read()) };
    match ops::bn254_g1_add(&p1.data, &p2.data) {
        Ok(data) => {
            // SAFETY: `result` is non-NULL and valid for writes.
            unsafe { result.write(ZkvmBn254G1Point { data }) };
            ZkvmStatus::Ok
        }
        Err(_) => ZkvmStatus::Fail,
    }
}

/// BN254 G1 scalar multiplication (precompile 0x07, EIP-196).
///
/// The scalar need not be canonical.
///
/// Returns [`ZkvmStatus::Fail`] if any pointer is NULL or the input point is
/// malformed.
///
/// # Safety
///
/// - `point`, if non-NULL, must be valid for reads of 64 bytes.
/// - `scalar`, if non-NULL, must be valid for reads of 32 bytes.
/// - `result`, if non-NULL, must be valid for writes of 64 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bn254_g1_mul(
    point: *const ZkvmBn254G1Point,
    scalar: *const ZkvmBn254Scalar,
    result: *mut ZkvmBn254G1Point,
) -> ZkvmStatus {
    if point.is_null() || scalar.is_null() || result.is_null() {
        return ZkvmStatus::Fail;
    }
    // SAFETY: the non-NULL inputs are valid for reads. Copy before writing to support overlap.
    let (point, scalar) = unsafe { (point.read(), scalar.read()) };
    match ops::bn254_g1_mul(&point.data, &scalar.data) {
        Ok(data) => {
            // SAFETY: `result` is non-NULL and valid for writes.
            unsafe { result.write(ZkvmBn254G1Point { data }) };
            ZkvmStatus::Ok
        }
        Err(_) => ZkvmStatus::Fail,
    }
}

/// BN254 pairing check (precompile 0x08, EIP-197).
///
/// Sets `verified` to whether the product of pairings equals one. Malformed
/// points return [`ZkvmStatus::Fail`]. `num_pairs == 0` verifies trivially.
///
/// # Safety
///
/// - `pairs`, if non-NULL, must be valid for reads of `num_pairs` elements.
/// - `verified`, if non-NULL, must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bn254_pairing(
    pairs: *const ZkvmBn254PairingPair,
    num_pairs: usize,
    verified: *mut bool,
) -> ZkvmStatus {
    if verified.is_null() || (pairs.is_null() && num_pairs != 0) {
        return ZkvmStatus::Fail;
    }
    // SAFETY: non-NULL checked above for non-empty input; validity is guaranteed by the caller.
    let pairs =
        if num_pairs == 0 { &[] } else { unsafe { core::slice::from_raw_parts(pairs, num_pairs) } };
    let pairs = pairs.iter().map(|pair| (pair.g1.data.as_slice(), pair.g2.data.as_slice()));
    match ops::bn254_pairing_check(pairs) {
        Ok(value) => {
            // SAFETY: `verified` is non-NULL and valid for writes; input reads are complete.
            unsafe { verified.write(value) };
            ZkvmStatus::Ok
        }
        Err(_) => {
            // SAFETY: `verified` is non-NULL and valid for writes; input reads are complete.
            unsafe { verified.write(false) };
            ZkvmStatus::Fail
        }
    }
}
