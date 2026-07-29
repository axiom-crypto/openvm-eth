//! C ABI for the BLS12-381 add/MSM accelerators (EIP-2537).

use crate::{
    ops,
    types::{
        ZkvmBls12381G1MsmPair, ZkvmBls12381G1Point, ZkvmBls12381G2MsmPair, ZkvmBls12381G2Point,
        ZkvmBls12381PairingPair, ZkvmStatus,
    },
};

/// BLS12-381 G1 point addition (precompile 0x0b, EIP-2537).
///
/// Inputs must be on the curve but, per EIP-2537 G1ADD, need not be in the
/// prime-order subgroup.
///
/// # Safety
///
/// - `p1` and `p2`, if non-NULL, must be valid for reads of 96 bytes.
/// - `result`, if non-NULL, must be valid for writes of 96 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_g1_add(
    p1: *const ZkvmBls12381G1Point,
    p2: *const ZkvmBls12381G1Point,
    result: *mut ZkvmBls12381G1Point,
) -> ZkvmStatus {
    if p1.is_null() || p2.is_null() || result.is_null() {
        return ZkvmStatus::Fail;
    }
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let (p1, p2, result) = unsafe { (&*p1, &*p2, &mut *result) };
    match ops::bls12_381_g1_add(p1, p2, result) {
        Ok(()) => ZkvmStatus::Ok,
        Err(_) => ZkvmStatus::Fail,
    }
}

/// BLS12-381 G1 multi-scalar multiplication (precompile 0x0c, EIP-2537).
///
/// Inputs must be in the prime-order subgroup. Scalars need not be canonical.
/// `num_pairs == 0` yields the identity (all-zero) point.
///
/// # Safety
///
/// - `pairs`, if non-NULL, must be valid for reads of `num_pairs` elements.
/// - `result`, if non-NULL, must be valid for writes of 96 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_g1_msm(
    pairs: *const ZkvmBls12381G1MsmPair,
    num_pairs: usize,
    result: *mut ZkvmBls12381G1Point,
) -> ZkvmStatus {
    if result.is_null() || (pairs.is_null() && num_pairs != 0) {
        return ZkvmStatus::Fail;
    }
    // SAFETY: non-NULL checked above for non-empty input; validity is guaranteed by the caller.
    let pairs =
        if num_pairs == 0 { &[] } else { unsafe { core::slice::from_raw_parts(pairs, num_pairs) } };
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let result = unsafe { &mut *result };
    match ops::bls12_381_g1_msm(pairs, result) {
        Ok(()) => ZkvmStatus::Ok,
        Err(_) => ZkvmStatus::Fail,
    }
}

/// BLS12-381 G2 point addition (precompile 0x0d, EIP-2537).
///
/// Inputs must be on the curve but, per EIP-2537 G2ADD, need not be in the
/// prime-order subgroup.
///
/// # Safety
///
/// - `p1` and `p2`, if non-NULL, must be valid for reads of 192 bytes.
/// - `result`, if non-NULL, must be valid for writes of 192 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_g2_add(
    p1: *const ZkvmBls12381G2Point,
    p2: *const ZkvmBls12381G2Point,
    result: *mut ZkvmBls12381G2Point,
) -> ZkvmStatus {
    if p1.is_null() || p2.is_null() || result.is_null() {
        return ZkvmStatus::Fail;
    }
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let (p1, p2, result) = unsafe { (&*p1, &*p2, &mut *result) };
    match ops::bls12_381_g2_add(p1, p2, result) {
        Ok(()) => ZkvmStatus::Ok,
        Err(_) => ZkvmStatus::Fail,
    }
}

/// BLS12-381 G2 multi-scalar multiplication (precompile 0x0e, EIP-2537).
///
/// Inputs must be in the prime-order subgroup. Scalars need not be canonical.
/// `num_pairs == 0` yields the identity (all-zero) point.
///
/// # Safety
///
/// - `pairs`, if non-NULL, must be valid for reads of `num_pairs` elements.
/// - `result`, if non-NULL, must be valid for writes of 192 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_g2_msm(
    pairs: *const ZkvmBls12381G2MsmPair,
    num_pairs: usize,
    result: *mut ZkvmBls12381G2Point,
) -> ZkvmStatus {
    if result.is_null() || (pairs.is_null() && num_pairs != 0) {
        return ZkvmStatus::Fail;
    }
    // SAFETY: non-NULL checked above for non-empty input; validity is guaranteed by the caller.
    let pairs =
        if num_pairs == 0 { &[] } else { unsafe { core::slice::from_raw_parts(pairs, num_pairs) } };
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let result = unsafe { &mut *result };
    match ops::bls12_381_g2_msm(pairs, result) {
        Ok(()) => ZkvmStatus::Ok,
        Err(_) => ZkvmStatus::Fail,
    }
}

/// BLS12-381 pairing check (precompile 0x0f, EIP-2537).
///
/// Sets `verified` to whether the product of pairings equals one. Inputs must
/// be in the prime-order subgroup; malformed points return
/// [`ZkvmStatus::Fail`]. `num_pairs == 0` verifies trivially.
///
/// # Safety
///
/// - `pairs`, if non-NULL, must be valid for reads of `num_pairs` elements.
/// - `verified`, if non-NULL, must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_pairing(
    pairs: *const ZkvmBls12381PairingPair,
    num_pairs: usize,
    verified: *mut bool,
) -> ZkvmStatus {
    if verified.is_null() || (pairs.is_null() && num_pairs != 0) {
        return ZkvmStatus::Fail;
    }
    // SAFETY: non-NULL checked above for non-empty input; validity is guaranteed by the caller.
    let pairs =
        if num_pairs == 0 { &[] } else { unsafe { core::slice::from_raw_parts(pairs, num_pairs) } };
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let verified = unsafe { &mut *verified };
    match ops::bls12_381_pairing_check(pairs, verified) {
        Ok(()) => ZkvmStatus::Ok,
        Err(_) => ZkvmStatus::Fail,
    }
}
