//! BLS12-381 accelerators (EIP-2537).

mod codec;
mod map;

use alloc::vec::Vec;

use crate::types::{zkvm_status, ZkvmBytes, ZKVM_EFAIL, ZKVM_EOK};
use codec::{
    encode_g1, encode_g2, read_g1, read_g1_no_subgroup_check, read_g2, read_g2_no_subgroup_check,
    read_scalar,
};
use openvm_ecc_guest::{
    weierstrass::{IntrinsicCurve, WeierstrassPoint},
    AffinePoint,
};
use openvm_pairing::{bls12_381::Bls12_381, PairingCheck};

use crate::error::Error;

pub type zkvm_bls12_381_g1_point = ZkvmBytes<96>;
pub type zkvm_bls12_381_g2_point = ZkvmBytes<192>;
pub type zkvm_bls12_381_scalar = ZkvmBytes<32>;
pub type zkvm_bls12_381_fp = ZkvmBytes<48>;
pub type zkvm_bls12_381_fp2 = ZkvmBytes<96>;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkvm_bls12_381_g1_msm_pair {
    pub point: zkvm_bls12_381_g1_point,
    pub scalar: zkvm_bls12_381_scalar,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkvm_bls12_381_g2_msm_pair {
    pub point: zkvm_bls12_381_g2_point,
    pub scalar: zkvm_bls12_381_scalar,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkvm_bls12_381_pairing_pair {
    pub g1: zkvm_bls12_381_g1_point,
    pub g2: zkvm_bls12_381_g2_point,
}

/// BLS12-381 G1 point addition.
///
/// # Safety
///
/// Each pointer must be non-NULL and valid for one value of its pointee type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_g1_add(
    p1: *const zkvm_bls12_381_g1_point,
    p2: *const zkvm_bls12_381_g1_point,
    result: *mut zkvm_bls12_381_g1_point,
) -> zkvm_status {
    if p1.is_null() || p2.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    // SAFETY: the caller guarantees valid reads. The output is written only after these
    // shared borrows are no longer used, so overlapping storage is supported.
    let value = unsafe { g1_add(&(*p1).data, &(*p2).data) };
    match value {
        Ok(data) => {
            // SAFETY: `result` is non-NULL and valid for writes.
            unsafe { result.write(zkvm_bls12_381_g1_point { data }) };
            ZKVM_EOK
        }
        Err(_) => ZKVM_EFAIL,
    }
}

/// BLS12-381 G1 multi-scalar multiplication.
///
/// # Safety
///
/// `pairs` must be valid for `num_pairs` reads when non-empty, and `result`
/// must be non-NULL and valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_g1_msm(
    pairs: *const zkvm_bls12_381_g1_msm_pair,
    num_pairs: usize,
    result: *mut zkvm_bls12_381_g1_point,
) -> zkvm_status {
    if result.is_null() || (pairs.is_null() && num_pairs != 0) {
        return ZKVM_EFAIL;
    }
    // SAFETY: the caller guarantees that non-empty input is valid for `num_pairs` reads.
    let pairs =
        if num_pairs == 0 { &[] } else { unsafe { core::slice::from_raw_parts(pairs, num_pairs) } };
    match g1_msm(pairs) {
        Ok(data) => {
            // SAFETY: all input reads are complete; `result` is valid for writes.
            unsafe { result.write(zkvm_bls12_381_g1_point { data }) };
            ZKVM_EOK
        }
        Err(_) => ZKVM_EFAIL,
    }
}

/// BLS12-381 G2 point addition.
///
/// # Safety
///
/// Each pointer must be non-NULL and valid for one value of its pointee type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_g2_add(
    p1: *const zkvm_bls12_381_g2_point,
    p2: *const zkvm_bls12_381_g2_point,
    result: *mut zkvm_bls12_381_g2_point,
) -> zkvm_status {
    if p1.is_null() || p2.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    // SAFETY: the caller guarantees valid reads. The output is written only after these
    // shared borrows are no longer used, so overlapping storage is supported.
    let value = unsafe { g2_add(&(*p1).data, &(*p2).data) };
    match value {
        Ok(data) => {
            // SAFETY: `result` is non-NULL and valid for writes.
            unsafe { result.write(zkvm_bls12_381_g2_point { data }) };
            ZKVM_EOK
        }
        Err(_) => ZKVM_EFAIL,
    }
}

/// BLS12-381 G2 multi-scalar multiplication.
///
/// # Safety
///
/// `pairs` must be valid for `num_pairs` reads when non-empty, and `result`
/// must be non-NULL and valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_g2_msm(
    pairs: *const zkvm_bls12_381_g2_msm_pair,
    num_pairs: usize,
    result: *mut zkvm_bls12_381_g2_point,
) -> zkvm_status {
    if result.is_null() || (pairs.is_null() && num_pairs != 0) {
        return ZKVM_EFAIL;
    }
    // SAFETY: the caller guarantees that non-empty input is valid for `num_pairs` reads.
    let pairs =
        if num_pairs == 0 { &[] } else { unsafe { core::slice::from_raw_parts(pairs, num_pairs) } };
    match g2_msm(pairs) {
        Ok(data) => {
            // SAFETY: all input reads are complete; `result` is valid for writes.
            unsafe { result.write(zkvm_bls12_381_g2_point { data }) };
            ZKVM_EOK
        }
        Err(_) => ZKVM_EFAIL,
    }
}

/// BLS12-381 pairing check.
///
/// # Safety
///
/// `pairs` must be valid for `num_pairs` reads when non-empty, and `verified`
/// must be non-NULL and valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_pairing(
    pairs: *const zkvm_bls12_381_pairing_pair,
    num_pairs: usize,
    verified: *mut bool,
) -> zkvm_status {
    if verified.is_null() || (pairs.is_null() && num_pairs != 0) {
        return ZKVM_EFAIL;
    }
    // SAFETY: the caller guarantees that non-empty input is valid for `num_pairs` reads.
    let pairs =
        if num_pairs == 0 { &[] } else { unsafe { core::slice::from_raw_parts(pairs, num_pairs) } };
    match pairing(pairs) {
        Ok(value) => {
            // SAFETY: all input reads are complete; `verified` is valid for writes.
            unsafe { verified.write(value) };
            ZKVM_EOK
        }
        Err(_) => ZKVM_EFAIL,
    }
}

/// Map a BLS12-381 base-field element to G1.
///
/// # Safety
///
/// Each pointer must be non-NULL and valid for one value of its pointee type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_map_fp_to_g1(
    field_element: *const zkvm_bls12_381_fp,
    result: *mut zkvm_bls12_381_g1_point,
) -> zkvm_status {
    if field_element.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    // SAFETY: the caller guarantees a valid read. The output is written only after this
    // shared borrow is no longer used, so overlapping storage is supported.
    let value = unsafe { map::fp_to_g1(&(*field_element).data) };
    match value {
        Ok(data) => {
            // SAFETY: `result` is non-NULL and valid for writes.
            unsafe { result.write(zkvm_bls12_381_g1_point { data }) };
            ZKVM_EOK
        }
        Err(_) => ZKVM_EFAIL,
    }
}

/// Map a BLS12-381 quadratic-extension-field element to G2.
///
/// # Safety
///
/// Each pointer must be non-NULL and valid for one value of its pointee type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_map_fp2_to_g2(
    field_element: *const zkvm_bls12_381_fp2,
    result: *mut zkvm_bls12_381_g2_point,
) -> zkvm_status {
    if field_element.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    // SAFETY: the caller guarantees a valid read. The output is written only after this
    // shared borrow is no longer used, so overlapping storage is supported.
    let value = unsafe { map::fp2_to_g2(&(*field_element).data) };
    match value {
        Ok(data) => {
            // SAFETY: `result` is non-NULL and valid for writes.
            unsafe { result.write(zkvm_bls12_381_g2_point { data }) };
            ZKVM_EOK
        }
        Err(_) => ZKVM_EFAIL,
    }
}

#[inline]
fn g1_add(p1: &[u8; 96], p2: &[u8; 96]) -> Result<[u8; 96], Error> {
    Ok(encode_g1(&(read_g1_no_subgroup_check(p1)? + read_g1_no_subgroup_check(p2)?)))
}

fn g1_msm(pairs: &[zkvm_bls12_381_g1_msm_pair]) -> Result<[u8; 96], Error> {
    let mut points = Vec::with_capacity(pairs.len());
    let mut scalars = Vec::with_capacity(pairs.len());
    for pair in pairs {
        points.push(read_g1(&pair.point.data)?);
        scalars.push(read_scalar(&pair.scalar.data));
    }
    if points.is_empty() {
        Ok([0; 96])
    } else {
        Ok(encode_g1(&Bls12_381::msm(&scalars, &points)))
    }
}

#[inline]
fn g2_add(p1: &[u8; 192], p2: &[u8; 192]) -> Result<[u8; 192], Error> {
    Ok(encode_g2(&(read_g2_no_subgroup_check(p1)? + read_g2_no_subgroup_check(p2)?)))
}

fn g2_msm(pairs: &[zkvm_bls12_381_g2_msm_pair]) -> Result<[u8; 192], Error> {
    let mut points = Vec::with_capacity(pairs.len());
    let mut scalars = Vec::with_capacity(pairs.len());
    for pair in pairs {
        points.push(read_g2(&pair.point.data)?);
        scalars.push(read_scalar(&pair.scalar.data));
    }
    if points.is_empty() {
        Ok([0; 192])
    } else {
        Ok(encode_g2(&openvm_ecc_guest::msm(&scalars, &points)))
    }
}

fn pairing(pairs: &[zkvm_bls12_381_pairing_pair]) -> Result<bool, Error> {
    let mut g1_points = Vec::with_capacity(pairs.len());
    let mut g2_points = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let (g1_x, g1_y) = read_g1(&pair.g1.data)?.into_coords();
        let (g2_x, g2_y) = read_g2(&pair.g2.data)?.into_coords();
        g1_points.push(AffinePoint::new(g1_x, g1_y));
        g2_points.push(AffinePoint::new(g2_x, g2_y));
    }
    if g1_points.is_empty() {
        Ok(true)
    } else {
        Ok(Bls12_381::pairing_check(&g1_points, &g2_points).is_ok())
    }
}
