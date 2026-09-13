//! BN254 accelerators (EIP-196 and EIP-197).

mod codec;

use alloc::vec::Vec;

use crate::types::{zkvm_status, ZkvmBytes, ZKVM_EFAIL, ZKVM_EOK};
use codec::{encode_g1, read_g1, read_g2, read_scalar};
use openvm_ecc_guest::{
    weierstrass::{IntrinsicCurve, WeierstrassPoint},
    AffinePoint,
};
use openvm_pairing::{bn254::Bn254, PairingCheck};

use crate::error::Error;

pub type zkvm_bn254_g1_point = ZkvmBytes<64>;
pub type zkvm_bn254_g2_point = ZkvmBytes<128>;
pub type zkvm_bn254_scalar = ZkvmBytes<32>;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkvm_bn254_pairing_pair {
    pub g1: zkvm_bn254_g1_point,
    pub g2: zkvm_bn254_g2_point,
}

/// Add two BN254 G1 points.
///
/// # Safety
///
/// Each pointer must be non-NULL and valid for one value of its pointee type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bn254_g1_add(
    p1: *const zkvm_bn254_g1_point,
    p2: *const zkvm_bn254_g1_point,
    result: *mut zkvm_bn254_g1_point,
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
            unsafe { result.write(zkvm_bn254_g1_point { data }) };
            ZKVM_EOK
        }
        Err(_) => ZKVM_EFAIL,
    }
}

/// Multiply a BN254 G1 point by a scalar.
///
/// # Safety
///
/// Each pointer must be non-NULL and valid for one value of its pointee type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bn254_g1_mul(
    point: *const zkvm_bn254_g1_point,
    scalar: *const zkvm_bn254_scalar,
    result: *mut zkvm_bn254_g1_point,
) -> zkvm_status {
    if point.is_null() || scalar.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    // SAFETY: the caller guarantees valid reads. The output is written only after these
    // shared borrows are no longer used, so overlapping storage is supported.
    let value = unsafe { g1_mul(&(*point).data, &(*scalar).data) };
    match value {
        Ok(data) => {
            // SAFETY: `result` is non-NULL and valid for writes.
            unsafe { result.write(zkvm_bn254_g1_point { data }) };
            ZKVM_EOK
        }
        Err(_) => ZKVM_EFAIL,
    }
}

/// Check a BN254 pairing equation.
///
/// # Safety
///
/// `pairs` must be valid for `num_pairs` reads when non-empty, and `verified`
/// must be non-NULL and valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_bn254_pairing(
    pairs: *const zkvm_bn254_pairing_pair,
    num_pairs: usize,
    verified: *mut bool,
) -> zkvm_status {
    if verified.is_null() || (pairs.is_null() && num_pairs != 0) {
        return ZKVM_EFAIL;
    }
    // SAFETY: the caller guarantees that non-empty input is valid for `num_pairs` reads.
    let pairs =
        if num_pairs == 0 { &[] } else { unsafe { core::slice::from_raw_parts(pairs, num_pairs) } };
    let value = pairing(pairs.iter().map(|pair| (&pair.g1.data, &pair.g2.data)));
    match value {
        Ok(value) => {
            // SAFETY: `verified` is non-NULL and all input reads are complete.
            unsafe { verified.write(value) };
            ZKVM_EOK
        }
        Err(_) => ZKVM_EFAIL,
    }
}

fn g1_add(p1: &[u8; 64], p2: &[u8; 64]) -> Result<[u8; 64], Error> {
    Ok(encode_g1(read_g1(p1)? + read_g1(p2)?))
}

fn g1_mul(point: &[u8; 64], scalar: &[u8; 32]) -> Result<[u8; 64], Error> {
    Ok(encode_g1(Bn254::msm(&[read_scalar(scalar)], &[read_g1(point)?])))
}

fn pairing<'a>(
    pairs: impl IntoIterator<Item = (&'a [u8; 64], &'a [u8; 128])>,
) -> Result<bool, Error> {
    let pairs = pairs.into_iter();
    let mut g1_points = Vec::with_capacity(pairs.size_hint().0);
    let mut g2_points = Vec::with_capacity(pairs.size_hint().0);
    for (g1, g2) in pairs {
        let (g1_x, g1_y) = read_g1(g1)?.into_coords();
        let (g2_x, g2_y) = read_g2(g2)?.into_coords();
        g1_points.push(AffinePoint::new(g1_x, g1_y));
        g2_points.push(AffinePoint::new(g2_x, g2_y));
    }
    if g1_points.is_empty() {
        Ok(true)
    } else {
        Ok(Bn254::pairing_check(&g1_points, &g2_points).is_ok())
    }
}
