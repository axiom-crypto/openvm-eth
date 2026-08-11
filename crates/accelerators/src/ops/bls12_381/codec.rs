//! Byte codecs for BLS12-381: EIP-2537 point encodings, including the
//! on-curve and subgroup validation performed while decoding.

use openvm_curve_utils::SubgroupCheck;
use openvm_ecc_guest::{algebra::IntMod, weierstrass::WeierstrassPoint, Group};
use openvm_pairing::bls12_381 as bls;

use super::BLS_FP_LEN;
use crate::ops::{BlsG1, BlsG2, Error};

#[inline]
fn read_bls_fp(input: &[u8]) -> Result<bls::Fp, Error> {
    bls::Fp::from_be_bytes(input).ok_or(Error::FieldElementInvalid)
}

#[inline]
fn read_bls_fp2(c0: &[u8], c1: &[u8]) -> Result<bls::Fp2, Error> {
    let real = read_bls_fp(c0)?;
    let imag = read_bls_fp(c1)?;
    Ok(bls::Fp2::new(real, imag))
}

#[inline]
pub(super) fn read_bls_g1_point_no_subgroup_check(point: &BlsG1) -> Result<bls::G1Affine, Error> {
    let px = read_bls_fp(&point.0)?;
    let py = read_bls_fp(&point.1)?;
    // SAFETY: `read_bls_fp` produces canonical Fp elements; `from_xy` itself checks the curve
    // equation and returns `None` if `(px, py)` is not on the curve.
    unsafe { bls::G1Affine::from_xy(px, py) }.ok_or(Error::PointNotOnCurve)
}

#[inline]
pub(super) fn read_bls_g1_point(point: &BlsG1) -> Result<bls::G1Affine, Error> {
    let point = read_bls_g1_point_no_subgroup_check(point)?;
    if point.is_in_correct_subgroup() {
        Ok(point)
    } else {
        Err(Error::PointNotInSubgroup)
    }
}

#[inline]
pub(super) fn read_bls_g2_point_no_subgroup_check(point: &BlsG2) -> Result<bls::G2Affine, Error> {
    let x = read_bls_fp2(&point.0, &point.1)?;
    let y = read_bls_fp2(&point.2, &point.3)?;
    // SAFETY: `read_bls_fp2` produces canonical Fp2 elements; `from_xy` itself checks the curve
    // equation and returns `None` if `(x, y)` is not on the twist.
    unsafe { bls::G2Affine::from_xy(x, y) }.ok_or(Error::PointNotOnCurve)
}

#[inline]
pub(super) fn read_bls_g2_point(point: &BlsG2) -> Result<bls::G2Affine, Error> {
    let point = read_bls_g2_point_no_subgroup_check(point)?;
    if point.is_in_correct_subgroup() {
        Ok(point)
    } else {
        Err(Error::PointNotInSubgroup)
    }
}

#[inline]
pub(super) fn read_bls_scalar(input: &[u8; 32]) -> bls::Scalar {
    bls::Scalar::from_be_bytes_unchecked(input)
}

#[inline]
pub(super) fn encode_bls_g1_point(point: &bls::G1Affine) -> [u8; 96] {
    let mut output = [0; 96];
    if point.is_identity() {
        return output;
    }

    let x_bytes: &[u8] = point.x().as_le_bytes();
    let y_bytes: &[u8] = point.y().as_le_bytes();
    for i in 0..BLS_FP_LEN {
        output[i] = x_bytes[BLS_FP_LEN - 1 - i];
        output[i + BLS_FP_LEN] = y_bytes[BLS_FP_LEN - 1 - i];
    }
    output
}

#[inline]
pub(super) fn encode_bls_g2_point(point: &bls::G2Affine) -> [u8; 192] {
    let mut output = [0; 192];
    if point.is_identity() {
        return output;
    }

    let x = point.x();
    let y = point.y();
    let x_c0 = x.c0.as_le_bytes();
    let x_c1 = x.c1.as_le_bytes();
    let y_c0 = y.c0.as_le_bytes();
    let y_c1 = y.c1.as_le_bytes();
    for i in 0..BLS_FP_LEN {
        output[i] = x_c0[BLS_FP_LEN - 1 - i];
        output[i + BLS_FP_LEN] = x_c1[BLS_FP_LEN - 1 - i];
        output[i + (2 * BLS_FP_LEN)] = y_c0[BLS_FP_LEN - 1 - i];
        output[i + (3 * BLS_FP_LEN)] = y_c1[BLS_FP_LEN - 1 - i];
    }
    output
}
