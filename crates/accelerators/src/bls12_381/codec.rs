//! EIP-2537 BLS12-381 point and scalar codecs.

use openvm_curve_utils::SubgroupCheck;
use openvm_ecc_guest::{algebra::IntMod, weierstrass::WeierstrassPoint, Group};
use openvm_pairing::bls12_381 as bls;

use crate::error::Error;

const FP_LEN: usize = 48;

#[inline]
fn read_fp(input: &[u8]) -> Result<bls::Fp, Error> {
    bls::Fp::from_be_bytes(input).ok_or(Error::FieldElementInvalid)
}

#[inline]
fn read_fp2(c0: &[u8], c1: &[u8]) -> Result<bls::Fp2, Error> {
    Ok(bls::Fp2::new(read_fp(c0)?, read_fp(c1)?))
}

#[inline]
pub(super) fn read_g1_no_subgroup_check(input: &[u8; 96]) -> Result<bls::G1Affine, Error> {
    let x = read_fp(&input[..FP_LEN])?;
    let y = read_fp(&input[FP_LEN..])?;
    // SAFETY: the coordinates are canonical; `from_xy` checks the curve equation.
    unsafe { bls::G1Affine::from_xy(x, y) }.ok_or(Error::PointNotOnCurve)
}

#[inline]
pub(super) fn read_g1(input: &[u8; 96]) -> Result<bls::G1Affine, Error> {
    let point = read_g1_no_subgroup_check(input)?;
    point.is_in_correct_subgroup().then_some(point).ok_or(Error::PointNotInSubgroup)
}

#[inline]
pub(super) fn read_g2_no_subgroup_check(input: &[u8; 192]) -> Result<bls::G2Affine, Error> {
    let x = read_fp2(&input[..FP_LEN], &input[FP_LEN..2 * FP_LEN])?;
    let y = read_fp2(&input[2 * FP_LEN..3 * FP_LEN], &input[3 * FP_LEN..])?;
    // SAFETY: the coordinates are canonical; `from_xy` checks the twist equation.
    unsafe { bls::G2Affine::from_xy(x, y) }.ok_or(Error::PointNotOnCurve)
}

#[inline]
pub(super) fn read_g2(input: &[u8; 192]) -> Result<bls::G2Affine, Error> {
    let point = read_g2_no_subgroup_check(input)?;
    point.is_in_correct_subgroup().then_some(point).ok_or(Error::PointNotInSubgroup)
}

#[inline]
pub(super) fn read_scalar(input: &[u8; 32]) -> bls::Scalar {
    bls::Scalar::from_be_bytes_unchecked(input)
}

#[inline]
pub(super) fn encode_g1(point: &bls::G1Affine) -> [u8; 96] {
    let mut output = [0; 96];
    if point.is_identity() {
        return output;
    }

    point.x().assert_reduced();
    point.y().assert_reduced();
    let x: &[u8] = point.x().as_le_bytes();
    let y: &[u8] = point.y().as_le_bytes();
    for index in 0..FP_LEN {
        output[index] = x[FP_LEN - 1 - index];
        output[index + FP_LEN] = y[FP_LEN - 1 - index];
    }
    output
}

#[inline]
pub(super) fn encode_g2(point: &bls::G2Affine) -> [u8; 192] {
    let mut output = [0; 192];
    if point.is_identity() {
        return output;
    }

    let x = point.x();
    let y = point.y();
    x.c0.assert_reduced();
    x.c1.assert_reduced();
    y.c0.assert_reduced();
    y.c1.assert_reduced();
    let x_c0 = x.c0.as_le_bytes();
    let x_c1 = x.c1.as_le_bytes();
    let y_c0 = y.c0.as_le_bytes();
    let y_c1 = y.c1.as_le_bytes();
    for index in 0..FP_LEN {
        output[index] = x_c0[FP_LEN - 1 - index];
        output[index + FP_LEN] = x_c1[FP_LEN - 1 - index];
        output[index + 2 * FP_LEN] = y_c0[FP_LEN - 1 - index];
        output[index + 3 * FP_LEN] = y_c1[FP_LEN - 1 - index];
    }
    output
}
