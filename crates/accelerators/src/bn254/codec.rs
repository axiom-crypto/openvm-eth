use openvm_curve_utils::SubgroupCheck;
use openvm_ecc_guest::{algebra::IntMod, weierstrass::WeierstrassPoint};
use openvm_pairing::bn254 as bn;

use crate::error::Error;

const FQ_LEN: usize = 32;

#[inline]
fn read_fq(input: &[u8]) -> Result<bn::Fp, Error> {
    bn::Fp::from_be_bytes(input).ok_or(Error::FieldElementInvalid)
}

#[inline]
fn read_fq2(input: &[u8; 64]) -> Result<bn::Fp2, Error> {
    let imag = read_fq(&input[..FQ_LEN])?;
    let real = read_fq(&input[FQ_LEN..])?;
    Ok(bn::Fp2::new(real, imag))
}

#[inline]
pub(super) fn read_g1(input: &[u8; 64]) -> Result<bn::G1Affine, Error> {
    let x = read_fq(&input[..FQ_LEN])?;
    let y = read_fq(&input[FQ_LEN..])?;
    // SAFETY: the coordinates are canonical; `from_xy` checks the curve equation.
    let point = unsafe { bn::G1Affine::from_xy(x, y) }.ok_or(Error::PointNotOnCurve)?;
    point.is_in_correct_subgroup().then_some(point).ok_or(Error::PointNotInSubgroup)
}

#[inline]
pub(super) fn read_g2(input: &[u8; 128]) -> Result<bn::G2Affine, Error> {
    let x = read_fq2(input[..64].try_into().unwrap())?;
    let y = read_fq2(input[64..].try_into().unwrap())?;
    // SAFETY: the coordinates are canonical; `from_xy` checks the curve equation.
    let point = unsafe { bn::G2Affine::from_xy(x, y) }.ok_or(Error::PointNotOnCurve)?;
    point.is_in_correct_subgroup().then_some(point).ok_or(Error::PointNotInSubgroup)
}

#[inline]
pub(super) fn read_scalar(input: &[u8; 32]) -> bn::Scalar {
    bn::Scalar::from_be_bytes_unchecked(input)
}

#[inline]
pub(super) fn encode_g1(point: bn::G1Affine) -> [u8; 64] {
    let mut output = [0; 64];
    let x: &[u8] = point.x().as_le_bytes();
    let y: &[u8] = point.y().as_le_bytes();
    for index in 0..FQ_LEN {
        output[index] = x[FQ_LEN - 1 - index];
        output[index + FQ_LEN] = y[FQ_LEN - 1 - index];
    }
    output
}
