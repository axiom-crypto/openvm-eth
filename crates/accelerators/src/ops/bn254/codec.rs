//! Byte codecs for BN254: EIP-196/197 point encodings, including the
//! on-curve and subgroup validation performed while decoding.

use openvm_curve_utils::SubgroupCheck;
use openvm_ecc_guest::{algebra::IntMod, weierstrass::WeierstrassPoint};
use openvm_pairing::bn254 as bn;

use crate::ops::Error;

const BN_FQ_LEN: usize = 32;
const BN_G1_LEN: usize = BN_FQ_LEN * 2;
const BN_G2_LEN: usize = BN_G1_LEN * 2;

#[inline]
fn read_bn_fq(input: &[u8]) -> Result<bn::Fp, Error> {
    bn::Fp::from_be_bytes(&input[..BN_FQ_LEN]).ok_or(Error::FieldElementInvalid)
}

#[inline]
fn read_bn_fq2(input: &[u8]) -> Result<bn::Fp2, Error> {
    // EIP-197 encodes the imaginary part first.
    let imag = read_bn_fq(&input[..BN_FQ_LEN])?;
    let real = read_bn_fq(&input[BN_FQ_LEN..BN_FQ_LEN * 2])?;
    Ok(bn::Fp2::new(real, imag))
}

#[inline]
pub(super) fn read_bn_g1_point(input: &[u8]) -> Result<bn::G1Affine, Error> {
    if input.len() != BN_G1_LEN {
        return Err(Error::InvalidLength);
    }
    let px = read_bn_fq(&input[..BN_FQ_LEN])?;
    let py = read_bn_fq(&input[BN_FQ_LEN..])?;
    // SAFETY: `read_bn_fq` produces canonical Fp elements; `from_xy` itself checks the curve
    // equation and returns `None` if `(px, py)` is not on the curve.
    let point = unsafe { bn::G1Affine::from_xy(px, py) }.ok_or(Error::PointNotOnCurve)?;
    if point.is_in_correct_subgroup() {
        Ok(point)
    } else {
        Err(Error::PointNotInSubgroup)
    }
}

#[inline]
pub(super) fn read_bn_g2_point(input: &[u8]) -> Result<bn::G2Affine, Error> {
    if input.len() != BN_G2_LEN {
        return Err(Error::InvalidLength);
    }
    let x = read_bn_fq2(&input[..BN_G1_LEN])?;
    let y = read_bn_fq2(&input[BN_G1_LEN..])?;
    // SAFETY: `read_bn_fq2` produces canonical Fp2 elements; `from_xy` itself checks the curve
    // equation and returns `None` if `(x, y)` is not on the twist.
    let point = unsafe { bn::G2Affine::from_xy(x, y) }.ok_or(Error::PointNotOnCurve)?;
    if point.is_in_correct_subgroup() {
        Ok(point)
    } else {
        Err(Error::PointNotInSubgroup)
    }
}

#[inline]
pub(super) fn read_bn_scalar(input: &[u8]) -> Result<bn::Scalar, Error> {
    if input.len() != BN_FQ_LEN {
        return Err(Error::InvalidLength);
    }
    Ok(bn::Scalar::from_be_bytes_unchecked(input))
}

#[inline]
pub(super) fn encode_bn_g1_point(point: bn::G1Affine) -> [u8; BN_G1_LEN] {
    let mut output = [0; BN_G1_LEN];
    let x_bytes: &[u8] = point.x().as_le_bytes();
    let y_bytes: &[u8] = point.y().as_le_bytes();
    for i in 0..BN_FQ_LEN {
        output[i] = x_bytes[BN_FQ_LEN - 1 - i];
        output[i + BN_FQ_LEN] = y_bytes[BN_FQ_LEN - 1 - i];
    }
    output
}
