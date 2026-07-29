//! Byte codecs for BN254: EIP-196/197 point encodings, including the
//! on-curve and subgroup validation performed while decoding.

use openvm_curve_utils::SubgroupCheck;
use openvm_ecc_guest::{algebra::IntMod, weierstrass::WeierstrassPoint};
use openvm_pairing::bn254 as bn;

use crate::{
    ops::Error,
    types::{ZkvmBn254G1Point, ZkvmBn254Scalar},
};

const BN_FQ_LEN: usize = 32;

#[inline]
fn read_bn_fq(input: &[u8]) -> Result<bn::Fp, Error> {
    bn::Fp::from_be_bytes(&input[..BN_FQ_LEN]).ok_or(Error::FieldElementInvalid)
}

#[inline]
pub(super) fn read_bn_g1_point(input: &ZkvmBn254G1Point) -> Result<bn::G1Affine, Error> {
    let px = read_bn_fq(&input.data[0..BN_FQ_LEN])?;
    let py = read_bn_fq(&input.data[BN_FQ_LEN..])?;
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
pub(super) fn read_bn_scalar(input: &ZkvmBn254Scalar) -> bn::Scalar {
    bn::Scalar::from_be_bytes_unchecked(&input.data)
}

#[inline]
pub(super) fn encode_bn_g1_point(point: bn::G1Affine, output: &mut ZkvmBn254G1Point) {
    let x_bytes: &[u8] = point.x().as_le_bytes();
    let y_bytes: &[u8] = point.y().as_le_bytes();
    for i in 0..BN_FQ_LEN {
        output.data[i] = x_bytes[BN_FQ_LEN - 1 - i];
        output.data[i + BN_FQ_LEN] = y_bytes[BN_FQ_LEN - 1 - i];
    }
}
