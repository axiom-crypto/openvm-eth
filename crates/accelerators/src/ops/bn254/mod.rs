//! BN254 (alt_bn128) group operations (EIP-196 / EIP-197).

mod codec;

use codec::{encode_bn_g1_point, read_bn_g1_point, read_bn_scalar};
use openvm_ecc_guest::weierstrass::IntrinsicCurve;
use openvm_pairing::bn254::Bn254;

use crate::{
    ops::Error,
    types::{ZkvmBn254G1Point, ZkvmBn254Scalar},
};

/// BN254 G1 point addition (precompile 0x06).
pub fn bn254_g1_add(
    p1: &ZkvmBn254G1Point,
    p2: &ZkvmBn254G1Point,
    output: &mut ZkvmBn254G1Point,
) -> Result<(), Error> {
    let p1 = read_bn_g1_point(p1)?;
    let p2 = read_bn_g1_point(p2)?;
    encode_bn_g1_point(p1 + p2, output);
    Ok(())
}

/// BN254 G1 scalar multiplication (precompile 0x07).
pub fn bn254_g1_mul(
    point: &ZkvmBn254G1Point,
    scalar: &ZkvmBn254Scalar,
    output: &mut ZkvmBn254G1Point,
) -> Result<(), Error> {
    let p = read_bn_g1_point(point)?;
    let s = read_bn_scalar(scalar);
    encode_bn_g1_point(Bn254::msm(&[s], &[p]), output);
    Ok(())
}
