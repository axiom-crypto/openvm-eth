//! BN254 (alt_bn128) group operations (EIP-196 / EIP-197).

mod codec;

use alloc::vec::Vec;

use codec::{encode_bn_g1_point, read_bn_g1_point, read_bn_g2_point, read_bn_scalar};
use openvm_ecc_guest::{
    weierstrass::{IntrinsicCurve, WeierstrassPoint},
    AffinePoint,
};
use openvm_pairing::{bn254::Bn254, PairingCheck};

use crate::{
    ops::Error,
    types::{ZkvmBn254G1Point, ZkvmBn254PairingPair, ZkvmBn254Scalar},
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

/// BN254 pairing check (precompile 0x08).
pub fn bn254_pairing_check(
    pairs: &[ZkvmBn254PairingPair],
    verified: &mut bool,
) -> Result<(), Error> {
    *verified = false;

    if pairs.is_empty() {
        *verified = true;
        return Ok(());
    }

    let mut g1_points = Vec::with_capacity(pairs.len());
    let mut g2_points = Vec::with_capacity(pairs.len());

    for pair in pairs {
        let g1 = read_bn_g1_point(&pair.g1)?;
        let g2 = read_bn_g2_point(&pair.g2)?;

        let (g1_x, g1_y) = g1.into_coords();
        let (g2_x, g2_y) = g2.into_coords();

        g1_points.push(AffinePoint::new(g1_x, g1_y));
        g2_points.push(AffinePoint::new(g2_x, g2_y));
    }

    *verified = Bn254::pairing_check(&g1_points, &g2_points).is_ok();
    Ok(())
}
