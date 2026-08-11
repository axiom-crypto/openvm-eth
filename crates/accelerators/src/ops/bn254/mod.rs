//! BN254 (alt_bn128) group operations (EIP-196 / EIP-197).

mod codec;

use alloc::vec::Vec;

use codec::{encode_bn_g1_point, read_bn_g1_point, read_bn_g2_point, read_bn_scalar};
use openvm_ecc_guest::{
    weierstrass::{IntrinsicCurve, WeierstrassPoint},
    AffinePoint,
};
use openvm_pairing::{bn254::Bn254, PairingCheck};

use crate::ops::Error;

/// BN254 G1 point addition (precompile 0x06).
pub fn bn254_g1_add(p1: &[u8], p2: &[u8]) -> Result<[u8; 64], Error> {
    let p1 = read_bn_g1_point(p1)?;
    let p2 = read_bn_g1_point(p2)?;
    Ok(encode_bn_g1_point(p1 + p2))
}

/// BN254 G1 scalar multiplication (precompile 0x07).
pub fn bn254_g1_mul(point: &[u8], scalar: &[u8]) -> Result<[u8; 64], Error> {
    let p = read_bn_g1_point(point)?;
    let s = read_bn_scalar(scalar)?;
    Ok(encode_bn_g1_point(Bn254::msm(&[s], &[p])))
}

/// BN254 pairing check (precompile 0x08).
pub fn bn254_pairing_check<'a>(
    pairs: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<bool, Error> {
    let pairs = pairs.into_iter();
    let capacity = pairs.size_hint().0;

    let mut g1_points = Vec::with_capacity(capacity);
    let mut g2_points = Vec::with_capacity(capacity);

    for (g1, g2) in pairs {
        let g1 = read_bn_g1_point(g1)?;
        let g2 = read_bn_g2_point(g2)?;

        let (g1_x, g1_y) = g1.into_coords();
        let (g2_x, g2_y) = g2.into_coords();

        g1_points.push(AffinePoint::new(g1_x, g1_y));
        g2_points.push(AffinePoint::new(g2_x, g2_y));
    }

    if g1_points.is_empty() {
        return Ok(true);
    }
    Ok(Bn254::pairing_check(&g1_points, &g2_points).is_ok())
}
