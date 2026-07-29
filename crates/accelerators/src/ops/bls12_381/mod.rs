//! BLS12-381 group operations (EIP-2537).

mod codec;
mod map;

pub use map::{bls12_381_map_fp2_to_g2, bls12_381_map_fp_to_g1};

use alloc::vec::Vec;

use codec::{
    encode_bls_g1_point, encode_bls_g2_point, read_bls_g1_point,
    read_bls_g1_point_no_subgroup_check, read_bls_g2_point, read_bls_g2_point_no_subgroup_check,
    read_bls_scalar,
};
use openvm_ecc_guest::{
    weierstrass::{IntrinsicCurve, WeierstrassPoint},
    AffinePoint,
};
use openvm_pairing::{bls12_381::Bls12_381, PairingCheck};

use crate::{
    ops::Error,
    types::{
        ZkvmBls12381G1MsmPair, ZkvmBls12381G1Point, ZkvmBls12381G2MsmPair, ZkvmBls12381G2Point,
        ZkvmBls12381PairingPair,
    },
};

/// The number of bytes needed to represent an element of the base field Fp.
const BLS_FP_LEN: usize = 48;

/// BLS12-381 G1 point addition (precompile 0x0b). Inputs are `x || y`.
///
/// Per EIP-2537 G1ADD, inputs are validated on-curve only, not for subgroup
/// membership.
pub fn bls12_381_g1_add(
    p1: &ZkvmBls12381G1Point,
    p2: &ZkvmBls12381G1Point,
    output: &mut ZkvmBls12381G1Point,
) -> Result<(), Error> {
    let p1 = read_bls_g1_point_no_subgroup_check(p1)?;
    let p2 = read_bls_g1_point_no_subgroup_check(p2)?;
    encode_bls_g1_point(&(p1 + p2), output);
    Ok(())
}

/// BLS12-381 G1 multi-scalar multiplication (precompile 0x0c).
///
/// Points must be in the prime-order subgroup; scalars need not be canonical.
/// An empty input yields the identity (all-zero) encoding.
pub fn bls12_381_g1_msm(
    pairs: &[ZkvmBls12381G1MsmPair],
    output: &mut ZkvmBls12381G1Point,
) -> Result<(), Error> {
    if pairs.is_empty() {
        output.data = [0u8; 96];
        return Ok(());
    }

    let mut points = Vec::with_capacity(pairs.len());
    let mut scalars = Vec::with_capacity(pairs.len());
    for pair in pairs {
        points.push(read_bls_g1_point(&pair.point)?);
        scalars.push(read_bls_scalar(&pair.scalar));
    }
    encode_bls_g1_point(&Bls12_381::msm(&scalars, &points), output);
    Ok(())
}

/// BLS12-381 G2 point addition (precompile 0x0d).
///
/// Per EIP-2537 G2ADD, inputs are validated on-curve only, not for subgroup
/// membership.
pub fn bls12_381_g2_add(
    p1: &ZkvmBls12381G2Point,
    p2: &ZkvmBls12381G2Point,
    output: &mut ZkvmBls12381G2Point,
) -> Result<(), Error> {
    let p1 = read_bls_g2_point_no_subgroup_check(p1)?;
    let p2 = read_bls_g2_point_no_subgroup_check(p2)?;
    encode_bls_g2_point(&(p1 + p2), output);
    Ok(())
}

/// BLS12-381 G2 multi-scalar multiplication (precompile 0x0e).
///
/// Points must be in the prime-order subgroup; scalars need not be canonical.
/// An empty input yields the identity (all-zero) encoding.
pub fn bls12_381_g2_msm(
    pairs: &[ZkvmBls12381G2MsmPair],
    output: &mut ZkvmBls12381G2Point,
) -> Result<(), Error> {
    if pairs.is_empty() {
        output.data = [0u8; 192];
        return Ok(());
    }

    let mut points = Vec::with_capacity(pairs.len());
    let mut scalars = Vec::with_capacity(pairs.len());
    for pair in pairs {
        points.push(read_bls_g2_point(&pair.point)?);
        scalars.push(read_bls_scalar(&pair.scalar));
    }
    encode_bls_g2_point(&openvm_ecc_guest::msm(&scalars, &points), output);
    Ok(())
}

/// BLS12-381 pairing check (precompile 0x0f).
///
/// Points must be in the prime-order subgroup.
pub fn bls12_381_pairing_check(
    pairs: &[ZkvmBls12381PairingPair],
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
        let g1 = read_bls_g1_point(&pair.g1)?;
        let g2 = read_bls_g2_point(&pair.g2)?;

        let (g1_x, g1_y) = g1.into_coords();
        let (g2_x, g2_y) = g2.into_coords();

        g1_points.push(AffinePoint::new(g1_x, g1_y));
        g2_points.push(AffinePoint::new(g2_x, g2_y));
    }

    *verified = Bls12_381::pairing_check(&g1_points, &g2_points).is_ok();
    Ok(())
}
