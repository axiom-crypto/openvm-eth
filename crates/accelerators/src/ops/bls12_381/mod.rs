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

use crate::ops::{BlsG1, BlsG2, Error, StreamError};

/// The number of bytes needed to represent an element of the base field Fp.
const BLS_FP_LEN: usize = 48;

/// BLS12-381 G1 point addition (precompile 0x0b). Inputs are `x || y`.
///
/// Per EIP-2537 G1ADD, inputs are validated on-curve only, not for subgroup
/// membership.
#[inline]
pub fn bls12_381_g1_add(p1: &BlsG1, p2: &BlsG1) -> Result<[u8; 96], Error> {
    let p1 = read_bls_g1_point_no_subgroup_check(p1)?;
    let p2 = read_bls_g1_point_no_subgroup_check(p2)?;
    Ok(encode_bls_g1_point(&(p1 + p2)))
}

/// BLS12-381 G1 multi-scalar multiplication (precompile 0x0c).
///
/// Points must be in the prime-order subgroup; scalars need not be canonical.
/// An empty input yields the identity (all-zero) encoding.
pub fn bls12_381_g1_msm<E>(
    pairs: impl IntoIterator<Item = Result<(BlsG1, [u8; 32]), E>>,
) -> Result<[u8; 96], StreamError<E>> {
    let pairs = pairs.into_iter();
    let capacity = pairs.size_hint().0;

    let mut points = Vec::with_capacity(capacity);
    let mut scalars = Vec::with_capacity(capacity);
    for pair in pairs {
        let (point, scalar) = pair.map_err(StreamError::Source)?;
        points.push(read_bls_g1_point(&point).map_err(StreamError::Operation)?);
        scalars.push(read_bls_scalar(&scalar));
    }
    if points.is_empty() {
        Ok([0; 96])
    } else {
        Ok(encode_bls_g1_point(&Bls12_381::msm(&scalars, &points)))
    }
}

/// BLS12-381 G2 point addition (precompile 0x0d).
///
/// Per EIP-2537 G2ADD, inputs are validated on-curve only, not for subgroup
/// membership.
#[inline]
pub fn bls12_381_g2_add(p1: &BlsG2, p2: &BlsG2) -> Result<[u8; 192], Error> {
    let p1 = read_bls_g2_point_no_subgroup_check(p1)?;
    let p2 = read_bls_g2_point_no_subgroup_check(p2)?;
    Ok(encode_bls_g2_point(&(p1 + p2)))
}

/// BLS12-381 G2 multi-scalar multiplication (precompile 0x0e).
///
/// Points must be in the prime-order subgroup; scalars need not be canonical.
/// An empty input yields the identity (all-zero) encoding.
pub fn bls12_381_g2_msm<E>(
    pairs: impl IntoIterator<Item = Result<(BlsG2, [u8; 32]), E>>,
) -> Result<[u8; 192], StreamError<E>> {
    let pairs = pairs.into_iter();
    let capacity = pairs.size_hint().0;

    let mut points = Vec::with_capacity(capacity);
    let mut scalars = Vec::with_capacity(capacity);
    for pair in pairs {
        let (point, scalar) = pair.map_err(StreamError::Source)?;
        points.push(read_bls_g2_point(&point).map_err(StreamError::Operation)?);
        scalars.push(read_bls_scalar(&scalar));
    }
    if points.is_empty() {
        Ok([0; 192])
    } else {
        Ok(encode_bls_g2_point(&openvm_ecc_guest::msm(&scalars, &points)))
    }
}

/// BLS12-381 pairing check (precompile 0x0f).
///
/// Points must be in the prime-order subgroup.
pub fn bls12_381_pairing_check(
    pairs: impl IntoIterator<Item = (BlsG1, BlsG2)>,
) -> Result<bool, Error> {
    let pairs = pairs.into_iter();
    let capacity = pairs.size_hint().0;

    let mut g1_points = Vec::with_capacity(capacity);
    let mut g2_points = Vec::with_capacity(capacity);

    for (g1, g2) in pairs {
        let g1 = read_bls_g1_point(&g1).map_err(|error| match error {
            Error::PointNotOnCurve => Error::BlsG1PointNotOnCurve,
            Error::PointNotInSubgroup => Error::BlsG1PointNotInSubgroup,
            error => error,
        })?;
        let g2 = read_bls_g2_point(&g2).map_err(|error| match error {
            Error::PointNotOnCurve => Error::BlsG2PointNotOnCurve,
            Error::PointNotInSubgroup => Error::BlsG2PointNotInSubgroup,
            error => error,
        })?;

        let (g1_x, g1_y) = g1.into_coords();
        let (g2_x, g2_y) = g2.into_coords();

        g1_points.push(AffinePoint::new(g1_x, g1_y));
        g2_points.push(AffinePoint::new(g2_x, g2_y));
    }

    if g1_points.is_empty() {
        return Ok(true);
    }
    Ok(Bls12_381::pairing_check(&g1_points, &g2_points).is_ok())
}
