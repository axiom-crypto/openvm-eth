//! BLS12-381 map-to-curve (EIP-2537).
//!
//! Implemented using arkworks.

use ark_bls12_381::{Fq, Fq2, G1Affine, G2Affine};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurve},
    AffineRepr,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::BLS_FP_LEN;
use crate::ops::Error;

/// BLS12-381 map field element to G1 (precompile 0x10).
#[inline]
pub fn bls12_381_map_fp_to_g1(fp: &[u8; 48]) -> Result<[u8; 96], Error> {
    let fp = read_fq(fp)?;
    let point = WBMap::map_to_curve(fp)
        .expect("the arkworks WB map is defined for every field element")
        .clear_cofactor();

    Ok(encode_g1_point(&point))
}

/// BLS12-381 map field element to G2 (precompile 0x11).
#[inline]
pub fn bls12_381_map_fp2_to_g2(fp2: &([u8; 48], [u8; 48])) -> Result<[u8; 192], Error> {
    let c0 = read_fq(&fp2.0)?;
    let c1 = read_fq(&fp2.1)?;
    let point = WBMap::map_to_curve(Fq2::new(c0, c1))
        .expect("the arkworks WB map is defined for every field element")
        .clear_cofactor();

    Ok(encode_g2_point(&point))
}

/// Reads a big-endian field element, rejecting non-canonical encodings.
fn read_fq(input_be: &[u8]) -> Result<Fq, Error> {
    let mut input_le = [0u8; BLS_FP_LEN];
    input_le.copy_from_slice(input_be);
    input_le.reverse();

    Fq::deserialize_uncompressed(&input_le[..]).map_err(|_| Error::FieldElementInvalid)
}

/// Writes a field element as big-endian bytes.
fn encode_fq(fq: &Fq, output: &mut [u8]) {
    fq.serialize_uncompressed(&mut output[..]).expect("field element serialization is infallible");
    output.reverse();
}

/// Writes a G1 point as `x || y`; the point at infinity encodes as zeros.
fn encode_g1_point(point: &G1Affine) -> [u8; 96] {
    let mut output = [0; 96];
    let Some((x, y)) = point.xy() else {
        return output;
    };

    encode_fq(&x, &mut output[..BLS_FP_LEN]);
    encode_fq(&y, &mut output[BLS_FP_LEN..]);
    output
}

/// Writes a G2 point as `x_c0 || x_c1 || y_c0 || y_c1`; the point at infinity
/// encodes as zeros.
fn encode_g2_point(point: &G2Affine) -> [u8; 192] {
    let mut output = [0; 192];
    let Some((x, y)) = point.xy() else {
        return output;
    };

    encode_fq(&x.c0, &mut output[..BLS_FP_LEN]);
    encode_fq(&x.c1, &mut output[BLS_FP_LEN..2 * BLS_FP_LEN]);
    encode_fq(&y.c0, &mut output[2 * BLS_FP_LEN..3 * BLS_FP_LEN]);
    encode_fq(&y.c1, &mut output[3 * BLS_FP_LEN..]);
    output
}
