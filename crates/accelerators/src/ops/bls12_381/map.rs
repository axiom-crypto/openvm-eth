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
use crate::{
    ops::Error,
    types::{ZkvmBls12381Fp, ZkvmBls12381Fp2, ZkvmBls12381G1Point, ZkvmBls12381G2Point},
};

/// BLS12-381 map field element to G1 (precompile 0x10).
pub fn bls12_381_map_fp_to_g1(
    fp: &ZkvmBls12381Fp,
    output: &mut ZkvmBls12381G1Point,
) -> Result<(), Error> {
    let fp = read_fq(&fp.data)?;
    let point = WBMap::map_to_curve(fp)
        .expect("the arkworks WB map is defined for every field element")
        .clear_cofactor();

    encode_g1_point(&point, output);
    Ok(())
}

/// BLS12-381 map field element to G2 (precompile 0x11). Input is `c0 || c1`.
pub fn bls12_381_map_fp2_to_g2(
    fp2: &ZkvmBls12381Fp2,
    output: &mut ZkvmBls12381G2Point,
) -> Result<(), Error> {
    let c0 = read_fq(&fp2.data[..BLS_FP_LEN])?;
    let c1 = read_fq(&fp2.data[BLS_FP_LEN..])?;
    let point = WBMap::map_to_curve(Fq2::new(c0, c1))
        .expect("the arkworks WB map is defined for every field element")
        .clear_cofactor();

    encode_g2_point(&point, output);
    Ok(())
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
fn encode_g1_point(point: &G1Affine, output: &mut ZkvmBls12381G1Point) {
    let Some((x, y)) = point.xy() else {
        output.data.fill(0);
        return;
    };

    encode_fq(&x, &mut output.data[..BLS_FP_LEN]);
    encode_fq(&y, &mut output.data[BLS_FP_LEN..]);
}

/// Writes a G2 point as `x_c0 || x_c1 || y_c0 || y_c1`; the point at infinity
/// encodes as zeros.
fn encode_g2_point(point: &G2Affine, output: &mut ZkvmBls12381G2Point) {
    let Some((x, y)) = point.xy() else {
        output.data.fill(0);
        return;
    };

    encode_fq(&x.c0, &mut output.data[..BLS_FP_LEN]);
    encode_fq(&x.c1, &mut output.data[BLS_FP_LEN..2 * BLS_FP_LEN]);
    encode_fq(&y.c0, &mut output.data[2 * BLS_FP_LEN..3 * BLS_FP_LEN]);
    encode_fq(&y.c1, &mut output.data[3 * BLS_FP_LEN..]);
}
