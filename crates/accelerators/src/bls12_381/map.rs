//! BLS12-381 map-to-curve operations.

use ark_bls12_381::{Fq, Fq2, G1Affine, G2Affine};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurve},
    AffineRepr,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::error::Error;

const FP_LEN: usize = 48;

#[inline]
pub(super) fn fp_to_g1(input: &[u8; 48]) -> Result<[u8; 96], Error> {
    let point = WBMap::map_to_curve(read_fq(input)?)
        .expect("the arkworks WB map is defined for every field element")
        .clear_cofactor();
    Ok(encode_g1(&point))
}

#[inline]
pub(super) fn fp2_to_g2(input: &[u8; 96]) -> Result<[u8; 192], Error> {
    let c0 = read_fq(&input[..FP_LEN])?;
    let c1 = read_fq(&input[FP_LEN..])?;
    let point = WBMap::map_to_curve(Fq2::new(c0, c1))
        .expect("the arkworks WB map is defined for every field element")
        .clear_cofactor();
    Ok(encode_g2(&point))
}

fn read_fq(input_be: &[u8]) -> Result<Fq, Error> {
    let mut input_le = [0; FP_LEN];
    input_le.copy_from_slice(input_be);
    input_le.reverse();
    Fq::deserialize_uncompressed(&input_le[..]).map_err(|_| Error::FieldElementInvalid)
}

fn encode_fq(fq: &Fq, output: &mut [u8]) {
    fq.serialize_uncompressed(&mut output[..]).expect("field element serialization is infallible");
    output.reverse();
}

fn encode_g1(point: &G1Affine) -> [u8; 96] {
    let mut output = [0; 96];
    let Some((x, y)) = point.xy() else {
        return output;
    };
    encode_fq(&x, &mut output[..FP_LEN]);
    encode_fq(&y, &mut output[FP_LEN..]);
    output
}

fn encode_g2(point: &G2Affine) -> [u8; 192] {
    let mut output = [0; 192];
    let Some((x, y)) = point.xy() else {
        return output;
    };
    encode_fq(&x.c0, &mut output[..FP_LEN]);
    encode_fq(&x.c1, &mut output[FP_LEN..2 * FP_LEN]);
    encode_fq(&y.c0, &mut output[2 * FP_LEN..3 * FP_LEN]);
    encode_fq(&y.c1, &mut output[3 * FP_LEN..]);
    output
}
