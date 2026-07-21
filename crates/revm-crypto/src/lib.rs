//! OpenVM Crypto Implementation for REVM
//!
//! This module provides OpenVM-optimized implementations of cryptographic operations
//! for both transaction validation (via Alloy crypto provider) and precompile execution.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use alloy_consensus::crypto::{
    backend::{install_default_provider, CryptoProvider},
    RecoveryError,
};
use alloy_primitives::Address;
use openvm_ecc_guest::{
    algebra::IntMod,
    weierstrass::{IntrinsicCurve, WeierstrassPoint},
    AffinePoint, Group,
};
use openvm_k256::ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId, Signature, VerifyingKey};
use openvm_keccak256::keccak256;
use openvm_kzg::{Bytes32, Bytes48, KzgProof};
use openvm_pairing::{
    bls12_381::{self as bls, Bls12_381},
    bn254::{self as bn, Bn254},
    PairingCheck,
};
use revm::{
    install_crypto,
    precompile::{
        bls12_381::{
            G1Point as BlsG1Point, G1PointScalar as BlsG1PointScalar, G2Point as BlsG2Point,
            G2PointScalar as BlsG2PointScalar,
        },
        bls12_381_const::{
            FP_LENGTH as BLS_FP_LEN, G1_LENGTH as BLS_G1_LEN, G2_LENGTH as BLS_G2_LEN,
            SCALAR_LENGTH as BLS_SCALAR_LEN,
        },
        Crypto, PrecompileHalt,
    },
};

use openvm_curve_utils::SubgroupCheck;

// BN254 constants
const BN_FQ_LEN: usize = 32;
const BN_G1_LEN: usize = 64;
const BN_G2_LEN: usize = 128;
/// BN_SCALAR_LEN specifies the number of bytes needed to represent an Fr element.
/// This is an element in the scalar field of BN254.
const BN_SCALAR_LEN: usize = 32;

/// OpenVM k256 backend for Alloy crypto operations (transaction validation)
#[derive(Debug, Default)]
struct OpenVmK256Provider;

impl CryptoProvider for OpenVmK256Provider {
    fn recover_signer_unchecked(
        &self,
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        // Extract components: sig[0..32]=r, sig[32..64]=s, sig[64]=recovery_id
        // Parse signature using OpenVM k256
        let mut signature = Signature::from_slice(&sig[..64]).map_err(|_| RecoveryError::new())?;

        // Normalize signature if needed
        let mut recid = sig[64];
        if let Some(sig_normalized) = signature.normalize_s() {
            signature = sig_normalized;
            recid ^= 1;
        }

        // Create recovery ID
        let recovery_id = RecoveryId::from_byte(recid).ok_or(RecoveryError::new())?;

        // Recover public key using OpenVM
        let recovered_key =
            VerifyingKey::recover_from_prehash_noverify(msg, &signature.to_bytes(), recovery_id)
                .map_err(|_| RecoveryError::new())?;

        // Hash the uncompressed SEC1 key without the 0x04 prefix.
        let public_key = recovered_key.to_encoded_point(false);
        let encoded_pubkey = &public_key.as_bytes()[1..65];

        // Hash to get Ethereum address
        let pubkey_hash = keccak256(encoded_pubkey);
        let address_bytes = &pubkey_hash[12..32]; // Last 20 bytes

        Ok(Address::from_slice(address_bytes))
    }

    fn verify_and_compute_signer_unchecked(
        &self,
        pubkey: &[u8; 65],
        sig: &[u8; 64],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        let vk = VerifyingKey::from_sec1_bytes(pubkey).map_err(|_| RecoveryError::new())?;

        let mut signature = Signature::from_slice(sig).map_err(|_| RecoveryError::new())?;
        if let Some(sig_normalized) = signature.normalize_s() {
            signature = sig_normalized;
        }

        vk.verify_prehash(msg.as_ref(), &signature).map_err(|_| RecoveryError::new())?;

        // Compute address directly from the provided pubkey bytes (skip 0x04 prefix)
        let pubkey_hash = keccak256(&pubkey[1..65]);
        Ok(Address::from_slice(&pubkey_hash[12..32]))
    }
}

/// OpenVM custom crypto implementation for faster precompiles
#[derive(Debug, Default)]
struct OpenVmCrypto;

impl Crypto for OpenVmCrypto {
    /// Custom SHA-256 implementation with openvm optimization
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        #[cfg(not(openvm_intrinsics))]
        use openvm_sha2::Digest;
        openvm_sha2::Sha256::digest(input).into()
    }

    /// Custom BN254 G1 addition with openvm optimization
    fn bn254_g1_add(&self, p1_bytes: &[u8], p2_bytes: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        let p1 = read_bn_g1_point(p1_bytes)?;
        let p2 = read_bn_g1_point(p2_bytes)?;
        let result = p1 + p2;
        Ok(encode_bn_g1_point(result))
    }

    /// Custom BN254 G1 scalar multiplication with openvm optimization
    fn bn254_g1_mul(
        &self,
        point_bytes: &[u8],
        scalar_bytes: &[u8],
    ) -> Result<[u8; 64], PrecompileHalt> {
        let p = read_bn_g1_point(point_bytes)?;
        let s = read_bn_scalar(scalar_bytes);
        let result = Bn254::msm(&[s], &[p]);
        Ok(encode_bn_g1_point(result))
    }

    /// Custom BN254 pairing check with openvm optimization
    fn bn254_pairing_check(&self, pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
        if pairs.is_empty() {
            return Ok(true);
        }
        let mut g1_points = Vec::with_capacity(pairs.len());
        let mut g2_points = Vec::with_capacity(pairs.len());

        for (g1_bytes, g2_bytes) in pairs {
            let g1 = read_bn_g1_point(g1_bytes)?;
            let g2 = read_bn_g2_point(g2_bytes)?;

            let (g1_x, g1_y, _) = g1.normalize().into_coords();
            let g1 = AffinePoint::new(g1_x, g1_y);

            let (g2_x, g2_y, _) = g2.normalize().into_coords();
            let g2 = AffinePoint::new(g2_x, g2_y);

            g1_points.push(g1);
            g2_points.push(g2);
        }

        let pairing_result = Bn254::pairing_check(&g1_points, &g2_points).is_ok();
        Ok(pairing_result)
    }

    /// Custom BLS12-381 G1 addition with openvm optimization
    fn bls12_381_g1_add(
        &self,
        a: BlsG1Point,
        b: BlsG1Point,
    ) -> Result<[u8; BLS_G1_LEN], PrecompileHalt> {
        // EIP-2537 G1ADD validates on-curve only, not subgroup membership.
        let p1 = read_bls_g1_point_no_subgroup_check(&a)?;
        let p2 = read_bls_g1_point_no_subgroup_check(&b)?;
        let sum = p1 + p2;
        Ok(encode_bls_g1_point(&sum))
    }

    /// Custom BLS12-381 G1 MSM with openvm optimization
    fn bls12_381_g1_msm(
        &self,
        pairs: &mut dyn Iterator<Item = Result<BlsG1PointScalar, PrecompileHalt>>,
    ) -> Result<[u8; BLS_G1_LEN], PrecompileHalt> {
        let mut scalars = Vec::new();
        let mut points = Vec::new();

        for pair in pairs {
            let (point_bytes, scalar_bytes) = pair?;
            points.push(read_bls_g1_point(&point_bytes)?);
            scalars.push(read_bls_scalar(&scalar_bytes));
        }

        if points.is_empty() {
            return Ok([0u8; BLS_G1_LEN]);
        }

        let result = Bls12_381::msm(&scalars, &points);
        Ok(encode_bls_g1_point(&result))
    }

    /// Custom BLS12-381 G2 addition with openvm optimization
    fn bls12_381_g2_add(
        &self,
        a: BlsG2Point,
        b: BlsG2Point,
    ) -> Result<[u8; BLS_G2_LEN], PrecompileHalt> {
        // EIP-2537 G2ADD validates on-curve only, not subgroup membership.
        let p1 = read_bls_g2_point_no_subgroup_check(&a)?;
        let p2 = read_bls_g2_point_no_subgroup_check(&b)?;
        let sum = p1 + p2;
        Ok(encode_bls_g2_point(&sum))
    }

    /// Custom BLS12-381 G2 MSM with openvm optimization
    fn bls12_381_g2_msm(
        &self,
        pairs: &mut dyn Iterator<Item = Result<BlsG2PointScalar, PrecompileHalt>>,
    ) -> Result<[u8; BLS_G2_LEN], PrecompileHalt> {
        let mut scalars = Vec::new();
        let mut points = Vec::new();

        for pair in pairs {
            let (point_bytes, scalar_bytes) = pair?;
            points.push(read_bls_g2_point(&point_bytes)?);
            scalars.push(read_bls_scalar(&scalar_bytes));
        }

        if points.is_empty() {
            return Ok([0u8; BLS_G2_LEN]);
        }

        // directly using openvm_ecc_guest::msm here
        let result = openvm_ecc_guest::msm(&scalars, &points);
        Ok(encode_bls_g2_point(&result))
    }

    /// Custom BLS12-381 pairing check with openvm optimization
    fn bls12_381_pairing_check(
        &self,
        pairs: &[(BlsG1Point, BlsG2Point)],
    ) -> Result<bool, PrecompileHalt> {
        if pairs.is_empty() {
            return Ok(true);
        }

        let mut g1_points = Vec::with_capacity(pairs.len());
        let mut g2_points = Vec::with_capacity(pairs.len());

        for (g1_bytes, g2_bytes) in pairs {
            let g1 = read_bls_g1_point(g1_bytes)?;
            let g2 = read_bls_g2_point(g2_bytes)?;

            let (g1_x, g1_y, _) = g1.normalize().into_coords();
            let (g2_x, g2_y, _) = g2.normalize().into_coords();

            g1_points.push(AffinePoint::new(g1_x, g1_y));
            g2_points.push(AffinePoint::new(g2_x, g2_y));
        }

        let pairing_result = Bls12_381::pairing_check(&g1_points, &g2_points).is_ok();
        Ok(pairing_result)
    }

    /// Custom secp256k1 ECDSA signature recovery with openvm optimization
    fn secp256k1_ecrecover(
        &self,
        sig_bytes: &[u8; 64],
        mut recid: u8,
        msg_hash: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        let mut sig = Signature::from_slice(sig_bytes)
            .map_err(|_| PrecompileHalt::other("Invalid signature format"))?;

        if let Some(sig_normalized) = sig.normalize_s() {
            sig = sig_normalized;
            recid ^= 1;
        }

        let recovery_id = RecoveryId::from_byte(recid)
            .ok_or_else(|| PrecompileHalt::other("Invalid recovery ID"))?;

        let recovered_key =
            VerifyingKey::recover_from_prehash_noverify(msg_hash, &sig.to_bytes(), recovery_id)
                .map_err(|_| PrecompileHalt::other("Key recovery failed"))?;

        let public_key = recovered_key.to_encoded_point(false);
        let encoded_pubkey = &public_key.as_bytes()[1..65];

        let pubkey_hash = keccak256(encoded_pubkey);
        let mut address = [0u8; 32];
        address[12..].copy_from_slice(&pubkey_hash[12..]);

        Ok(address)
    }

    /// Custom secp256r1 signature verification with openvm optimization
    fn secp256r1_verify_signature(&self, msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> bool {
        use openvm_p256::{
            ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey},
            EncodedPoint,
        };

        // Can fail only if the input is not exact length.
        let Ok(signature) = Signature::from_slice(sig) else {
            return false;
        };
        // Decode the public key bytes (x,y coordinates) using EncodedPoint
        let encoded_point = EncodedPoint::from_untagged_bytes(&(*pk).into());
        // Create VerifyingKey from the encoded point
        let Ok(public_key) = VerifyingKey::from_encoded_point(&encoded_point) else {
            return false;
        };

        public_key.verify_prehash(msg, &signature).is_ok()
    }

    /// Custom KZG point evaluation with configurable backends
    fn verify_kzg_proof(
        &self,
        z: &[u8; 32],
        y: &[u8; 32],
        commitment: &[u8; 48],
        proof: &[u8; 48],
    ) -> Result<(), PrecompileHalt> {
        let env = openvm_kzg::EnvKzgSettings::default();
        let kzg_settings = env.get();

        let commitment_bytes = Bytes48::from_slice(commitment)
            .map_err(|_| PrecompileHalt::other("invalid commitment bytes"))?;
        let z_bytes =
            Bytes32::from_slice(z).map_err(|_| PrecompileHalt::other("invalid z bytes"))?;
        let y_bytes =
            Bytes32::from_slice(y).map_err(|_| PrecompileHalt::other("invalid y bytes"))?;
        let proof_bytes =
            Bytes48::from_slice(proof).map_err(|_| PrecompileHalt::other("invalid proof bytes"))?;

        let valid = KzgProof::verify_kzg_proof(
            &commitment_bytes,
            &z_bytes,
            &y_bytes,
            &proof_bytes,
            kzg_settings,
        )
        .map_err(|_| PrecompileHalt::other("openvm kzg proof verification failed"))?;
        if valid {
            Ok(())
        } else {
            Err(PrecompileHalt::BlobVerifyKzgProofFailed)
        }
    }

    /// Custom modular exponentiation with BN254 Fr acceleration
    fn modexp(&self, base: &[u8], exp: &[u8], modulus: &[u8]) -> Result<Vec<u8>, PrecompileHalt> {
        if is_bn254_fr(modulus) {
            return Ok(accelerated_modexp_bn254_fr(base, exp));
        }
        Ok(aurora_engine_modexp::modexp(base, exp, modulus))
    }
}

/// Returns true if the modulus (big-endian, possibly with leading zeros) equals BN254 Fr.
fn is_bn254_fr(modulus: &[u8]) -> bool {
    // Strip leading zeros
    let stripped = match modulus.iter().position(|&b| b != 0) {
        Some(i) => &modulus[i..],
        None => return false, // all zeros
    };
    // bn::Scalar::MODULUS is little-endian; compare against reversed input
    stripped.len() == BN_SCALAR_LEN && stripped.iter().rev().eq(bn::Scalar::MODULUS.as_ref().iter())
}

/// Accelerated modexp for BN254 Fr using field arithmetic intrinsics.
fn accelerated_modexp_bn254_fr(base: &[u8], exp: &[u8]) -> Vec<u8> {
    use openvm_ecc_guest::algebra::{ExpBytes, Reduce};

    // OpenVM's field reduction requires inputs to be aligned to the field byte size.
    let padded_len = base.len().next_multiple_of(BN_SCALAR_LEN).max(BN_SCALAR_LEN);
    let mut padded = vec![0u8; padded_len];
    padded[padded_len - base.len()..].copy_from_slice(base);
    let base_fr = bn::Scalar::reduce_be_bytes(&padded);

    base_fr.exp_bytes(true, exp).to_be_bytes().as_ref().to_vec()
}

/// Install OpenVM crypto implementations globally
pub fn install_openvm_crypto() -> Result<bool, Box<dyn core::error::Error>> {
    // Install OpenVM k256 provider for Alloy (transaction validation)
    install_default_provider(Arc::new(OpenVmK256Provider))?;

    // Install OpenVM crypto for REVM precompiles
    let installed = install_crypto(OpenVmCrypto);

    Ok(installed)
}

// Helper functions for BN254 operations

#[inline]
fn read_bn_fq(input: &[u8]) -> Result<bn::Fp, PrecompileHalt> {
    if input.len() < BN_FQ_LEN {
        Err(PrecompileHalt::Bn254FieldPointNotAMember)
    } else {
        bn::Fp::from_be_bytes(&input[..BN_FQ_LEN]).ok_or(PrecompileHalt::Bn254FieldPointNotAMember)
    }
}

#[inline]
fn read_bn_fq2(input: &[u8]) -> Result<bn::Fp2, PrecompileHalt> {
    let y = read_bn_fq(&input[..BN_FQ_LEN])?;
    let x = read_bn_fq(&input[BN_FQ_LEN..BN_FQ_LEN * 2])?;
    Ok(bn::Fp2::new(x, y))
}

#[inline]
fn read_bn_g1_point(input: &[u8]) -> Result<bn::G1Affine, PrecompileHalt> {
    if input.len() != BN_G1_LEN {
        return Err(PrecompileHalt::Bn254PairLength);
    }
    let px = read_bn_fq(&input[0..BN_FQ_LEN])?;
    let py = read_bn_fq(&input[BN_FQ_LEN..BN_G1_LEN])?;
    // SAFETY: `read_bn_fq` produces canonical Fp elements; `from_xy` itself checks the curve
    // equation and returns `None` if `(px, py)` is not on the curve.
    let point = unsafe { bn::G1Affine::from_xy(px, py) }
        .ok_or(PrecompileHalt::Bn254AffineGFailedToCreate)?;
    if point.is_in_correct_subgroup() {
        Ok(point)
    } else {
        Err(PrecompileHalt::Bn254AffineGFailedToCreate)
    }
}

#[inline]
fn read_bn_g2_point(input: &[u8]) -> Result<bn::G2Affine, PrecompileHalt> {
    if input.len() != BN_G2_LEN {
        return Err(PrecompileHalt::Bn254PairLength);
    }
    let c0 = read_bn_fq2(&input[0..BN_G1_LEN])?;
    let c1 = read_bn_fq2(&input[BN_G1_LEN..BN_G2_LEN])?;
    // SAFETY: `read_bn_fq2` produces canonical Fp2 elements; `from_xy` itself checks the curve
    // equation and returns `None` if `(c0, c1)` is not on the twist.
    let point = unsafe { bn::G2Affine::from_xy(c0, c1) }
        .ok_or(PrecompileHalt::Bn254AffineGFailedToCreate)?;
    if point.is_in_correct_subgroup() {
        Ok(point)
    } else {
        Err(PrecompileHalt::Bn254AffineGFailedToCreate)
    }
}

#[inline]
fn encode_bn_g1_point(point: bn::G1Affine) -> [u8; BN_G1_LEN] {
    // EC-op results are projective (z != 1); the point at infinity encodes as all-zero.
    if point.is_identity() {
        return [0u8; BN_G1_LEN];
    }
    // Normalize to affine (x/z, y/z) before serializing — the raw projective x,y are NOT the
    // affine coordinates.
    let point = point.normalize();

    let mut output = [0u8; BN_G1_LEN];

    let x_bytes: &[u8] = point.x().as_le_bytes();
    let y_bytes: &[u8] = point.y().as_le_bytes();
    for i in 0..BN_FQ_LEN {
        output[i] = x_bytes[BN_FQ_LEN - 1 - i];
        output[i + BN_FQ_LEN] = y_bytes[BN_FQ_LEN - 1 - i];
    }
    output
}

/// Reads a scalar from the input slice
///
/// Note: The scalar does not need to be canonical.
///
/// # Panics
///
/// If `input.len()` is not equal to [`BN_SCALAR_LEN`].
#[inline]
fn read_bn_scalar(input: &[u8]) -> bn::Scalar {
    assert_eq!(
        input.len(),
        BN_SCALAR_LEN,
        "unexpected scalar length. got {}, expected {BN_SCALAR_LEN}",
        input.len()
    );
    bn::Scalar::from_be_bytes_unchecked(input)
}

// Helper functions for BLS12-381 operations

#[inline]
fn read_bls_fp(input: &[u8]) -> Result<bls::Fp, PrecompileHalt> {
    if input.len() != BLS_FP_LEN {
        return Err(PrecompileHalt::other("invalid BLS12-381 fp length"));
    }
    bls::Fp::from_be_bytes(input)
        .ok_or_else(|| PrecompileHalt::other("element not in BLS12-381 base field"))
}

#[inline]
fn read_bls_fp2(c0: &[u8], c1: &[u8]) -> Result<bls::Fp2, PrecompileHalt> {
    let real = read_bls_fp(c0)?;
    let imag = read_bls_fp(c1)?;
    Ok(bls::Fp2::new(real, imag))
}

#[inline]
fn read_bls_g1_point_no_subgroup_check(
    point: &BlsG1Point,
) -> Result<bls::G1Affine, PrecompileHalt> {
    let px = read_bls_fp(&point.0)?;
    let py = read_bls_fp(&point.1)?;
    // SAFETY: `read_bls_fp` produces canonical Fp elements; `from_xy` itself checks the curve
    // equation and returns `None` if `(px, py)` is not on the curve.
    unsafe { bls::G1Affine::from_xy(px, py) }.ok_or(PrecompileHalt::Bls12381G1NotOnCurve)
}

#[inline]
fn read_bls_g1_point(point: &BlsG1Point) -> Result<bls::G1Affine, PrecompileHalt> {
    let point = read_bls_g1_point_no_subgroup_check(point)?;
    if point.is_in_correct_subgroup() {
        Ok(point)
    } else {
        Err(PrecompileHalt::Bls12381G1NotInSubgroup)
    }
}

#[inline]
fn read_bls_g2_point_no_subgroup_check(
    point: &BlsG2Point,
) -> Result<bls::G2Affine, PrecompileHalt> {
    let x = read_bls_fp2(&point.0, &point.1)?;
    let y = read_bls_fp2(&point.2, &point.3)?;
    // SAFETY: `read_bls_fp2` produces canonical Fp2 elements; `from_xy` itself checks the curve
    // equation and returns `None` if `(x, y)` is not on the twist.
    unsafe { bls::G2Affine::from_xy(x, y) }.ok_or(PrecompileHalt::Bls12381G2NotOnCurve)
}

#[inline]
fn read_bls_g2_point(point: &BlsG2Point) -> Result<bls::G2Affine, PrecompileHalt> {
    let point = read_bls_g2_point_no_subgroup_check(point)?;
    if point.is_in_correct_subgroup() {
        Ok(point)
    } else {
        Err(PrecompileHalt::Bls12381G2NotInSubgroup)
    }
}

#[inline]
fn read_bls_scalar(input: &[u8]) -> bls::Scalar {
    assert_eq!(
        input.len(),
        BLS_SCALAR_LEN,
        "unexpected scalar length. got {}, expected {BLS_SCALAR_LEN}",
        input.len()
    );
    bls::Scalar::from_be_bytes_unchecked(input)
}

#[inline]
fn encode_bls_g1_point(point: &bls::G1Affine) -> [u8; BLS_G1_LEN] {
    if point.is_identity() {
        return [0u8; BLS_G1_LEN];
    }
    // Normalize to affine before serializing — EC-op results are projective (z != 1).
    let point = point.normalize();

    let mut output = [0u8; BLS_G1_LEN];
    let x_bytes: &[u8] = point.x().as_le_bytes();
    let y_bytes: &[u8] = point.y().as_le_bytes();
    for i in 0..BLS_FP_LEN {
        output[i] = x_bytes[BLS_FP_LEN - 1 - i];
        output[i + BLS_FP_LEN] = y_bytes[BLS_FP_LEN - 1 - i];
    }
    output
}

#[inline]
fn encode_bls_g2_point(point: &bls::G2Affine) -> [u8; BLS_G2_LEN] {
    if point.is_identity() {
        return [0u8; BLS_G2_LEN];
    }
    // Normalize to affine before serializing — EC-op results are projective (z != 1).
    let point = point.normalize();

    let mut output = [0u8; BLS_G2_LEN];
    let x = point.x();
    let y = point.y();
    let x_c0 = x.c0.as_le_bytes();
    let x_c1 = x.c1.as_le_bytes();
    let y_c0 = y.c0.as_le_bytes();
    let y_c1 = y.c1.as_le_bytes();
    for i in 0..BLS_FP_LEN {
        output[i] = x_c0[BLS_FP_LEN - 1 - i];
        output[i + BLS_FP_LEN] = x_c1[BLS_FP_LEN - 1 - i];
        output[i + (2 * BLS_FP_LEN)] = y_c0[BLS_FP_LEN - 1 - i];
        output[i + (3 * BLS_FP_LEN)] = y_c1[BLS_FP_LEN - 1 - i];
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `secp256r1_verify_signature` on a 160-byte P256VERIFY input (msg || sig || pk).
    fn p256_verify_input(input_hex: &str) -> bool {
        let input = alloy_primitives::hex::decode(input_hex).unwrap();
        assert_eq!(input.len(), 160);
        OpenVmCrypto.secp256r1_verify_signature(
            input[..32].try_into().unwrap(),
            input[32..96].try_into().unwrap(),
            input[96..160].try_into().unwrap(),
        )
    }

    // Test vectors from https://github.com/daimo-eth/p256-verifier/tree/master/test-vectors,
    // as used by revm-precompile's secp256r1 tests.
    #[test]
    fn test_secp256r1_verify_signature() {
        // valid signature
        assert!(p256_verify_input("4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e"));
        assert!(p256_verify_input("3fec5769b5cf4e310a7d150508e82fb8e3eda1c2c94c61492d3bd8aea99e06c9e22466e928fdccef0de49e3503d2657d00494a00e764fd437bdafa05f5922b1fbbb77c6817ccf50748419477e843d5bac67e6a70e97dde5a57e0c983b777e1ad31a80482dadf89de6302b1988c82c29544c9c07bb910596158f6062517eb089a2f54c9a0f348752950094d3228d3b940258c75fe2a413cb70baa21dc2e352fc5"));
        // wrong message
        assert!(!p256_verify_input("3cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e"));
        // signature values out of range
        assert!(!p256_verify_input("4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e"));
        // public key not on the curve
        assert!(!p256_verify_input("4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
    }

    /// BN254 Fr modulus in big-endian bytes
    fn bn254_fr_modulus_be() -> Vec<u8> {
        let m = bn::Scalar::MODULUS;
        m.as_ref().iter().rev().copied().collect()
    }

    /// Reference implementation: aurora_engine_modexp
    fn reference_modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
        aurora_engine_modexp::modexp(base, exp, modulus)
    }

    /// Helper: run accelerated and compare against reference.
    /// The accelerated path always returns BN_SCALAR_LEN bytes, so we left-pad the
    /// reference output to match.
    fn check(base: &[u8], exp: &[u8]) {
        let modulus = bn254_fr_modulus_be();
        let expected = reference_modexp(base, exp, &modulus);
        let actual = accelerated_modexp_bn254_fr(base, exp);
        let mut expected_padded = vec![0u8; BN_SCALAR_LEN];
        let offset = BN_SCALAR_LEN - expected.len();
        expected_padded[offset..].copy_from_slice(&expected);
        assert_eq!(actual, expected_padded, "base={base:?}, exp={exp:?}");
    }

    #[test]
    fn test_is_bn254_fr() {
        // Exact modulus
        assert!(is_bn254_fr(&bn254_fr_modulus_be()));

        // With leading zeros
        let mut padded = vec![0u8; 10];
        padded.extend_from_slice(&bn254_fr_modulus_be());
        assert!(is_bn254_fr(&padded));

        // All zeros → false
        assert!(!is_bn254_fr(&[0u8; 32]));

        // Wrong modulus (flip last bit)
        let mut m = bn254_fr_modulus_be();
        *m.last_mut().unwrap() ^= 1;
        assert!(!is_bn254_fr(&m));
    }

    #[test]
    fn test_accelerated_modexp_bn254_fr() {
        // --- short base (<=32 bytes), value < modulus ---
        check(&[3], &[5]); // 3^5 mod Fr
        check(&[0], &[5]); // 0^5 = 0
        check(&[3], &[0]); // 3^0 = 1
        check(&[0], &[0]); // 0^0 = 1 by convention
        check(&[], &[]); // empty inputs
        check(&[0, 0, 0, 3], &[5]); // leading zeros in base

        // --- short base, value >= modulus (triggers reduce fallback) ---
        let m = bn254_fr_modulus_be();
        check(&m, &[1]); // Fr mod Fr = 0, so 0^1 = 0
        let mut m_plus_1 = m.clone();
        *m_plus_1.last_mut().unwrap() = m_plus_1.last().unwrap().wrapping_add(1);
        check(&m_plus_1, &[2]); // (Fr+1)^2 mod Fr = 1
        check(&[0xff; 32], &[1]); // max 256-bit value, >= modulus

        // --- large base (> 32 bytes, reduce_be_bytes path) ---
        check(&[0xab; 64], &[3]); // aligned (multiple of 32)
        check(&[0x42; 100], &[2]); // unaligned (tests padding fix)
        check(&[0xab; 64], &[0xff; 32]); // large base + large exponent

        // --- larger exponents ---
        check(&[2], &[0xff; 32]); // 2^(2^256-1) mod Fr
        check(&[2], &[0, 0, 0, 5]); // leading zeros in exponent
        check(&[3], &[0xab; 64]); // exponent > 32 bytes

        // --- cross-path consistency: same value through different code paths ---
        // 33-byte base with leading zero (reduce_be_bytes path) vs 32-byte base (from_be_bytes
        // path)
        let base_32 = [0xab; 32];
        let mut base_33 = vec![0u8];
        base_33.extend_from_slice(&base_32);
        let exp = &[7];
        assert_eq!(
            accelerated_modexp_bn254_fr(&base_32, exp),
            accelerated_modexp_bn254_fr(&base_33, exp),
            "33-byte base with leading zero must match 32-byte base"
        );
    }

    /// Test the `Crypto::modexp` dispatch: accelerated path for BN254 Fr,
    /// aurora fallback for other moduli.
    #[test]
    fn test_modexp_dispatch() {
        let crypto = OpenVmCrypto;
        let fr_mod = bn254_fr_modulus_be();

        // Accelerated path: BN254 Fr modulus
        let accel = crypto.modexp(&[3], &[5], &fr_mod).unwrap();
        let reference = reference_modexp(&[3], &[5], &fr_mod);
        let mut ref_padded = vec![0u8; BN_SCALAR_LEN];
        let offset = BN_SCALAR_LEN - reference.len();
        ref_padded[offset..].copy_from_slice(&reference);
        assert_eq!(accel, ref_padded, "accelerated path should match reference");

        // Fallback path: non-BN254 modulus (e.g. small prime 7)
        let other_mod = &[7];
        let fallback = crypto.modexp(&[3], &[4], other_mod).unwrap();
        let expected = reference_modexp(&[3], &[4], other_mod);
        assert_eq!(fallback, expected, "fallback path should match reference");
    }
}
