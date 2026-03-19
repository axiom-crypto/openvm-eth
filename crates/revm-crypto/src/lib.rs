//! OpenVM Crypto Implementation for REVM
//!
//! This module provides OpenVM-optimized implementations of cryptographic operations
//! for both transaction validation (via Alloy crypto provider) and precompile execution.

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
use openvm_k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use openvm_keccak256::keccak256;
use openvm_kzg::{Bytes32, Bytes48, KzgProof};
#[allow(unused_imports, clippy::single_component_path_imports)]
use openvm_p256; // ensure this is linked in for the standard OpenVM config
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
        Crypto, PrecompileError,
    },
};
use std::{sync::Arc, vec::Vec};

mod subgroup_check;
use subgroup_check::SubgroupCheck;

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

        // Get public key coordinates
        let public_key = recovered_key.as_affine();
        let mut encoded_pubkey = [0u8; 64];
        encoded_pubkey[..32].copy_from_slice(&WeierstrassPoint::x(public_key).to_be_bytes());
        encoded_pubkey[32..].copy_from_slice(&WeierstrassPoint::y(public_key).to_be_bytes());

        // Hash to get Ethereum address
        let pubkey_hash = keccak256(&encoded_pubkey);
        let address_bytes = &pubkey_hash[12..32]; // Last 20 bytes

        Ok(Address::from_slice(address_bytes))
    }
}

/// OpenVM custom crypto implementation for faster precompiles
#[derive(Debug, Default)]
struct OpenVmCrypto;

impl Crypto for OpenVmCrypto {
    /// Custom SHA-256 implementation with openvm optimization
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        #[cfg(not(target_os = "zkvm"))]
        use openvm_sha2::Digest;
        openvm_sha2::Sha256::digest(input).into()
    }

    /// Custom BN254 G1 addition with openvm optimization
    fn bn254_g1_add(&self, p1_bytes: &[u8], p2_bytes: &[u8]) -> Result<[u8; 64], PrecompileError> {
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
    ) -> Result<[u8; 64], PrecompileError> {
        let p = read_bn_g1_point(point_bytes)?;
        let s = read_bn_scalar(scalar_bytes);
        let result = Bn254::msm(&[s], &[p]);
        Ok(encode_bn_g1_point(result))
    }

    /// Custom BN254 pairing check with openvm optimization
    fn bn254_pairing_check(&self, pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileError> {
        if pairs.is_empty() {
            return Ok(true);
        }
        let mut g1_points = Vec::with_capacity(pairs.len());
        let mut g2_points = Vec::with_capacity(pairs.len());

        for (g1_bytes, g2_bytes) in pairs {
            let g1 = read_bn_g1_point(g1_bytes)?;
            let g2 = read_bn_g2_point(g2_bytes)?;

            let (g1_x, g1_y) = g1.into_coords();
            let g1 = AffinePoint::new(g1_x, g1_y);

            let (g2_x, g2_y) = g2.into_coords();
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
    ) -> Result<[u8; BLS_G1_LEN], PrecompileError> {
        let p1 = read_bls_g1_point(&a)?;
        let p2 = read_bls_g1_point(&b)?;
        let sum = p1 + p2;
        Ok(encode_bls_g1_point(&sum))
    }

    /// Custom BLS12-381 G1 MSM with openvm optimization
    fn bls12_381_g1_msm(
        &self,
        pairs: &mut dyn Iterator<Item = Result<BlsG1PointScalar, PrecompileError>>,
    ) -> Result<[u8; BLS_G1_LEN], PrecompileError> {
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
    ) -> Result<[u8; BLS_G2_LEN], PrecompileError> {
        let p1 = read_bls_g2_point(&a)?;
        let p2 = read_bls_g2_point(&b)?;
        let sum = p1 + p2;
        Ok(encode_bls_g2_point(&sum))
    }

    /// Custom BLS12-381 G2 MSM with openvm optimization
    fn bls12_381_g2_msm(
        &self,
        pairs: &mut dyn Iterator<Item = Result<BlsG2PointScalar, PrecompileError>>,
    ) -> Result<[u8; BLS_G2_LEN], PrecompileError> {
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
    ) -> Result<bool, PrecompileError> {
        if pairs.is_empty() {
            return Ok(true);
        }

        let mut g1_points = Vec::with_capacity(pairs.len());
        let mut g2_points = Vec::with_capacity(pairs.len());

        for (g1_bytes, g2_bytes) in pairs {
            let g1 = read_bls_g1_point(g1_bytes)?;
            let g2 = read_bls_g2_point(g2_bytes)?;

            let (g1_x, g1_y) = g1.into_coords();
            let (g2_x, g2_y) = g2.into_coords();

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
    ) -> Result<[u8; 32], PrecompileError> {
        let mut sig = Signature::from_slice(sig_bytes)
            .map_err(|_| PrecompileError::other("Invalid signature format"))?;

        if let Some(sig_normalized) = sig.normalize_s() {
            sig = sig_normalized;
            recid ^= 1;
        }

        let recovery_id = RecoveryId::from_byte(recid)
            .ok_or_else(|| PrecompileError::other("Invalid recovery ID"))?;

        let recovered_key =
            VerifyingKey::recover_from_prehash_noverify(msg_hash, &sig.to_bytes(), recovery_id)
                .map_err(|_| PrecompileError::other("Key recovery failed"))?;

        let public_key = recovered_key.as_affine();
        let mut encoded_pubkey = [0u8; 64];
        encoded_pubkey[..32].copy_from_slice(&WeierstrassPoint::x(public_key).to_be_bytes());
        encoded_pubkey[32..].copy_from_slice(&WeierstrassPoint::y(public_key).to_be_bytes());

        let pubkey_hash = keccak256(&encoded_pubkey);
        let mut address = [0u8; 32];
        address[12..].copy_from_slice(&pubkey_hash[12..]);

        Ok(address)
    }

    /// Custom KZG point evaluation with configurable backends
    fn verify_kzg_proof(
        &self,
        z: &[u8; 32],
        y: &[u8; 32],
        commitment: &[u8; 48],
        proof: &[u8; 48],
    ) -> Result<(), PrecompileError> {
        let env = openvm_kzg::EnvKzgSettings::default();
        let kzg_settings = env.get();

        let commitment_bytes = Bytes48::from_slice(commitment)
            .map_err(|_| PrecompileError::other("invalid commitment bytes"))?;
        let z_bytes =
            Bytes32::from_slice(z).map_err(|_| PrecompileError::other("invalid z bytes"))?;
        let y_bytes =
            Bytes32::from_slice(y).map_err(|_| PrecompileError::other("invalid y bytes"))?;
        let proof_bytes = Bytes48::from_slice(proof)
            .map_err(|_| PrecompileError::other("invalid proof bytes"))?;

        KzgProof::verify_kzg_proof(
            &commitment_bytes,
            &z_bytes,
            &y_bytes,
            &proof_bytes,
            kzg_settings,
        )
        .map_err(|_| PrecompileError::other("openvm kzg proof verification failed"))?;
        Ok(())
    }

    /// Custom modular exponentiation with BN254 Fr acceleration
    fn modexp(&self, base: &[u8], exp: &[u8], modulus: &[u8]) -> Result<Vec<u8>, PrecompileError> {
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

    let base_fr = if base.len() <= BN_SCALAR_LEN {
        // Use checked conversion; reduce if base >= modulus.
        bn::Scalar::from_be_bytes(base).unwrap_or_else(|| bn::Scalar::reduce_be_bytes(base))
    } else {
        // Pad to a multiple of BN_SCALAR_LEN so reduce_be_bytes chunk processing works correctly.
        let padded_len = base.len().next_multiple_of(BN_SCALAR_LEN);
        let mut padded = vec![0u8; padded_len];
        padded[padded_len - base.len()..].copy_from_slice(base);
        bn::Scalar::reduce_be_bytes(&padded)
    };

    base_fr.exp_bytes(true, exp).to_be_bytes().as_ref().to_vec()
}

/// Install OpenVM crypto implementations globally
pub fn install_openvm_crypto() -> Result<bool, Box<dyn std::error::Error>> {
    // Install OpenVM k256 provider for Alloy (transaction validation)
    install_default_provider(Arc::new(OpenVmK256Provider))?;

    // Install OpenVM crypto for REVM precompiles
    let installed = install_crypto(OpenVmCrypto);

    Ok(installed)
}

// Helper functions for BN254 operations

#[inline]
fn read_bn_fq(input: &[u8]) -> Result<bn::Fp, PrecompileError> {
    if input.len() < BN_FQ_LEN {
        Err(PrecompileError::Bn254FieldPointNotAMember)
    } else {
        bn::Fp::from_be_bytes(&input[..BN_FQ_LEN]).ok_or(PrecompileError::Bn254FieldPointNotAMember)
    }
}

#[inline]
fn read_bn_fq2(input: &[u8]) -> Result<bn::Fp2, PrecompileError> {
    let y = read_bn_fq(&input[..BN_FQ_LEN])?;
    let x = read_bn_fq(&input[BN_FQ_LEN..BN_FQ_LEN * 2])?;
    Ok(bn::Fp2::new(x, y))
}

#[inline]
fn read_bn_g1_point(input: &[u8]) -> Result<bn::G1Affine, PrecompileError> {
    if input.len() != BN_G1_LEN {
        return Err(PrecompileError::Bn254PairLength);
    }
    let px = read_bn_fq(&input[0..BN_FQ_LEN])?;
    let py = read_bn_fq(&input[BN_FQ_LEN..BN_G1_LEN])?;
    let point = bn::G1Affine::from_xy(px, py).ok_or(PrecompileError::Bn254AffineGFailedToCreate)?;
    if point.is_in_correct_subgroup() {
        Ok(point)
    } else {
        Err(PrecompileError::Bn254AffineGFailedToCreate)
    }
}

#[inline]
fn read_bn_g2_point(input: &[u8]) -> Result<bn::G2Affine, PrecompileError> {
    if input.len() != BN_G2_LEN {
        return Err(PrecompileError::Bn254PairLength);
    }
    let c0 = read_bn_fq2(&input[0..BN_G1_LEN])?;
    let c1 = read_bn_fq2(&input[BN_G1_LEN..BN_G2_LEN])?;
    let point = bn::G2Affine::from_xy(c0, c1).ok_or(PrecompileError::Bn254AffineGFailedToCreate)?;
    if point.is_in_correct_subgroup() {
        Ok(point)
    } else {
        Err(PrecompileError::Bn254AffineGFailedToCreate)
    }
}

#[inline]
fn encode_bn_g1_point(point: bn::G1Affine) -> [u8; BN_G1_LEN] {
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
fn read_bls_fp(input: &[u8]) -> Result<bls::Fp, PrecompileError> {
    if input.len() != BLS_FP_LEN {
        return Err(PrecompileError::other("invalid BLS12-381 fp length"));
    }
    bls::Fp::from_be_bytes(input)
        .ok_or_else(|| PrecompileError::other("element not in BLS12-381 base field"))
}

#[inline]
fn read_bls_fp2(c0: &[u8], c1: &[u8]) -> Result<bls::Fp2, PrecompileError> {
    let real = read_bls_fp(c0)?;
    let imag = read_bls_fp(c1)?;
    Ok(bls::Fp2::new(real, imag))
}

#[inline]
fn read_bls_g1_point(point: &BlsG1Point) -> Result<bls::G1Affine, PrecompileError> {
    let px = read_bls_fp(&point.0)?;
    let py = read_bls_fp(&point.1)?;
    let point = bls::G1Affine::from_xy(px, py).ok_or(PrecompileError::Bls12381G1NotOnCurve)?;
    if point.is_in_correct_subgroup() {
        Ok(point)
    } else {
        Err(PrecompileError::Bls12381G1NotInSubgroup)
    }
}

#[inline]
fn read_bls_g2_point(point: &BlsG2Point) -> Result<bls::G2Affine, PrecompileError> {
    let x = read_bls_fp2(&point.0, &point.1)?;
    let y = read_bls_fp2(&point.2, &point.3)?;
    let point = bls::G2Affine::from_xy(x, y).ok_or(PrecompileError::Bls12381G2NotOnCurve)?;
    if point.is_in_correct_subgroup() {
        Ok(point)
    } else {
        Err(PrecompileError::Bls12381G2NotInSubgroup)
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
