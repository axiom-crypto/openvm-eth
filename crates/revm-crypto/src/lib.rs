//! OpenVM crypto providers for REVM and Alloy.
//!
//! Cryptographic operations live in `openvm-accelerators`; this crate only
//! adapts their byte-oriented API to REVM and Alloy's provider traits.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{boxed::Box, sync::Arc, vec::Vec};

use alloy_consensus::crypto::{
    backend::{install_default_provider, CryptoProvider},
    RecoveryError,
};
use alloy_primitives::Address;
use openvm_accelerators::{
    blake2f, bls12_381_g1_add, bls12_381_g1_msm, bls12_381_g2_add, bls12_381_g2_msm,
    bls12_381_map_fp2_to_g2, bls12_381_map_fp_to_g1, bls12_381_pairing_check, bn254_g1_add,
    bn254_g1_mul, bn254_pairing_check, keccak256, kzg_point_eval, modexp, ripemd160,
    secp256k1_ecrecover, secp256k1_verify, secp256r1_verify, sha256, Error, StreamError,
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
        },
        Crypto, PrecompileHalt,
    },
};

#[derive(Debug, Default)]
struct OpenVmK256Provider;

impl CryptoProvider for OpenVmK256Provider {
    fn recover_signer_unchecked(
        &self,
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        let pubkey = secp256k1_ecrecover(msg, sig[..64].try_into().unwrap(), sig[64])
            .map_err(|_| RecoveryError::new())?;
        Ok(address_from_pubkey(&pubkey))
    }

    fn verify_and_compute_signer_unchecked(
        &self,
        pubkey: &[u8; 65],
        sig: &[u8; 64],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        if pubkey[0] != 0x04 {
            return Err(RecoveryError::new());
        }

        let pubkey: &[u8; 64] = pubkey[1..].try_into().unwrap();
        if !secp256k1_verify(msg, sig, pubkey) {
            return Err(RecoveryError::new());
        }

        Ok(address_from_pubkey(pubkey))
    }
}

fn address_from_pubkey(pubkey: &[u8; 64]) -> Address {
    Address::from_slice(&keccak256(pubkey)[12..])
}

#[derive(Debug, Default)]
struct OpenVmCrypto;

impl Crypto for OpenVmCrypto {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        sha256(input)
    }

    fn ripemd160(&self, input: &[u8]) -> [u8; 32] {
        ripemd160(input)
    }

    fn bn254_g1_add(&self, p1: &[u8], p2: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        bn254_g1_add(p1, p2).map_err(map_bn_error)
    }

    fn bn254_g1_mul(&self, point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        bn254_g1_mul(point, scalar).map_err(map_bn_error)
    }

    fn bn254_pairing_check(&self, pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
        bn254_pairing_check(pairs.iter().copied()).map_err(map_bn_error)
    }

    fn secp256k1_ecrecover(
        &self,
        sig: &[u8; 64],
        recid: u8,
        msg: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        let pubkey = secp256k1_ecrecover(msg, sig, recid)
            .map_err(|_| PrecompileHalt::Secp256k1RecoverFailed)?;

        let mut hash = keccak256(&pubkey);
        hash[..12].fill(0);
        Ok(hash)
    }

    fn modexp(&self, base: &[u8], exp: &[u8], modulus: &[u8]) -> Result<Vec<u8>, PrecompileHalt> {
        Ok(modexp(base, exp, modulus))
    }

    fn blake2_compress(&self, rounds: u32, h: &mut [u64; 8], m: &[u64; 16], t: &[u64; 2], f: bool) {
        blake2f(rounds, h, m, t, f);
    }

    fn secp256r1_verify_signature(&self, msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> bool {
        secp256r1_verify(msg, sig, pk)
    }

    fn verify_kzg_proof(
        &self,
        z: &[u8; 32],
        y: &[u8; 32],
        commitment: &[u8; 48],
        proof: &[u8; 48],
    ) -> Result<(), PrecompileHalt> {
        let verified = kzg_point_eval(commitment, z, y, proof)
            .map_err(|_| PrecompileHalt::BlobVerifyKzgProofFailed)?;
        if verified {
            Ok(())
        } else {
            Err(PrecompileHalt::BlobVerifyKzgProofFailed)
        }
    }

    fn bls12_381_g1_add(
        &self,
        a: BlsG1Point,
        b: BlsG1Point,
    ) -> Result<[u8; BLS_G1_LEN], PrecompileHalt> {
        bls12_381_g1_add(a, b).map_err(map_bls_g1_error)
    }

    fn bls12_381_g1_msm(
        &self,
        pairs: &mut dyn Iterator<Item = Result<BlsG1PointScalar, PrecompileHalt>>,
    ) -> Result<[u8; BLS_G1_LEN], PrecompileHalt> {
        bls12_381_g1_msm(pairs).map_err(|error| map_stream_error(error, map_bls_g1_error))
    }

    fn bls12_381_g2_add(
        &self,
        a: BlsG2Point,
        b: BlsG2Point,
    ) -> Result<[u8; BLS_G2_LEN], PrecompileHalt> {
        bls12_381_g2_add(a, b).map_err(map_bls_g2_error)
    }

    fn bls12_381_g2_msm(
        &self,
        pairs: &mut dyn Iterator<Item = Result<BlsG2PointScalar, PrecompileHalt>>,
    ) -> Result<[u8; BLS_G2_LEN], PrecompileHalt> {
        bls12_381_g2_msm(pairs).map_err(|error| map_stream_error(error, map_bls_g2_error))
    }

    fn bls12_381_pairing_check(
        &self,
        pairs: &[(BlsG1Point, BlsG2Point)],
    ) -> Result<bool, PrecompileHalt> {
        bls12_381_pairing_check(pairs.iter().copied()).map_err(map_bls_pairing_error)
    }

    fn bls12_381_fp_to_g1(
        &self,
        fp: &[u8; BLS_FP_LEN],
    ) -> Result<[u8; BLS_G1_LEN], PrecompileHalt> {
        bls12_381_map_fp_to_g1(fp).map_err(map_bls_field_error)
    }

    fn bls12_381_fp2_to_g2(
        &self,
        fp2: ([u8; BLS_FP_LEN], [u8; BLS_FP_LEN]),
    ) -> Result<[u8; BLS_G2_LEN], PrecompileHalt> {
        bls12_381_map_fp2_to_g2(fp2).map_err(map_bls_field_error)
    }
}

fn map_stream_error(
    error: StreamError<PrecompileHalt>,
    map_operation: fn(Error) -> PrecompileHalt,
) -> PrecompileHalt {
    match error {
        StreamError::Source(error) => error,
        StreamError::Operation(error) => map_operation(error),
    }
}

fn map_bn_error(error: Error) -> PrecompileHalt {
    match error {
        Error::InvalidLength => PrecompileHalt::Bn254PairLength,
        Error::FieldElementInvalid => PrecompileHalt::Bn254FieldPointNotAMember,
        Error::PointNotOnCurve | Error::PointNotInSubgroup => {
            PrecompileHalt::Bn254AffineGFailedToCreate
        }
        _ => PrecompileHalt::other("unexpected BN254 accelerator error"),
    }
}

fn map_bls_g1_error(error: Error) -> PrecompileHalt {
    match error {
        Error::PointNotInSubgroup => PrecompileHalt::Bls12381G1NotInSubgroup,
        Error::PointNotOnCurve => PrecompileHalt::Bls12381G1NotOnCurve,
        Error::FieldElementInvalid => PrecompileHalt::NonCanonicalFp,
        _ => PrecompileHalt::other("unexpected BLS12-381 G1 accelerator error"),
    }
}

fn map_bls_g2_error(error: Error) -> PrecompileHalt {
    match error {
        Error::PointNotInSubgroup => PrecompileHalt::Bls12381G2NotInSubgroup,
        Error::PointNotOnCurve => PrecompileHalt::Bls12381G2NotOnCurve,
        Error::FieldElementInvalid => PrecompileHalt::NonCanonicalFp,
        _ => PrecompileHalt::other("unexpected BLS12-381 G2 accelerator error"),
    }
}

fn map_bls_pairing_error(error: Error) -> PrecompileHalt {
    match error {
        Error::FieldElementInvalid => PrecompileHalt::NonCanonicalFp,
        Error::BlsG1PointNotOnCurve => PrecompileHalt::Bls12381G1NotOnCurve,
        Error::BlsG1PointNotInSubgroup => PrecompileHalt::Bls12381G1NotInSubgroup,
        Error::BlsG2PointNotOnCurve => PrecompileHalt::Bls12381G2NotOnCurve,
        Error::BlsG2PointNotInSubgroup => PrecompileHalt::Bls12381G2NotInSubgroup,
        _ => PrecompileHalt::other("unexpected BLS12-381 pairing accelerator error"),
    }
}

fn map_bls_field_error(error: Error) -> PrecompileHalt {
    match error {
        Error::FieldElementInvalid => PrecompileHalt::NonCanonicalFp,
        _ => PrecompileHalt::other("unexpected BLS12-381 map accelerator error"),
    }
}

/// Install the OpenVM implementations globally.
pub fn install_openvm_crypto() -> Result<bool, Box<dyn core::error::Error>> {
    install_default_provider(Arc::new(OpenVmK256Provider))?;
    Ok(install_crypto(OpenVmCrypto))
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::precompile::DefaultCrypto;

    fn p256_verify_input(input_hex: &str) -> bool {
        let input = alloy_primitives::hex::decode(input_hex).unwrap();
        assert_eq!(input.len(), 160);
        OpenVmCrypto.secp256r1_verify_signature(
            input[..32].try_into().unwrap(),
            input[32..96].try_into().unwrap(),
            input[96..160].try_into().unwrap(),
        )
    }

    // Vectors from daimo-eth/p256-verifier, also used by revm-precompile.
    #[test]
    fn secp256r1_verify_signature() {
        assert!(p256_verify_input("4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e"));
        assert!(!p256_verify_input("3cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e"));
    }

    #[test]
    fn modexp_dispatch_and_padding() {
        let modulus = alloy_primitives::hex::decode(
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        )
        .unwrap();
        let accelerated = OpenVmCrypto.modexp(&[3], &[5], &modulus).unwrap();
        assert_eq!(accelerated.len(), 32);
        assert!(accelerated[..31].iter().all(|byte| *byte == 0));
        assert_eq!(accelerated[31], 243);

        assert_eq!(OpenVmCrypto.modexp(&[3], &[4], &[7]).unwrap(), [4]);
    }

    #[test]
    fn ripemd160_adapter_uses_evm_padding() {
        assert_eq!(
            OpenVmCrypto.ripemd160(b"abc"),
            alloy_primitives::hex!(
                "0000000000000000000000008eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
            )
        );
    }

    #[test]
    fn adapters_match_revm_for_portable_primitives() {
        let input = b"OpenVM accelerator provider";
        assert_eq!(OpenVmCrypto.sha256(input), DefaultCrypto.sha256(input));
        assert_eq!(OpenVmCrypto.ripemd160(input), DefaultCrypto.ripemd160(input));
        assert_eq!(
            OpenVmCrypto.modexp(&[0x12; 40], &[0x34; 3], &[0xef; 24]),
            DefaultCrypto.modexp(&[0x12; 40], &[0x34; 3], &[0xef; 24])
        );

        let mut actual = [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ];
        let mut expected = actual;
        let message = [0x0123_4567_89ab_cdef; 16];
        let offset = [0x1020_3040_5060_7080, 0x90a0_b0c0_d0e0_f000];
        OpenVmCrypto.blake2_compress(12, &mut actual, &message, &offset, true);
        DefaultCrypto.blake2_compress(12, &mut expected, &message, &offset, true);
        assert_eq!(actual, expected);
    }

    #[test]
    fn adapters_preserve_revm_error_variants() {
        let invalid_bn_point = [0xff; 64];
        let actual = OpenVmCrypto.bn254_g1_add(&invalid_bn_point, &[0; 64]);
        assert_eq!(actual, Err(PrecompileHalt::Bn254FieldPointNotAMember));
        assert_eq!(actual, DefaultCrypto.bn254_g1_add(&invalid_bn_point, &[0; 64]));

        let noncanonical_fp = [0xff; BLS_FP_LEN];
        let actual = OpenVmCrypto.bls12_381_fp_to_g1(&noncanonical_fp);
        assert_eq!(actual, Err(PrecompileHalt::NonCanonicalFp));
        assert_eq!(actual, DefaultCrypto.bls12_381_fp_to_g1(&noncanonical_fp));

        assert_eq!(
            OpenVmCrypto.secp256k1_ecrecover(&[0; 64], 0, &[0; 32]),
            Err(PrecompileHalt::Secp256k1RecoverFailed)
        );
    }

    #[test]
    fn streaming_adapters_report_the_first_invalid_pair() {
        let invalid_bn_g1 = [0xff; 64];
        let identity_bn_g2 = [0; 128];
        let identity_bn_g1 = [0; 64];
        let short_bn_g2 = [0; 127];
        let bn_pairs =
            [(&invalid_bn_g1[..], &identity_bn_g2[..]), (&identity_bn_g1[..], &short_bn_g2[..])];
        assert_eq!(
            OpenVmCrypto.bn254_pairing_check(&bn_pairs),
            Err(PrecompileHalt::Bn254FieldPointNotAMember)
        );

        let invalid_g1 = ([0xff; BLS_FP_LEN], [0xff; BLS_FP_LEN]);
        let mut g1_pairs =
            [Ok((invalid_g1, [0; 32])), Err(PrecompileHalt::Bls12381ScalarInputLength)].into_iter();
        assert_eq!(
            OpenVmCrypto.bls12_381_g1_msm(&mut g1_pairs),
            Err(PrecompileHalt::NonCanonicalFp)
        );
    }
}
