//! REVM adapter for the standard zkVM accelerator C interface.

use alloc::vec::Vec;
use core::mem::MaybeUninit;

use crate::status_ok;
use openvm_accelerators::{
    zkvm_blake2f, zkvm_blake2f_message, zkvm_blake2f_offset, zkvm_blake2f_state, zkvm_bls12_381_fp,
    zkvm_bls12_381_fp2, zkvm_bls12_381_g1_msm_pair, zkvm_bls12_381_g1_point,
    zkvm_bls12_381_g2_msm_pair, zkvm_bls12_381_g2_point, zkvm_bls12_381_pairing_pair,
    zkvm_bls12_381_scalar, zkvm_bls12_g1_add, zkvm_bls12_g1_msm, zkvm_bls12_g2_add,
    zkvm_bls12_g2_msm, zkvm_bls12_map_fp2_to_g2, zkvm_bls12_map_fp_to_g1, zkvm_bls12_pairing,
    zkvm_bn254_g1_add, zkvm_bn254_g1_mul, zkvm_bn254_g1_point, zkvm_bn254_g2_point,
    zkvm_bn254_pairing, zkvm_bn254_pairing_pair, zkvm_bn254_scalar, zkvm_keccak256,
    zkvm_keccak256_hash, zkvm_kzg_commitment, zkvm_kzg_field_element, zkvm_kzg_point_eval,
    zkvm_kzg_proof, zkvm_modexp, zkvm_ripemd160, zkvm_ripemd160_hash, zkvm_secp256k1_ecrecover,
    zkvm_secp256k1_hash, zkvm_secp256k1_pubkey, zkvm_secp256k1_signature, zkvm_secp256r1_hash,
    zkvm_secp256r1_pubkey, zkvm_secp256r1_signature, zkvm_secp256r1_verify, zkvm_sha256,
    zkvm_sha256_hash,
};
use revm::precompile::{
    bls12_381::{
        G1Point as BlsG1Point, G1PointScalar as BlsG1PointScalar, G2Point as BlsG2Point,
        G2PointScalar as BlsG2PointScalar,
    },
    bls12_381_const::{FP_LENGTH as BLS_FP_LEN, G1_LENGTH as BLS_G1_LEN, G2_LENGTH as BLS_G2_LEN},
    Crypto, PrecompileHalt,
};

fn bls_g1((x, y): BlsG1Point) -> zkvm_bls12_381_g1_point {
    let mut data = [0; BLS_G1_LEN];
    data[..BLS_FP_LEN].copy_from_slice(&x);
    data[BLS_FP_LEN..].copy_from_slice(&y);
    zkvm_bls12_381_g1_point { data }
}

fn bls_g2((x0, x1, y0, y1): BlsG2Point) -> zkvm_bls12_381_g2_point {
    let mut data = [0; BLS_G2_LEN];
    for (output, coordinate) in data.chunks_exact_mut(BLS_FP_LEN).zip([x0, x1, y0, y1]) {
        output.copy_from_slice(&coordinate);
    }
    zkvm_bls12_381_g2_point { data }
}

fn write_words<const N: usize>(words: &[u64; N], bytes: &mut [u8]) {
    for (output, word) in bytes.chunks_exact_mut(8).zip(words) {
        output.copy_from_slice(&word.to_le_bytes());
    }
}

#[derive(Debug, Default)]
struct OpenVmCrypto;

impl Crypto for OpenVmCrypto {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        let mut output = zkvm_sha256_hash { data: [0; 32] };
        let status = unsafe { zkvm_sha256(input.as_ptr(), input.len(), &mut output) };
        assert!(status_ok(status), "zkVM accelerator call failed");
        output.data
    }

    fn ripemd160(&self, input: &[u8]) -> [u8; 32] {
        let mut output = zkvm_ripemd160_hash { data: [0; 32] };
        let status = unsafe { zkvm_ripemd160(input.as_ptr(), input.len(), &mut output) };
        assert!(status_ok(status), "zkVM accelerator call failed");
        output.data
    }

    fn bn254_g1_add(&self, p1: &[u8], p2: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        let p1 = zkvm_bn254_g1_point {
            data: p1.try_into().map_err(|_| PrecompileHalt::Bn254PairLength)?,
        };
        let p2 = zkvm_bn254_g1_point {
            data: p2.try_into().map_err(|_| PrecompileHalt::Bn254PairLength)?,
        };
        let mut output = zkvm_bn254_g1_point { data: [0; 64] };
        let status = unsafe { zkvm_bn254_g1_add(&p1, &p2, &mut output) };
        if !status_ok(status) {
            return Err(PrecompileHalt::Bn254AffineGFailedToCreate);
        }
        Ok(output.data)
    }

    fn bn254_g1_mul(&self, point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        let point = zkvm_bn254_g1_point {
            data: point.try_into().map_err(|_| PrecompileHalt::Bn254PairLength)?,
        };
        let scalar = zkvm_bn254_scalar {
            data: scalar.try_into().map_err(|_| PrecompileHalt::Bn254PairLength)?,
        };
        let mut output = zkvm_bn254_g1_point { data: [0; 64] };
        let status = unsafe { zkvm_bn254_g1_mul(&point, &scalar, &mut output) };
        if !status_ok(status) {
            return Err(PrecompileHalt::Bn254AffineGFailedToCreate);
        }
        Ok(output.data)
    }

    fn bn254_pairing_check(&self, pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
        let pairs: Result<Vec<_>, _> = pairs
            .iter()
            .map(|&(g1, g2)| {
                Ok(zkvm_bn254_pairing_pair {
                    g1: zkvm_bn254_g1_point {
                        data: g1.try_into().map_err(|_| PrecompileHalt::Bn254PairLength)?,
                    },
                    g2: zkvm_bn254_g2_point {
                        data: g2.try_into().map_err(|_| PrecompileHalt::Bn254PairLength)?,
                    },
                })
            })
            .collect();
        let pairs = pairs?;
        let mut verified = false;
        let status = unsafe { zkvm_bn254_pairing(pairs.as_ptr(), pairs.len(), &mut verified) };
        if !status_ok(status) {
            return Err(PrecompileHalt::Bn254AffineGFailedToCreate);
        }
        Ok(verified)
    }

    fn secp256k1_ecrecover(
        &self,
        sig: &[u8; 64],
        recid: u8,
        msg: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        let msg = zkvm_secp256k1_hash { data: *msg };
        let sig = zkvm_secp256k1_signature { data: *sig };
        let mut pubkey = zkvm_secp256k1_pubkey { data: [0; 64] };
        let status = unsafe { zkvm_secp256k1_ecrecover(&msg, &sig, recid, &mut pubkey) };
        if !status_ok(status) {
            return Err(PrecompileHalt::Secp256k1RecoverFailed);
        }
        let mut hash = zkvm_keccak256_hash { data: [0; 32] };
        let status = unsafe { zkvm_keccak256(pubkey.data.as_ptr(), pubkey.data.len(), &mut hash) };
        assert!(status_ok(status), "zkVM accelerator call failed");
        hash.data[..12].fill(0);
        Ok(hash.data)
    }

    fn modexp(&self, base: &[u8], exp: &[u8], modulus: &[u8]) -> Result<Vec<u8>, PrecompileHalt> {
        let mut output = alloc::vec![0; modulus.len()];
        let status = unsafe {
            zkvm_modexp(
                base.as_ptr(),
                base.len(),
                exp.as_ptr(),
                exp.len(),
                modulus.as_ptr(),
                modulus.len(),
                output.as_mut_ptr(),
            )
        };
        assert!(status_ok(status), "zkVM accelerator call failed");
        Ok(output)
    }

    fn blake2_compress(&self, rounds: u32, h: &mut [u64; 8], m: &[u64; 16], t: &[u64; 2], f: bool) {
        let mut state = zkvm_blake2f_state { data: [0; 64] };
        let mut message = zkvm_blake2f_message { data: [0; 128] };
        let mut offset = zkvm_blake2f_offset { data: [0; 16] };
        write_words(h, &mut state.data);
        write_words(m, &mut message.data);
        write_words(t, &mut offset.data);
        let status = unsafe { zkvm_blake2f(rounds, &mut state, &message, &offset, u8::from(f)) };
        assert!(status_ok(status), "zkVM accelerator call failed");
        for (word, bytes) in h.iter_mut().zip(state.data.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*bytes);
        }
    }

    fn secp256r1_verify_signature(&self, msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> bool {
        let msg = zkvm_secp256r1_hash { data: *msg };
        let sig = zkvm_secp256r1_signature { data: *sig };
        let pubkey = zkvm_secp256r1_pubkey { data: *pk };
        let mut verified = false;
        let status = unsafe { zkvm_secp256r1_verify(&msg, &sig, &pubkey, &mut verified) };
        status_ok(status) && verified
    }

    fn verify_kzg_proof(
        &self,
        z: &[u8; 32],
        y: &[u8; 32],
        commitment: &[u8; 48],
        proof: &[u8; 48],
    ) -> Result<(), PrecompileHalt> {
        let commitment = zkvm_kzg_commitment { data: *commitment };
        let z = zkvm_kzg_field_element { data: *z };
        let y = zkvm_kzg_field_element { data: *y };
        let proof = zkvm_kzg_proof { data: *proof };
        let mut verified = false;
        let status = unsafe { zkvm_kzg_point_eval(&commitment, &z, &y, &proof, &mut verified) };
        if status_ok(status) && verified {
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
        let (a, b) = (bls_g1(a), bls_g1(b));
        let mut output = MaybeUninit::<zkvm_bls12_381_g1_point>::uninit();
        let status = unsafe { zkvm_bls12_g1_add(&a, &b, output.as_mut_ptr()) };
        if !status_ok(status) {
            return Err(PrecompileHalt::Bls12381G1NotOnCurve);
        }
        // SAFETY: the C interface initializes the output when it returns success.
        Ok(unsafe { output.assume_init() }.data)
    }

    fn bls12_381_g1_msm(
        &self,
        pairs: &mut dyn Iterator<Item = Result<BlsG1PointScalar, PrecompileHalt>>,
    ) -> Result<[u8; BLS_G1_LEN], PrecompileHalt> {
        let mut wire_pairs = Vec::with_capacity(pairs.size_hint().0);
        for pair in pairs {
            let (point, scalar) = pair?;
            wire_pairs.push(zkvm_bls12_381_g1_msm_pair {
                point: bls_g1(point),
                scalar: zkvm_bls12_381_scalar { data: scalar },
            });
        }
        let mut output = MaybeUninit::<zkvm_bls12_381_g1_point>::uninit();
        let status = unsafe {
            zkvm_bls12_g1_msm(wire_pairs.as_ptr(), wire_pairs.len(), output.as_mut_ptr())
        };
        if !status_ok(status) {
            return Err(PrecompileHalt::Bls12381G1NotInSubgroup);
        }
        // SAFETY: the C interface initializes the output when it returns success.
        Ok(unsafe { output.assume_init() }.data)
    }

    fn bls12_381_g2_add(
        &self,
        a: BlsG2Point,
        b: BlsG2Point,
    ) -> Result<[u8; BLS_G2_LEN], PrecompileHalt> {
        let (a, b) = (bls_g2(a), bls_g2(b));
        let mut output = MaybeUninit::<zkvm_bls12_381_g2_point>::uninit();
        let status = unsafe { zkvm_bls12_g2_add(&a, &b, output.as_mut_ptr()) };
        if !status_ok(status) {
            return Err(PrecompileHalt::Bls12381G2NotOnCurve);
        }
        // SAFETY: the C interface initializes the output when it returns success.
        Ok(unsafe { output.assume_init() }.data)
    }

    fn bls12_381_g2_msm(
        &self,
        pairs: &mut dyn Iterator<Item = Result<BlsG2PointScalar, PrecompileHalt>>,
    ) -> Result<[u8; BLS_G2_LEN], PrecompileHalt> {
        let mut wire_pairs = Vec::with_capacity(pairs.size_hint().0);
        for pair in pairs {
            let (point, scalar) = pair?;
            wire_pairs.push(zkvm_bls12_381_g2_msm_pair {
                point: bls_g2(point),
                scalar: zkvm_bls12_381_scalar { data: scalar },
            });
        }
        let mut output = MaybeUninit::<zkvm_bls12_381_g2_point>::uninit();
        let status = unsafe {
            zkvm_bls12_g2_msm(wire_pairs.as_ptr(), wire_pairs.len(), output.as_mut_ptr())
        };
        if !status_ok(status) {
            return Err(PrecompileHalt::Bls12381G2NotInSubgroup);
        }
        // SAFETY: the C interface initializes the output when it returns success.
        Ok(unsafe { output.assume_init() }.data)
    }

    fn bls12_381_pairing_check(
        &self,
        pairs: &[(BlsG1Point, BlsG2Point)],
    ) -> Result<bool, PrecompileHalt> {
        let pairs: Vec<_> = pairs
            .iter()
            .copied()
            .map(|(p1, p2)| zkvm_bls12_381_pairing_pair { g1: bls_g1(p1), g2: bls_g2(p2) })
            .collect();
        let mut verified = MaybeUninit::<bool>::uninit();
        let status =
            unsafe { zkvm_bls12_pairing(pairs.as_ptr(), pairs.len(), verified.as_mut_ptr()) };
        if !status_ok(status) {
            return Err(PrecompileHalt::Bls12381G1NotInSubgroup);
        }
        // SAFETY: the C interface initializes the output when it returns success.
        Ok(unsafe { verified.assume_init() })
    }

    fn bls12_381_fp_to_g1(
        &self,
        fp: &[u8; BLS_FP_LEN],
    ) -> Result<[u8; BLS_G1_LEN], PrecompileHalt> {
        let fp = zkvm_bls12_381_fp { data: *fp };
        let mut output = MaybeUninit::<zkvm_bls12_381_g1_point>::uninit();
        let status = unsafe { zkvm_bls12_map_fp_to_g1(&fp, output.as_mut_ptr()) };
        if !status_ok(status) {
            return Err(PrecompileHalt::NonCanonicalFp);
        }
        // SAFETY: the C interface initializes the output when it returns success.
        Ok(unsafe { output.assume_init() }.data)
    }

    fn bls12_381_fp2_to_g2(
        &self,
        fp2: ([u8; BLS_FP_LEN], [u8; BLS_FP_LEN]),
    ) -> Result<[u8; BLS_G2_LEN], PrecompileHalt> {
        let mut data = [0; BLS_FP_LEN * 2];
        data[..BLS_FP_LEN].copy_from_slice(&fp2.0);
        data[BLS_FP_LEN..].copy_from_slice(&fp2.1);
        let fp2 = zkvm_bls12_381_fp2 { data };
        let mut output = MaybeUninit::<zkvm_bls12_381_g2_point>::uninit();
        let status = unsafe { zkvm_bls12_map_fp2_to_g2(&fp2, output.as_mut_ptr()) };
        if !status_ok(status) {
            return Err(PrecompileHalt::NonCanonicalFp);
        }
        // SAFETY: the C interface initializes the output when it returns success.
        Ok(unsafe { output.assume_init() }.data)
    }
}

pub(super) fn install() -> bool {
    revm::install_crypto(OpenVmCrypto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::precompile::DefaultCrypto;

    #[test]
    fn portable_operations_match_revm() {
        let input = b"OpenVM accelerator C interface";
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
    fn p256_accepts_valid_and_rejects_invalid_signatures() {
        let input = alloy_primitives::hex::decode("4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e").unwrap();
        let msg = input[..32].try_into().unwrap();
        let signature = input[32..96].try_into().unwrap();
        let public_key = input[96..].try_into().unwrap();
        assert!(OpenVmCrypto.secp256r1_verify_signature(msg, signature, public_key));
        assert!(!OpenVmCrypto.secp256r1_verify_signature(msg, &[0; 64], public_key));
    }

    #[test]
    fn c_status_failures_are_mapped_at_the_client_boundary() {
        assert_eq!(
            OpenVmCrypto.secp256k1_ecrecover(&[0; 64], 0, &[0; 32]),
            Err(PrecompileHalt::Secp256k1RecoverFailed)
        );
        assert_eq!(
            OpenVmCrypto.bls12_381_fp_to_g1(&[0xff; BLS_FP_LEN]),
            Err(PrecompileHalt::NonCanonicalFp)
        );
        assert_eq!(
            OpenVmCrypto.bn254_g1_add(&[0; 63], &[0; 64]),
            Err(PrecompileHalt::Bn254PairLength)
        );
    }
}
