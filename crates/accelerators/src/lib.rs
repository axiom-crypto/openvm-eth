//! OpenVM implementation of the standard zkVM accelerator C interface.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_camel_case_types)]

extern crate alloc;

mod blake2f;
mod bls12_381;
mod bn254;
mod error;
mod keccak256;
mod kzg;
mod modexp;
mod ripemd160;
mod secp256k1;
mod secp256r1;
mod sha256;
mod types;

pub use blake2f::{zkvm_blake2f, zkvm_blake2f_message, zkvm_blake2f_offset, zkvm_blake2f_state};
pub use bls12_381::{
    zkvm_bls12_381_fp, zkvm_bls12_381_fp2, zkvm_bls12_381_g1_msm_pair, zkvm_bls12_381_g1_point,
    zkvm_bls12_381_g2_msm_pair, zkvm_bls12_381_g2_point, zkvm_bls12_381_pairing_pair,
    zkvm_bls12_381_scalar, zkvm_bls12_g1_add, zkvm_bls12_g1_msm, zkvm_bls12_g2_add,
    zkvm_bls12_g2_msm, zkvm_bls12_map_fp2_to_g2, zkvm_bls12_map_fp_to_g1, zkvm_bls12_pairing,
};
pub use bn254::{
    zkvm_bn254_g1_add, zkvm_bn254_g1_mul, zkvm_bn254_g1_point, zkvm_bn254_g2_point,
    zkvm_bn254_pairing, zkvm_bn254_pairing_pair, zkvm_bn254_scalar,
};
pub use keccak256::{zkvm_keccak256, zkvm_keccak256_hash};
pub use kzg::{zkvm_kzg_commitment, zkvm_kzg_field_element, zkvm_kzg_point_eval, zkvm_kzg_proof};
pub use modexp::zkvm_modexp;
pub use ripemd160::{zkvm_ripemd160, zkvm_ripemd160_hash};
pub use secp256k1::{
    zkvm_secp256k1_ecrecover, zkvm_secp256k1_hash, zkvm_secp256k1_pubkey, zkvm_secp256k1_signature,
    zkvm_secp256k1_verify,
};
pub use secp256r1::{
    zkvm_secp256r1_hash, zkvm_secp256r1_pubkey, zkvm_secp256r1_signature, zkvm_secp256r1_verify,
};
pub use sha256::{zkvm_sha256, zkvm_sha256_hash};
pub use types::{zkvm_status, ZKVM_EFAIL, ZKVM_EOK};
