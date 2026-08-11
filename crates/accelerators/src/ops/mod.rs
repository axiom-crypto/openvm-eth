//! OpenVM-accelerated implementations of the zkVM accelerator operations.
//!
//! Functions use ordinary Rust arrays, slices and tuples. BLS12-381 G2 is
//! `(x_c0, x_c1, y_c0, y_c1)`; BN254 G2 byte slices use the EIP-197
//! `x_c1 || x_c0 || y_c1 || y_c0` order.

mod blake2;
mod bls12_381;
mod bn254;
mod ecdsa;
mod hash;
mod kzg;
mod modexp;

pub use blake2::blake2f;
pub use bls12_381::{
    bls12_381_g1_add, bls12_381_g1_msm, bls12_381_g2_add, bls12_381_g2_msm,
    bls12_381_map_fp2_to_g2, bls12_381_map_fp_to_g1, bls12_381_pairing_check,
};
pub use bn254::{bn254_g1_add, bn254_g1_mul, bn254_pairing_check};
pub use ecdsa::{secp256k1_ecrecover, secp256k1_verify, secp256r1_verify};
pub use hash::{keccak256, ripemd160, sha256};
pub use kzg::kzg_point_eval;
pub use modexp::modexp;

/// Uncompressed BLS12-381 G1 coordinates `(x, y)`, big-endian.
pub type BlsG1 = ([u8; 48], [u8; 48]);

/// Uncompressed BLS12-381 G2 coordinates `(x_c0, x_c1, y_c0, y_c1)`, big-endian.
pub type BlsG2 = ([u8; 48], [u8; 48], [u8; 48], [u8; 48]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError<E> {
    /// The input iterator produced an error.
    Source(E),
    /// An accelerator operation rejected an input.
    Operation(Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An input does not have the length required by the operation.
    InvalidLength,
    /// A field element is out of range or otherwise not a field member.
    FieldElementInvalid,
    /// A point encoding does not satisfy the curve equation.
    PointNotOnCurve,
    /// A point is on the curve but not in the prime-order subgroup.
    PointNotInSubgroup,
    /// A BLS12-381 pairing G1 point does not satisfy the curve equation.
    BlsG1PointNotOnCurve,
    /// A BLS12-381 pairing G1 point is not in the prime-order subgroup.
    BlsG1PointNotInSubgroup,
    /// A BLS12-381 pairing G2 point does not satisfy the curve equation.
    BlsG2PointNotOnCurve,
    /// A BLS12-381 pairing G2 point is not in the prime-order subgroup.
    BlsG2PointNotInSubgroup,
    /// A signature could not be parsed or key recovery failed.
    InvalidSignature,
    /// KZG commitment/proof/field-element inputs are malformed.
    KzgInvalidInput,
}
