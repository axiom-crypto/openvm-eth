//! OpenVM-accelerated implementations of the zkVM accelerator operations.
//!
//! All functions operate on fixed-size big-endian byte encodings; BLS12-381
//! G2 is `x_c0 || x_c1 || y_c0 || y_c1`, BN254 G2 uses the EIP-197
//! `x_c1 || x_c0 || y_c1 || y_c0` order.

mod blake2;
mod ecdsa;
mod hash;

pub use blake2::blake2f;
pub use ecdsa::{secp256k1_ecrecover, secp256k1_verify, secp256r1_verify};
pub use hash::{keccak256, ripemd160, sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A field element is out of range or otherwise not a field member.
    FieldElementInvalid,
    /// A point encoding does not satisfy the curve equation.
    PointNotOnCurve,
    /// A point is on the curve but not in the prime-order subgroup.
    PointNotInSubgroup,
    /// The BLAKE2f final-block flag is neither 0 nor 1.
    InvalidFinalFlag,
    /// A signature could not be parsed or key recovery failed.
    InvalidSignature,
    /// KZG commitment/proof/field-element inputs are malformed.
    KzgInvalidInput,
}
