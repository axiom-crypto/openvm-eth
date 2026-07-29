//! The `extern "C"` layer: `zkvm_*` symbols matching `zkvm_accelerators.h`.
//!
//! Every function is a thin wrapper over [`crate::ops`]: it checks pointers,
//! converts them to references, calls the operation, and maps the result to
//! [`crate::types::ZkvmStatus`]. No other logic lives here.

mod blake2;
mod bls12_381;
mod bn254;
mod ecdsa;
mod hash;
mod kzg;
mod modexp;

pub use blake2::*;
pub use bls12_381::*;
pub use bn254::*;
pub use ecdsa::*;
pub use hash::*;
pub use kzg::*;
pub use modexp::*;
