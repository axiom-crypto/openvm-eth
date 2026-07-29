//! The `extern "C"` layer: `zkvm_*` symbols matching `zkvm_accelerators.h`.
//!
//! Every function is a thin wrapper over [`crate::ops`]: it checks pointers,
//! converts them to references, calls the operation, and maps the result to
//! [`crate::types::ZkvmStatus`]. No other logic lives here.

mod blake2;
mod ecdsa;
mod hash;

pub use blake2::*;
pub use ecdsa::*;
pub use hash::*;
