//! OpenVM implementation of the zkVM cryptographic accelerator interface.
//!
//! Points and scalars use fixed-size big-endian encodings. BLS12-381 G2 uses
//! `x_c0 || x_c1 || y_c0 || y_c1`; BN254 G2 uses the EIP-197
//! `x_c1 || x_c0 || y_c1 || y_c0` order.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "ffi")]
mod ffi;
mod ops;
#[cfg(feature = "ffi")]
mod types;

#[cfg(feature = "ffi")]
pub use ffi::*;
pub use ops::*;
#[cfg(feature = "ffi")]
pub use types::*;
