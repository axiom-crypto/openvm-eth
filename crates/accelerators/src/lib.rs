//! OpenVM implementation of the zkVM Cryptographic Accelerators C Interface.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "ffi")]
pub mod ffi;
pub mod ops;
pub mod types;
