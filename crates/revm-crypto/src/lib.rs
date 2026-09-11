//! OpenVM crypto providers for REVM and Alloy.
//!
//! These adapters use the standard zkVM accelerator C interface.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod alloy;
mod revm;

use alloc::boxed::Box;
use core::error::Error;
use openvm_accelerators::{zkvm_status, ZKVM_EOK};

fn status_ok(status: zkvm_status) -> bool {
    status == ZKVM_EOK
}

/// Install the OpenVM implementations globally.
pub fn install_openvm_crypto() -> Result<bool, Box<dyn Error>> {
    alloy::install()?;
    Ok(revm::install())
}
