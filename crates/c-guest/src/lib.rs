//! Static library that runs C programs as OpenVM guests.
//!
//! It gives a C program the guest interfaces of [zkevm-standards]:
//!
//! - the entry point: OpenVM's `_start`, which calls the C `main` and then exits with code 0;
//! - the I/O interface `zkvm_io.h` ([`io`]);
//! - the accelerator interface `zkvm_accelerators.h` (`openvm-accelerators`), for the VM
//!   configuration in `openvm.toml`, which is OpenVM's standard configuration;
//! - the accelerated memory operations `memcpy`, `memmove`, `memset` and `memcmp` (`openvm-mem`).
//!
//! [zkevm-standards]: https://github.com/eth-act/zkevm-standards

#![no_std]

extern crate alloc;

// Links the accelerators, which the library only exports.
use openvm_accelerators as _;

pub mod io;

// Sets up the moduli, complex extensions and curves of `openvm.toml` for the accelerators.
openvm::init!();
