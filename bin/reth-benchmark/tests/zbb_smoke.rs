//! Smoke test for the execute-only Zbb extension: transpiles a Zbb-compiled guest ELF and
//! constructs the interpreter instance, which pre-computes a handler for every instruction
//! in the program. This validates the whole decode/executor-registration path without
//! needing an RPC witness.
//!
//! Skipped unless `ZBB_GUEST_ELF` points at a guest ELF built with
//! `RUSTFLAGS="-C target-feature=+zbb" cargo openvm build`.

use openvm_circuit::arch::VmExecutor;
use openvm_reth_benchmark::{build_reth_exe, reth_vm_config};

#[test]
fn zbb_guest_elf_transpiles_and_precomputes() {
    let Ok(elf_path) = std::env::var("ZBB_GUEST_ELF") else {
        eprintln!("ZBB_GUEST_ELF not set; skipping");
        return;
    };
    // SAFETY: test runs single-threaded at this point.
    unsafe { std::env::set_var("OPENVM_ZBB", "1") };

    let elf_bytes = std::fs::read(&elf_path).unwrap();
    let config = reth_vm_config();
    assert!(config.zbb.is_some(), "OPENVM_ZBB=1 must enable the zbb extension");
    let exe = build_reth_exe(&config, &elf_bytes).unwrap();
    let executor = VmExecutor::new(config).unwrap();
    // Interpreter instance construction pre-computes a handler for every instruction,
    // so this fails if any Zbb instruction is missing decode or executor support.
    let _instance = executor.instance(&exe).unwrap();
}
