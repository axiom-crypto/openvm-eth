//! Arithmetic-only static-verifier tracegen benchmark.
//!
//! Loads the `static_verifier_pk.bin` cache produced by the sibling
//! `bin/static-verifier-tracegen` binary and runs `arithonly_constrained_verify`
//! `TRACEGEN_ITERS` times, then also runs the native root STARK verify for a
//! reference wall-clock point.

mod chip;
mod hash;
mod proof_wire;
mod transcript;
mod verify;
mod wire;

use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
};

use eyre::{eyre, Result};
use openvm_continuations::RootSC;
use openvm_sdk::fs::read_object_from_file;
use openvm_stark_sdk::{
    bench::run_with_metric_collection,
    openvm_stark_backend::{codec::Decode, proof::Proof, StarkEngine},
};
use openvm_static_verifier::StaticVerifierProvingKey;
use tracing::info_span;

use chip::{BabyBearChip, BabyBearExt4Chip, RangeChip};
use verify::full_pipeline::{constrained_verify, load_proof_wire};

fn cache_dir() -> PathBuf {
    match std::env::var("STATIC_VERIFIER_CACHE_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => Path::new("cache").to_path_buf(),
    }
}

fn main() -> Result<()> {
    let cache = cache_dir();
    let pk_path = cache.join("static_verifier_pk.bin");
    let root_proof_path = cache.join("root_proof.bitcode");

    if !pk_path.exists() {
        return Err(eyre!(
            "static_verifier_pk cache not found at {:?}. \
             Generate it by running the sibling binary first: \
             `cargo run -p static-verifier-tracegen --release`.",
            pk_path
        ));
    }
    if !root_proof_path.exists() {
        return Err(eyre!("root_proof cache not found at {:?}.", root_proof_path));
    }

    eprintln!("reusing static verifier pk from {:?}", pk_path);
    let mut reader = BufReader::new(File::open(&pk_path)?);
    let static_verifier_pk = StaticVerifierProvingKey::decode(&mut reader)?;
    let root_proof: Proof<RootSC> = read_object_from_file(&root_proof_path)?;

    let root_vk = &static_verifier_pk.circuit.root_vk;

    #[cfg(feature = "cuda")]
    let root_engine =
        openvm_cuda_backend::BabyBearBn254Poseidon2GpuEngine::new(root_vk.inner.params.clone());
    #[cfg(not(feature = "cuda"))]
    let root_engine =
        openvm_stark_sdk::config::baby_bear_bn254_poseidon2::BabyBearBn254Poseidon2CpuEngine::new(
            root_vk.inner.params.clone(),
        );

    let lookup_bits = static_verifier_pk.pinning.metadata.config_params.lookup_bits.unwrap_or(15);
    let tracegen_iters: usize = std::env::var("TRACEGEN_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    eprintln!(
        "running arithonly constrained_verify {tracegen_iters}x (lookup_bits={lookup_bits})"
    );

    let range = Arc::new(RangeChip::new(lookup_bits));
    let base = BabyBearChip::new(range);
    let ext_chip = BabyBearExt4Chip::new(base);

    run_with_metric_collection("OUTPUT_PATH", || -> Result<()> {
        info_span!("static_verifier_tracegen_arithonly", iters = tracegen_iters).in_scope(|| {
            for _ in 0..tracegen_iters {
                let proof_wire = load_proof_wire(
                    &ext_chip,
                    &root_proof,
                    &static_verifier_pk.circuit.log_heights_per_air,
                );
                constrained_verify(
                    &ext_chip,
                    &static_verifier_pk.circuit.root_vk,
                    &proof_wire,
                    &static_verifier_pk.circuit.trace_id_to_air_id,
                    &static_verifier_pk.circuit.log_heights_per_air,
                    &static_verifier_pk.circuit.stacked_layouts,
                );
            }
        });

        info_span!("root_verifier_native").in_scope(|| -> Result<()> {
            root_engine.verify(root_vk, &root_proof)?;
            Ok(())
        })?;

        Ok(())
    })?;

    Ok(())
}
