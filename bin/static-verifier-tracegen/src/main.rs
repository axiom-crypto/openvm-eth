use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::Path,
};

use eyre::Result;
use halo2_base::gates::circuit::builder::WitnessCircuitBuilder;
use openvm::platform::memory::GUEST_MAX_MEM;
use openvm_continuations::RootSC;
use openvm_sdk::{
    config::{AggregationSystemParams, AppConfig, DEFAULT_APP_L_SKIP},
    fs::{read_object_from_file, write_object_to_file},
    keygen::static_verifier::keygen_static_verifier,
    types::ExecutableFormat,
    Sdk, StdIn,
};
use openvm_stark_sdk::{
    bench::run_with_metric_collection,
    config::app_params_with_100_bits_security,
    openvm_stark_backend::{
        codec::{Decode, Encode},
        proof::Proof,
        StarkEngine,
    },
};
use openvm_static_verifier::StaticVerifierProvingKey;
use openvm_transpiler::elf::Elf;
use tracing::info_span;

const FIB_ELF: &[u8] =
    include_bytes!("../../../halo2-gpu/benchmarks/guest/fibonacci/elf/fibonacci.elf");

fn main() -> Result<()> {
    let n: u64 = 1000;
    let mut stdin = StdIn::default();
    stdin.write(&n);

    let elf = Elf::decode(FIB_ELF, GUEST_MAX_MEM as u32)?;

    let cache_dir = Path::new("cache");
    std::fs::create_dir_all(cache_dir)?;
    let root_proof_path = cache_dir.join("root_proof.bitcode");
    let app_pk_path = cache_dir.join("app_pk.bitcode");
    let agg_pk_path = cache_dir.join("agg_pk.bitcode");
    let root_pk_path = cache_dir.join("root_pk.bitcode");
    let static_verifier_pk_path = cache_dir.join("static_verifier_pk.bin");

    let (static_verifier_pk, root_proof) = if static_verifier_pk_path.exists() {
        eprintln!("reusing static verifier pk from {:?}", static_verifier_pk_path);
        let mut reader = BufReader::new(File::open(&static_verifier_pk_path)?);
        (StaticVerifierProvingKey::decode(&mut reader)?, read_object_from_file(&root_proof_path)?)
    } else {
        let n_stack = 19;
        let mut builder = Sdk::builder();

        if app_pk_path.exists() {
            eprintln!("reusing app pk");
            builder = builder.app_pk(read_object_from_file(&app_pk_path)?);
        } else {
            let app_params = app_params_with_100_bits_security(DEFAULT_APP_L_SKIP + n_stack);
            builder = builder.app_config(AppConfig::riscv32(app_params));
        }

        if agg_pk_path.exists() {
            eprintln!("reusing agg pk");
            builder = builder.agg_pk(read_object_from_file(&agg_pk_path)?);
        } else {
            builder = builder.agg_params(AggregationSystemParams::default());
        }

        if root_pk_path.exists() {
            eprintln!("reusing root pk");
            builder = builder.root_pk(read_object_from_file(&root_pk_path)?);
        }

        let sdk = builder.build()?;
        let app_exe = sdk.convert_to_exe(ExecutableFormat::Elf(elf))?;

        let root_proof: Proof<RootSC> = if root_proof_path.exists() {
            eprintln!("reusing root proof from {:?}", root_proof_path);
            read_object_from_file(&root_proof_path)?
        } else {
            let mut evm_prover =
                sdk.evm_prover_without_halo2(app_exe).expect("evm_prover construction failed");

            let root_proof = evm_prover.prove_root(stdin, &[])?;

            write_object_to_file(&root_proof_path, &root_proof)?;
            write_object_to_file(&app_pk_path, sdk.app_pk())?;
            write_object_to_file(&agg_pk_path, sdk.agg_pk())?;
            write_object_to_file(&root_pk_path, sdk.root_pk())?;

            root_proof
        };

        let agg_prover = sdk.agg_prover();
        let root_prover = sdk.root_prover();
        let internal_recursive_vk = agg_prover.internal_recursive_prover.get_vk();
        let root_vk = root_prover.0.get_vk().as_ref().clone();
        let shape = *sdk.halo2_shape();
        let params = sdk.halo2_params_reader().read_params(shape.k);

        let pk =
            keygen_static_verifier(&params, shape, &internal_recursive_vk, &root_vk, &root_proof);

        let mut writer = BufWriter::new(File::create(&static_verifier_pk_path)?);
        pk.encode(&mut writer)?;
        (pk, root_proof)
    };

    let root_vk = &static_verifier_pk.circuit.root_vk;

    #[cfg(feature = "cuda")]
    let root_engine =
        openvm_cuda_backend::BabyBearBn254Poseidon2GpuEngine::new(root_vk.inner.params.clone());
    #[cfg(not(feature = "cuda"))]
    let root_engine =
        openvm_stark_sdk::config::baby_bear_bn254_poseidon2::BabyBearBn254Poseidon2CpuEngine::new(
            root_vk.inner.params.clone(),
        );

    let tracegen_iters: usize =
        std::env::var("TRACEGEN_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    eprintln!("running populate_witness_gen {tracegen_iters}x");

    run_with_metric_collection("OUTPUT_PATH", || -> Result<()> {
        info_span!("static_verifier_tracegen", iters = tracegen_iters).in_scope(|| {
            for _ in 0..tracegen_iters {
                // #[cfg(feature = "coz")]
                // coz::scope!("tracegen_iter");
                let mut witness_builder = WitnessCircuitBuilder::new(
                    static_verifier_pk.pinning.metadata.break_points[0].clone(),
                    static_verifier_pk.pinning.metadata.config_params.clone(),
                    static_verifier_pk.pinning.pk.get_vk().cs().num_advice_columns(),
                );
                static_verifier_pk.circuit.populate_witness_gen(&mut witness_builder, &root_proof);
            }
        });

        info_span!("root_verifier_native").in_scope(|| -> Result<()> {
            root_engine.verify(root_vk, &root_proof)?;
            Ok(())
        })?;

        emit_instrument_snapshot();
        Ok(())
    })?;

    Ok(())
}

/// Publishes per-function counters from `halo2_base::instrument` to the metrics
/// registry so they land in `metrics.json` under gauges named
/// `<fn>_{count,sum_ns,sum_ns_sq}`.
fn emit_instrument_snapshot() {
    for (name, snap) in halo2_base::instrument::snapshot_all() {
        metrics::gauge!(format!("instr.{name}.count")).set(snap.count as f64);
        metrics::gauge!(format!("instr.{name}.sum_ns")).set(snap.sum_ns as f64);
        metrics::gauge!(format!("instr.{name}.sum_ns_sq")).set(snap.sum_ns_sq as f64);
    }
}
