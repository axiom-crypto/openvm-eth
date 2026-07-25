//! Benchmark host for the Zilkworm stateless Ethereum validator guest.
//!
//! Zilkworm (github.com/eth-act/zilkworm-stateless) is a bare-metal C++
//! stateless block validator compiled to an RV64IM ELF. This host loads the
//! prebuilt guest ELF, feeds it an eth-act SSZ `StatelessInput` byte vector
//! (an EEST / conformance `*_input.bin`), and runs it through the same
//! execute / prove pipeline as the Reth benchmark.
//!
//! The guest reads exactly one length-prefixed input vector from the hint
//! stream and reveals the SSZ `StatelessValidationResult`
//! (`root[32] || success[1] || offset[4] || chain_config`) as public values.

use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::Parser;
use eyre::Result;
use openvm_circuit::arch::{
    execution_mode::metered::segment_ctx::DEFAULT_MAX_MEMORY, instructions::exe::VmExe,
    verify_segments, VmCircuitConfig,
};
use openvm_sdk::{
    config::{
        AggregationSystemParams, AggregationTreeConfig, AppConfig, DEFAULT_APP_LOG_BLOWUP,
        DEFAULT_APP_L_SKIP, DEFAULT_INTERNAL_LOG_BLOWUP, DEFAULT_LEAF_LOG_BLOWUP,
    },
    fs::{read_object_from_file, write_object_to_file},
    Sdk, StdIn, SC,
};
use openvm_sdk_config::{SdkVmConfig, TranspilerConfig};
use openvm_stark_sdk::{
    bench::run_with_metric_collection,
    config::{
        app_params_with_100_bits_security, baby_bear_poseidon2::F,
        internal_params_with_100_bits_security, leaf_params_with_100_bits_security,
        MAX_APP_LOG_STACKED_HEIGHT, SECURITY_BITS_TARGET,
    },
    openvm_stark_backend::{codec::Encode, SystemParams},
};
use openvm_transpiler::{elf::Elf, openvm_platform::memory::MEM_SIZE, FromElf};
use openvm_verify_stark_host::{
    verify_vm_stark_proof_decoded,
    vk::{write_vk_to_file, VmStarkVerifyingKey},
};
use tracing::{info, info_span};

const VM_MAX_CONSTRAINT_DEGREE: usize = 4;

/// Capacity of the user public-values address space in bytes. The guest's SSZ
/// `StatelessValidationResult` is 105 bytes for mainnet blocks (root[32] ||
/// success[1] || offset[4] || chain_config), so 128 is the smallest power of
/// two that fits it. (z6m's MAX_PUBLIC_VALUES_SIZE buffer is 256, but only the
/// encoded prefix is revealed.)
const PUBLIC_VALUES_BYTES: usize = 128;

/// Enum representing the execution mode of the host executable.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum BenchMode {
    /// Execute the VM without generating a proof.
    Execute,
    /// Execute the VM with metering to get segments information.
    ExecuteMetered,
    /// Generate sequence of app proofs for continuation segments.
    ProveApp,
    /// Generate a full end-to-end STARK proof with aggregation.
    ProveStark,
    /// Generate proving and verifying keys for app and aggregation circuits.
    Keygen,
    /// Generate VM verifying key baseline artifact and write it to a local file.
    GenerateVmVkey,
}

impl std::fmt::Display for BenchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Execute => write!(f, "execute"),
            Self::ExecuteMetered => write!(f, "execute_metered"),
            Self::ProveApp => write!(f, "prove_app"),
            Self::ProveStark => write!(f, "prove_stark"),
            Self::Keygen => write!(f, "keygen"),
            Self::GenerateVmVkey => write!(f, "generate_vm_vkey"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(allow_external_subcommands = true)]
pub struct BenchmarkCli {
    /// Application level log blowup
    #[arg(long, default_value_t = DEFAULT_APP_LOG_BLOWUP)]
    pub app_log_blowup: usize,

    /// Log of univariate skip domain size
    #[arg(long, default_value_t = DEFAULT_APP_L_SKIP)]
    pub app_l_skip: usize,

    /// Aggregation (leaf) level log blowup
    #[arg(long, default_value_t = DEFAULT_LEAF_LOG_BLOWUP)]
    pub leaf_log_blowup: usize,

    /// Internal level log blowup
    #[arg(long, default_value_t = DEFAULT_INTERNAL_LOG_BLOWUP)]
    pub internal_log_blowup: usize,

    #[command(flatten)]
    pub agg_tree_config: AggregationTreeConfig,

    /// Estimated proving-memory cap per VM segment, in bytes
    #[arg(long, default_value_t = DEFAULT_MAX_MEMORY)]
    pub segment_max_memory: usize,

    /// Whether the proving-memory model assumes the Reed-Solomon code matrix
    /// stays resident after `stacked_commit`.
    ///
    /// This is a segmentation *setting*, not a backend detail, and the two
    /// engines disagree on it: the CPU engine passes `true`
    /// (stark-backend `Engine::proving_memory_config`) while the CUDA engine
    /// uses `GpuProverConfig::default()`, which is `false`. Caching leaves
    /// less of `--segment-max-memory` for trace, so the same guest segments
    /// differently: block 24001988 gives 119 segments under the CPU model and
    /// 79 under the GPU model.
    ///
    /// Defaults to the GPU model so local `execute-metered` estimates match
    /// the GPU benchmark runs; pass `--cache-rs-code-matrix` to model a CPU
    /// prover instead.
    #[arg(long, default_value_t = false)]
    pub cache_rs_code_matrix: bool,
}

/// The arguments for the host executable.
#[derive(Debug, Parser)]
pub struct HostArgs {
    /// The execution mode.
    #[clap(long, value_enum)]
    mode: BenchMode,

    /// Path to the prebuilt Zilkworm RV64IM guest ELF (z6m_guest.elf).
    #[clap(long, env = "ZILKWORM_GUEST_ELF")]
    guest_elf: PathBuf,

    /// Path to the guest input: raw eth-act SSZ `StatelessInput` bytes
    /// (a conformance `*_input.bin` / EEST `*.input.bin` file).
    /// Required for all modes except keygen / generate-vm-vkey.
    #[clap(long)]
    input_path: Option<PathBuf>,

    /// Optional path to the expected public values (an SSZ
    /// `StatelessValidationResult`, e.g. a conformance
    /// `*_expected_success.bin`). When provided, execution output is
    /// checked against it.
    #[clap(long)]
    expected_output: Option<PathBuf>,

    /// Label used for metric grouping; defaults to the input file stem.
    #[clap(long)]
    program_label: Option<String>,

    #[clap(flatten)]
    benchmark: BenchmarkCli,

    /// If specified, the proof and other output is written to this dir.
    #[arg(long, default_value = "output")]
    pub output_dir: PathBuf,

    /// If specified, loads the app proving key from this path.
    #[arg(long)]
    pub app_pk_path: Option<PathBuf>,

    /// Path to save the app verifying key (overrides output_dir)
    #[arg(long)]
    pub app_vk_path: Option<PathBuf>,

    /// If specified, loads the agg proving key from this path.
    #[arg(long)]
    pub agg_pk_path: Option<PathBuf>,
}

/// VM extension config for the Zilkworm guest.
///
/// Uses `SdkVmConfig::standard()` — byte-for-byte the same extension set the
/// Reth benchmark host uses (`reth_vm_config`) — so the two guests are proven
/// on an identical circuit and their segment counts are directly comparable.
/// `standard()` also fixes the modulus / Fp2 / curve ordering that the guest's
/// funct7 indices encode (see zilkworm's zkvm/openvm/src/include/openvm_ecc.hpp),
/// and it enables the Int256 (`bigint`) extension.
///
/// The one deliberate difference from Reth: public-value capacity. Reth reveals
/// a 32-byte block hash and configures 32 cells (64 bytes); the Zilkworm guest
/// reveals the SSZ `StatelessValidationResult`, which is 105 bytes for mainnet
/// blocks, so it needs 64 cells (128 bytes).
pub fn zilkworm_vm_config() -> SdkVmConfig {
    let mut config = SdkVmConfig::standard();
    config.system.config = config
        .system
        .config
        .clone()
        .with_max_constraint_degree(VM_MAX_CONSTRAINT_DEGREE)
        .with_public_values_bytes(PUBLIC_VALUES_BYTES);
    config
}

pub fn build_zilkworm_exe(vm_config: &SdkVmConfig, guest_elf: &[u8]) -> Result<VmExe<F>> {
    let transpiler = vm_config.transpiler().clone();
    let elf = Elf::decode(guest_elf, MEM_SIZE as u32)?;
    Ok(VmExe::from_elf(elf, transpiler)?)
}

fn override_system_params(
    params: SystemParams,
    log_blowup: usize,
    l_skip: usize,
) -> Result<SystemParams> {
    let log_stacked_height = params.log_stacked_height();
    if l_skip > log_stacked_height {
        eyre::bail!("l_skip ({l_skip}) must be <= log_stacked_height ({log_stacked_height})");
    }

    let whir = params.whir().clone();
    Ok(SystemParams::new(
        log_blowup,
        l_skip,
        log_stacked_height - l_skip,
        params.w_stack,
        whir.log_final_poly_len(log_stacked_height),
        whir.folding_pow_bits,
        whir.mu_pow_bits,
        whir.proximity,
        SECURITY_BITS_TARGET,
        params.logup,
        params.max_constraint_degree,
        whir.query_phase_pow_bits,
        whir.k,
    ))
}

fn override_log_blowup(params: SystemParams, log_blowup: usize) -> Result<SystemParams> {
    let l_skip = params.l_skip;
    override_system_params(params, log_blowup, l_skip)
}

/// Check the guest's revealed public values against an expected SSZ
/// `StatelessValidationResult`. The public-values buffer is fixed-size and
/// zero-padded past the SSZ payload, so compare the expected prefix and
/// require the tail to be zero.
fn check_expected_output(public_values: &[u8], expected_path: &Path) -> Result<()> {
    let expected = fs::read(expected_path)?;
    if expected.len() > public_values.len() {
        eyre::bail!(
            "expected output ({} bytes) exceeds public values capacity ({} bytes)",
            expected.len(),
            public_values.len()
        );
    }
    if public_values[..expected.len()] != expected[..] {
        eyre::bail!(
            "public values mismatch:\n  expected: {}\n  actual:   {}",
            hex::encode(&expected),
            hex::encode(&public_values[..expected.len()])
        );
    }
    if public_values[expected.len()..].iter().any(|&b| b != 0) {
        eyre::bail!("public values have non-zero bytes past the expected output");
    }
    info!("Public values match expected output ({} bytes)", expected.len());
    Ok(())
}

fn report_public_values(public_values: &[u8]) {
    // SSZ StatelessValidationResult: root[32] || success[1] || offset[4] || chain_config
    if public_values.len() >= 33 {
        let root = hex::encode(&public_values[..32]);
        let success = public_values[32] == 1;
        println!("BENCH_STATE_ROOT=0x{root}");
        println!("BENCH_SUCCESS={success}");
    }
    println!("BENCH_PUBLIC_VALUES={}", hex::encode(public_values));
}

pub fn run_zilkworm_benchmark(args: HostArgs) -> Result<()> {
    // Initialize the environment variables.
    dotenv::dotenv().ok();

    #[cfg(feature = "cuda")]
    eprintln!("CUDA Backend Enabled");

    let mut vm_config = zilkworm_vm_config();
    vm_config.as_mut().set_segmentation_max_memory(args.benchmark.segment_max_memory);

    for (air_idx, air) in VmCircuitConfig::<SC>::create_airs(&vm_config)?.into_airs().enumerate() {
        tracing::debug!("air_idx={air_idx} | {}", air.name());
    }

    let app_params = override_system_params(
        app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT),
        args.benchmark.app_log_blowup,
        args.benchmark.app_l_skip,
    )?;

    // Setup: this can all be done once before receiving proof input
    let app_config = AppConfig::new(vm_config.clone(), app_params);
    let agg_params = AggregationSystemParams {
        leaf: override_log_blowup(
            leaf_params_with_100_bits_security(),
            args.benchmark.leaf_log_blowup,
        )?,
        internal: override_log_blowup(
            internal_params_with_100_bits_security(),
            args.benchmark.internal_log_blowup,
        )?,
    };

    // Resolve key paths: explicit flag wins; otherwise fall back to <output_dir>/<name>.pk
    // if the file exists.
    let app_pk_path = args.app_pk_path.clone().or_else(|| {
        let p = args.output_dir.join("app.pk");
        p.exists().then_some(p)
    });
    let agg_pk_path = args.agg_pk_path.clone().or_else(|| {
        let p = args.output_dir.join("agg.pk");
        p.exists().then_some(p)
    });

    let mut sdk_builder = Sdk::builder().agg_tree_config(args.benchmark.agg_tree_config);

    if let Some(p) = app_pk_path {
        info!("Loading app proving key from {}", p.display());
        let app_pk = read_object_from_file(&p)?;
        sdk_builder = sdk_builder.app_pk(app_pk);
    } else {
        sdk_builder = sdk_builder.app_config(app_config);
    }

    if let Some(p) = agg_pk_path {
        info!("Loading agg proving key from {}", p.display());
        let agg_pk = read_object_from_file(&p)?;
        sdk_builder = sdk_builder.agg_pk(agg_pk);
    } else {
        sdk_builder = sdk_builder.agg_params(agg_params);
    }

    let sdk = sdk_builder.build()?;

    let guest_elf = fs::read(&args.guest_elf)?;
    let exe = build_zilkworm_exe(&vm_config, &guest_elf)?;

    if matches!(args.mode, BenchMode::GenerateVmVkey) {
        let prover = sdk.prover(exe)?;
        let vk = VmStarkVerifyingKey {
            mvk: (*sdk.agg_vk()).clone(),
            baseline: prover.generate_baseline(),
        };
        let vk_path = PathBuf::from("zilkworm.vm.vk");
        write_vk_to_file(&vk_path, &vk)?;
        info!("VM verifying key written to {}", vk_path.display());
        return Ok(());
    }

    if matches!(args.mode, BenchMode::Keygen) {
        fs::create_dir_all(&args.output_dir)?;

        let app_pk_path = args.app_pk_path.unwrap_or_else(|| args.output_dir.join("app.pk"));
        let app_vk_path = args.app_vk_path.unwrap_or_else(|| args.output_dir.join("app.vk"));
        let agg_pk_path = args.agg_pk_path.unwrap_or_else(|| args.output_dir.join("agg.pk"));

        info!("Generating app proving key...");
        let (app_pk, app_vk) = sdk.app_keygen();

        info!("Saving app proving key to: {}", app_pk_path.display());
        write_object_to_file(&app_pk_path, &app_pk)?;

        info!("Saving app verifying key to: {}", app_vk_path.display());
        write_object_to_file(&app_vk_path, &app_vk)?;

        info!("Generating aggregation proving key...");
        let agg_pk = sdk.agg_pk();

        info!("Saving agg proving key to: {}", agg_pk_path.display());
        write_object_to_file(&agg_pk_path, &agg_pk)?;

        info!("Keygen completed successfully!");
        return Ok(());
    }

    let input_path = args
        .input_path
        .as_ref()
        .ok_or_else(|| eyre::eyre!("--input-path is required for mode {}", args.mode))?;
    let input_bytes = fs::read(input_path)?;
    info!("Loaded {} input bytes from {}", input_bytes.len(), input_path.display());

    let label = args.program_label.clone().unwrap_or_else(|| {
        input_path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "input".to_string())
    });
    let program_name = format!("zilkworm.{}.{}", args.mode, label);

    let cache_rs_code_matrix = args.benchmark.cache_rs_code_matrix;
    let stdin: StdIn = vec![input_bytes].into();

    run_with_metric_collection("OUTPUT_PATH", move || {
        info_span!("zilkworm-block", label = label).in_scope(|| -> Result<()> {
            match args.mode {
                BenchMode::Execute => {
                    let compiled = sdk.compile(exe)?;
                    let public_values = sdk.execute(&compiled, stdin)?;
                    info!("Execute completed");
                    report_public_values(&public_values);
                    if let Some(expected) = &args.expected_output {
                        check_expected_output(&public_values, expected)?;
                    }
                }
                BenchMode::ExecuteMetered => {
                    let mut compiled = sdk.compile_metered(exe)?;
                    compiled.ctx.set_cache_rs_code_matrix(cache_rs_code_matrix);
                    let (public_values, segments) = sdk.execute_metered(&compiled, stdin)?;
                    info!("Execute metered completed, {} segments", segments.len());
                    report_public_values(&public_values);
                    if let Some(expected) = &args.expected_output {
                        check_expected_output(&public_values, expected)?;
                    }
                }
                BenchMode::ProveApp => {
                    let mut prover = sdk.app_prover(exe)?;
                    prover.set_program_name(program_name);
                    let app_proof = prover.prove(stdin)?;
                    let (_, app_vk) = sdk.app_keygen();
                    verify_segments(&prover.vm().engine, &app_vk.vk, &app_proof.per_segment)?;
                }
                BenchMode::ProveStark => {
                    let (proof, baseline) = sdk.prove(exe, stdin, &[])?;
                    let vk = VmStarkVerifyingKey { mvk: (*sdk.agg_vk()).clone(), baseline };
                    let encoded = proof.encode_to_vec()?;
                    let compressed = zstd::encode_all(&encoded[..], 19)?;
                    tracing::info!(
                        "Proof Size (bytes): {}, Compressed Size: {}",
                        encoded.len(),
                        compressed.len()
                    );
                    verify_vm_stark_proof_decoded(&vk, &proof)?;
                }
                _ => {
                    // Keygen, GenerateVmVkey handled earlier
                    unreachable!();
                }
            }

            Ok(())
        })
    })?;
    Ok(())
}
