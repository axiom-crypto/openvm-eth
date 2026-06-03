#![cfg_attr(feature = "tco", allow(incomplete_features))]
#![cfg_attr(feature = "tco", feature(explicit_tail_calls))]
use std::{fs, io::Write, path::PathBuf, time::Instant};

use alloy_provider::RootProvider;
use alloy_rpc_client::RpcClient;
use alloy_transport::layers::RetryBackoffLayer;
use clap::Parser;
use openvm_circuit::arch::*;
use openvm_rpc_proxy::{RpcExecutor, DEFAULT_PREIMAGE_CACHE_NIBBLES};
use openvm_sdk::{
    config::{
        AggregationSystemParams, AppConfig, DEFAULT_APP_LOG_BLOWUP, DEFAULT_APP_L_SKIP,
        DEFAULT_INTERNAL_LOG_BLOWUP, DEFAULT_LEAF_LOG_BLOWUP,
    },
    fs::write_object_to_file,
    StdIn, SC,
};
use openvm_sdk_config::SdkVmConfig;
use openvm_stark_sdk::{
    bench::run_with_metric_collection,
    config::{
        app_params_with_100_bits_security, baby_bear_poseidon2::F,
        internal_params_with_100_bits_security, leaf_params_with_100_bits_security,
        log_up_params::log_up_security_params_baby_bear_100_bits,
    },
    openvm_stark_backend::{
        air_builders::symbolic::{SymbolicExpressionDag, SymbolicExpressionNode},
        codec::Encode,
        keygen::types::MultiStarkProvingKey,
        p3_field::PrimeCharacteristicRing,
        SystemParams, WhirProximityStrategy,
    },
};
use openvm_stateless_executor::{
    io::StatelessExecutorInput, ChainVariant, StatelessExecutor, CHAIN_ID_ETH_MAINNET,
};
use openvm_transpiler::{elf::Elf, openvm_platform::memory::MEM_SIZE};
use openvm_verify_stark_host::{
    verify_vm_stark_proof_decoded,
    vk::{write_vk_to_file, VmStarkVerifyingKey},
};
use powdr_autoprecompiles::{
    execution_profile::execution_profile, PgoConfig, PgoType, SelectConfig,
};
#[cfg(not(feature = "cuda"))]
use powdr_openvm::PowdrSdkCpu;
#[cfg(feature = "cuda")]
use powdr_openvm::PowdrSdkGpu;
use powdr_openvm::{
    default_generate_config, extraction_utils::OriginalVmConfig,
    make_default_empirical_constraints, BabyBearOpenVmApcAdapter, CompiledProgram,
    OriginalCompiledProgram, PowdrExecutionProfileSdkCpu, Prog, StagedPipeline,
};
use powdr_openvm_riscv::{ExtendedVmConfig, RiscvISA};
use powdr_openvm_riscv_hints_circuit::HintsExtension;
use serde::{Deserialize, Serialize};
use tracing::{info, info_span};

mod cli;
use cli::ProviderArgs;

pub const DEFAULT_LOG_STACKED_HEIGHT: usize = 24;

/// Enum representing the execution mode of the host executable.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum BenchMode {
    /// Generate input file only.
    MakeInput,
    /// Execute natively on host.
    ExecuteHost,
    /// Execute the VM without generating a proof.
    Execute,
    /// Execute the VM with metering to get segments information.
    ExecuteMetered,
    /// Compile the APC-specialized program and cache it; no execution or proving.
    /// Requires `--apc > 0`. APC-specific.
    Compile,
    /// Generate sequence of app proofs for continuation segments.
    ProveApp,
    /// Generate a full end-to-end STARK proof with aggregation.
    ProveStark,
    /// Generate a full end-to-end halo2 proof for EVM verifier.
    #[cfg(feature = "evm-verify")]
    ProveEvm,
    /// Generate proving and verifying keys for app and aggregation circuits.
    Keygen,
    /// Generate VM verifying key baseline artifact and write it to a local file.
    GenerateVmVkey,
    /// Dump per-AIR statistics and exit.
    DumpAirStats,
}

impl std::fmt::Display for BenchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MakeInput => write!(f, "make_input"),
            Self::ExecuteHost => write!(f, "execute_host"),
            Self::Execute => write!(f, "execute"),
            Self::ExecuteMetered => write!(f, "execute_metered"),
            Self::Compile => write!(f, "compile"),
            Self::ProveApp => write!(f, "prove_app"),
            Self::ProveStark => write!(f, "prove_stark"),
            #[cfg(feature = "evm-verify")]
            Self::ProveEvm => write!(f, "prove_evm"),
            Self::Keygen => write!(f, "keygen"),
            Self::GenerateVmVkey => write!(f, "generate_vm_vkey"),
            Self::DumpAirStats => write!(f, "dump_air_stats"),
        }
    }
}

/// The arguments for the host executable.
#[derive(Debug, Parser)]
pub struct HostArgs {
    /// The block number of the block to execute.
    #[clap(long)]
    block_number: Option<u64>,
    #[clap(flatten)]
    provider: ProviderArgs,

    /// The execution mode.
    #[clap(long, value_enum)]
    mode: BenchMode,

    /// Optional path to the directory containing cached client input. A new cache file will be
    /// created from RPC data if it doesn't already exist.
    #[clap(long)]
    cache_dir: Option<PathBuf>,
    /// The path to the CSV file containing the execution data.
    #[clap(long, default_value = "report.csv")]
    report_path: PathBuf,
    /// The path to the CSV file containing per-AIR statistics.
    #[clap(long, default_value = "air_stats.csv")]
    air_stats_path: PathBuf,

    #[clap(flatten)]
    benchmark: BenchmarkCli,

    /// Optional path to the input file.
    #[arg(long)]
    pub input_path: Option<PathBuf>,

    /// Path to write the fixtures to. Only needed for mode=make_input
    #[arg(long)]
    pub fixtures_path: Option<PathBuf>,

    /// In make_input mode, this path is where the input JSON is written.
    #[arg(long)]
    pub generated_input_path: Option<PathBuf>,

    /// If specificed, the proof and other output is written to this dir.
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

    /// The number of nibbles to precompute for the preimage lookup table.
    /// Higher values increase startup time but reduce RPC calls for missing storage keys.
    ///
    /// Warning: This is a form of grinding, so higher values will be slower on machines with many
    /// CPU cores.
    #[clap(long, default_value_t = DEFAULT_PREIMAGE_CACHE_NIBBLES, value_parser = clap::value_parser!(u8).range(..=8))]
    pub preimage_cache_nibbles: u8,

    // =====================================================================
    // APC (autoprecompile) options. When `--apc > 0`, the `Compile`,
    // `ProveApp` and `ProveStark` modes take an alternate code path that
    // specialises the guest program with powdr-generated APCs and proves
    // through powdr's `PowdrSdkGpu/Cpu`. Other modes ignore these flags.
    // =====================================================================
    /// Block numbers to use for APC PGO input (comma-separated). Defaults to
    /// `--block-number`.
    #[clap(long, value_delimiter = ',')]
    pub pgo_block_numbers: Vec<u64>,

    /// Root for powdr's staged APC artifact cache. Setting this enables reuse
    /// of the `generate` / `select` / `setup` stages across runs; sweeping
    /// `--apc N` under `--pgo-type cell` will only build candidates once and
    /// reuse them across every selection size.
    #[clap(long, default_value = "apc-cache")]
    pub artifacts_dir: PathBuf,

    /// Number of APCs to generate. `0` disables APC entirely.
    #[clap(long, default_value_t = 0)]
    pub apc: usize,

    /// Number of APC candidates to skip when selecting (debugging aid).
    #[clap(long, default_value_t = 0)]
    pub apc_skip: usize,

    /// PGO strategy for selecting basic blocks to accelerate.
    #[clap(long, value_parser = parse_pgo_type, default_value = "cell")]
    pub pgo_type: PgoType,

    /// Override the leaf aggregation layer's `log_stacked_height`. Preset is
    /// 21. APC ≳ 500 needs 22; diverges from the proven-soundness preset.
    #[clap(long)]
    pub leaf_log_stacked_height: Option<usize>,

    /// Override the internal recursion layer's `log_stacked_height`. Preset
    /// is 19. Bump in tandem with `--leaf-log-stacked-height` if internal
    /// hits `LayoutHeightExceeded`.
    #[clap(long)]
    pub internal_log_stacked_height: Option<usize>,
}

fn parse_pgo_type(s: &str) -> Result<PgoType, String> {
    s.parse::<PgoType>().map_err(|e| format!("invalid pgo-type '{s}': {e}"))
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

    /// Max trace height per chip in segment for continuations
    #[arg(long, alias = "max_segment_length")]
    pub max_segment_length: Option<u32>,

    /// Total cells used in all chips in segment for continuations
    #[arg(long)]
    pub segment_max_memory: Option<usize>,
}

pub fn reth_vm_config() -> SdkVmConfig {
    let mut config = SdkVmConfig::standard();
    config.system.config = config
        .system
        .config
        .with_max_constraint_degree(VM_MAX_CONSTRAINT_DEGREE)
        .with_public_values(32);
    config
}

const VM_MAX_CONSTRAINT_DEGREE: usize = 4;

/// Wrap `reth_vm_config()` in powdr's [`ExtendedVmConfig`] (SdkVmConfig +
/// HintsExtension) so `powdr-openvm-riscv` can specialise it with APCs.
fn reth_extended_vm_config() -> ExtendedVmConfig {
    ExtendedVmConfig { sdk: reth_vm_config(), hints: HintsExtension }
}

/// Build `AggregationSystemParams`, overriding leaf / internal
/// `log_stacked_height` when requested. Diverges from the 100-bit-security
/// presets — intended for benchmarking large APC counts where the preset
/// leaf/internal circuits can't accommodate the generated AIR shapes.
fn build_agg_params(
    leaf_log_stacked_height: Option<usize>,
    internal_log_stacked_height: Option<usize>,
) -> AggregationSystemParams {
    let leaf = match leaf_log_stacked_height {
        None => leaf_params_with_100_bits_security(),
        Some(h) => {
            const L_SKIP: usize = 4;
            assert!(h >= L_SKIP, "--leaf-log-stacked-height must be >= {L_SKIP}");
            let n_stack = h - L_SKIP;
            tracing::warn!(
                "Overriding leaf log_stacked_height to {h} (l_skip={L_SKIP}, n_stack={n_stack}) \
                 — diverges from the 100-bit-security preset"
            );
            // Mirrors `leaf_params_with_100_bits_security` with custom n_stack.
            // Two magic numbers are stark-sdk module-private:
            // WHIR_MAX_LOG_FINAL_POLY_LEN=10, SECURITY_BITS_TARGET=100.
            SystemParams::new(
                DEFAULT_LEAF_LOG_BLOWUP,
                L_SKIP,
                n_stack,
                2048,
                10,
                4,
                13,
                WhirProximityStrategy::UniqueDecoding,
                100,
                log_up_security_params_baby_bear_100_bits(),
            )
        }
    };
    let internal = match internal_log_stacked_height {
        None => internal_params_with_100_bits_security(),
        Some(h) => {
            const L_SKIP: usize = 2;
            assert!(h >= L_SKIP, "--internal-log-stacked-height must be >= {L_SKIP}");
            let n_stack = h - L_SKIP;
            tracing::warn!(
                "Overriding internal log_stacked_height to {h} (l_skip={L_SKIP}, n_stack={n_stack}) \
                 — diverges from the 100-bit-security preset"
            );
            SystemParams::new(
                DEFAULT_INTERNAL_LOG_BLOWUP,
                L_SKIP,
                n_stack,
                512,
                10,
                18,
                20,
                WhirProximityStrategy::ListDecoding { m: 2 },
                100,
                log_up_security_params_baby_bear_100_bits(),
            )
        }
    };
    AggregationSystemParams { leaf, internal }
}

/// Cached APC-specialised program (reused across runs with the same setup).
/// Proving keys are regenerated on each run rather than cached — the v2 SDK
/// handles keygen internally when the SDK is constructed.
#[derive(Serialize, Deserialize)]
pub struct PrecomputedProverData {
    program: CompiledProgram<RiscvISA>,
}

/// Compile the APC-specialised program through powdr's [`StagedPipeline`],
/// which transparently caches the `generate` / `select` / `setup` stages
/// under `--artifacts-dir`. With `args.apc == 0` this is a fast identity
/// specialisation — no PGO, zero APCs selected.
///
/// Stage cache keys are chosen so a sweep across `--apc N` values under
/// `--pgo-type cell` reuses the candidate ranking: the `generate` key omits
/// `--apc` / `--apc-skip`, while `select` and `setup` add them back.
pub async fn precompute_prover_data(
    args: &HostArgs,
    vm_config: &ExtendedVmConfig,
    openvm_client_eth_elf: &[u8],
) -> eyre::Result<PrecomputedProverData> {
    // OpenVM only installs its tracing subscriber when `run_with_metric_collection`
    // is entered, so we install a local one here to surface powdr's APC compile
    // progress logs.
    let subscriber =
        tracing_subscriber::FmtSubscriber::builder().with_max_level(tracing::Level::DEBUG).finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    // With --apc 0, nothing to select, so force PGO off regardless of flag.
    let pgo_type = if args.apc == 0 { PgoType::None } else { args.pgo_type };

    let pgo_blocks: Vec<u64> = if args.apc == 0 {
        Vec::new()
    } else {
        let block_number = args
            .block_number
            .ok_or_else(|| eyre::eyre!("--block-number is required for APC compile"))?;
        if args.pgo_block_numbers.is_empty() {
            vec![block_number]
        } else {
            args.pgo_block_numbers.clone()
        }
    };

    // Pre-fetch the PGO stdins. Cheap on warm runs because `load_stateless_input`
    // hits the local rpc-cache; the expensive RPC path only fires on cold cache.
    // Pre-fetching keeps the closure passed to `generate_apcs` synchronous.
    let provider_config = args.provider.clone().into_provider().await?;
    let mut pgo_stdins: Vec<StdIn> = Vec::new();
    for block_id in pgo_blocks {
        let pgo_input = load_stateless_input(
            &provider_config,
            &args.cache_dir,
            CHAIN_ID_ETH_MAINNET,
            block_id,
            args.preimage_cache_nibbles,
        )
        .await?;
        let mut stdin = StdIn::default();
        stdin.write(&pgo_input);
        pgo_stdins.push(stdin);
    }

    let system_params = app_params_with_100_bits_security(DEFAULT_LOG_STACKED_HEIGHT);
    let app_config = AppConfig::new(vm_config.clone(), system_params);

    let exe = {
        let profile_sdk = PowdrExecutionProfileSdkCpu::<RiscvISA>::new(
            app_config.clone(),
            AggregationSystemParams::default(),
        )?;
        let elf = Elf::decode(openvm_client_eth_elf, MEM_SIZE as u32)?;
        profile_sdk.convert_to_exe(elf)?
    };
    let elf = powdr_riscv_elf::load_elf_from_buffer(openvm_client_eth_elf);
    let original_program =
        OriginalCompiledProgram::new(exe, OriginalVmConfig::new(vm_config.clone()), elf);

    let pipeline = StagedPipeline::new(original_program, Some(args.artifacts_dir.clone()));

    let select = SelectConfig::new(args.apc as u64, args.apc_skip as u64);
    let mut generate = default_generate_config().with_select_defaults(pgo_type, select);

    if let Ok(path) = std::env::var("POWDR_APC_CANDIDATES_DIR") {
        fs::create_dir_all(&path)?;
        generate = generate.with_apc_candidates_dir(path);
    }

    let pgo_inputs = bincode::serde::encode_to_vec(&pgo_stdins, bincode::config::standard())
        .expect("serialize pgo_stdins for PgoConfig::inputs");
    let pgo_config = PgoConfig::new(pgo_type, None, pgo_inputs);

    tracing::info!(
        "precompute: compiling {} autoprecompiles (pgo={pgo_type:?}, artifacts_dir={})",
        args.apc,
        args.artifacts_dir.display()
    );

    let app_config_for_closure = app_config.clone();
    let make_pgo_profile = move |guest: &OriginalCompiledProgram<'static, RiscvISA>,
                                 inputs: &[u8]| {
        let (pgo_stdins, _): (Vec<StdIn>, usize) =
            bincode::serde::decode_from_slice(inputs, bincode::config::standard())
                .expect("deserialize pgo_stdins from PgoConfig::inputs");
        let prog = Prog::from(&guest.exe.program);
        let exec_sdk = PowdrExecutionProfileSdkCpu::<RiscvISA>::new(
            app_config_for_closure,
            AggregationSystemParams::default(),
        )
        .unwrap();
        execution_profile::<BabyBearOpenVmApcAdapter<'_, RiscvISA>>(&prog, || {
            for stdin in &pgo_stdins {
                exec_sdk.execute_interpreted(guest.exe.clone(), stdin.clone()).unwrap();
            }
        })
    };

    let program = pipeline.setup(
        &generate,
        &pgo_config,
        select,
        make_pgo_profile,
        make_default_empirical_constraints,
    );

    Ok(PrecomputedProverData { program })
}

/// Load stateless input either from bincode cache under `cache_dir` or by
/// fetching from RPC. Shared by the PGO input loader and the main flow.
async fn load_stateless_input(
    provider_config: &cli::ProviderConfig,
    cache_dir: &Option<PathBuf>,
    chain_id: u64,
    block_number: u64,
    preimage_cache_nibbles: u8,
) -> eyre::Result<StatelessExecutorInput> {
    if let Some(cached) = try_load_input_from_cache(cache_dir.as_ref(), chain_id, block_number)? {
        return Ok(cached);
    }
    let rpc_url = provider_config
        .rpc_url
        .as_ref()
        .ok_or_else(|| eyre::eyre!("cache not found and RPC URL not provided"))?;
    let client =
        RpcClient::builder().layer(RetryBackoffLayer::new(5, 1000, 100)).http(rpc_url.clone());
    let provider = RootProvider::new(client);
    let rpc_executor = RpcExecutor::new(provider, preimage_cache_nibbles);
    let stateless_input = rpc_executor.execute(block_number).await.expect("failed to execute host");
    if let Some(cache_dir) = cache_dir {
        let input_folder = cache_dir.join(format!("input/{chain_id}"));
        if !input_folder.exists() {
            std::fs::create_dir_all(&input_folder)?;
        }
        let input_path = input_folder.join(format!("{block_number}.bin"));
        let mut cache_file = std::fs::File::create(input_path)?;
        bincode::serde::encode_into_std_write(
            &stateless_input,
            &mut cache_file,
            bincode::config::standard(),
        )?;
    }
    Ok(stateless_input)
}

pub async fn run_reth_benchmark(args: HostArgs, openvm_client_eth_elf: &[u8]) -> eyre::Result<()> {
    // Initialize the environment variables.
    dotenv::dotenv().ok();

    let app_log_blowup = args.benchmark.app_log_blowup;
    let _app_l_skip = args.benchmark.app_l_skip;

    #[cfg(feature = "cuda")]
    println!("CUDA Backend Enabled");

    // Every run goes through powdr's machinery — with `--apc 0` it degenerates
    // into an identity specialisation (zero APCs, no PGO) that's
    // functionally equivalent to axiom's vanilla path. The circuit shape
    // differs by one empty AIR (`HintsExtension`) that's inert unless the
    // guest uses hints instructions.
    let mut vm_config = reth_extended_vm_config();
    if let Some(max_trace_height) = args.benchmark.max_segment_length {
        vm_config.sdk.as_mut().segmentation_config.limits.set_max_trace_height(max_trace_height);
    }
    if let Some(max_memory) = args.benchmark.segment_max_memory {
        vm_config.sdk.as_mut().segmentation_config.limits.set_max_memory(max_memory);
    }
    vm_config.sdk.as_mut().segmentation_config.main_cell_weight = 1 + (1 << app_log_blowup);

    for (air_idx, air) in VmCircuitConfig::<SC>::create_airs(&vm_config)?.into_airs().enumerate() {
        tracing::debug!("air_idx={air_idx} | {}", air.name());
    }

    if args.app_pk_path.is_some() != args.agg_pk_path.is_some() {
        eyre::bail!("app_pk_path and agg_pk_path must be provided together");
    }
    if let Some(_app_pk_path) = args.app_pk_path {
        todo!();
    }

    // APC compile (cached). With --apc 0 this is a fast identity pass that
    // produces a `SpecializedConfig` over `vm_config` and an unmodified exe.
    let PrecomputedProverData { program } =
        precompute_prover_data(&args, &vm_config, openvm_client_eth_elf).await?;
    let CompiledProgram { exe, vm_config: specialized_vm_config, .. } = program;

    if matches!(args.mode, BenchMode::Compile) {
        info!("APC compile finished (artifacts_dir={})", args.artifacts_dir.display());
        return Ok(());
    }

    let app_params = app_params_with_100_bits_security(DEFAULT_LOG_STACKED_HEIGHT);
    let app_config = AppConfig::new(specialized_vm_config, app_params);
    let agg_params =
        build_agg_params(args.leaf_log_stacked_height, args.internal_log_stacked_height);
    #[cfg(feature = "cuda")]
    let sdk = PowdrSdkGpu::<RiscvISA>::new(app_config, agg_params)?;
    #[cfg(not(feature = "cuda"))]
    let sdk = PowdrSdkCpu::<RiscvISA>::new(app_config, agg_params)?;

    if matches!(args.mode, BenchMode::DumpAirStats) {
        dump_air_stats(&sdk, &args.air_stats_path)?;
        return Ok(());
    }

    if matches!(args.mode, BenchMode::GenerateVmVkey) {
        let prover = sdk.prover(exe)?;
        let vk = VmStarkVerifyingKey {
            mvk: (*sdk.agg_vk()).clone(),
            baseline: prover.generate_baseline(),
        };
        let vk_path = PathBuf::from("reth.vm.vk");
        write_vk_to_file(&vk_path, &vk)?;
        info!("VM verifying key written to {}", vk_path.display());
        return Ok(());
    }

    let block_number = args
        .block_number
        .ok_or_else(|| eyre::eyre!("--block-number is required for mode {}", args.mode))?;

    let program_name = format!("reth.{}.block_{}", args.mode, block_number);

    // Load / fetch stateless input.
    let stateless_input = if let Some(path) = args.input_path.as_ref() {
        try_load_input_from_path(path)?
    } else {
        let provider_config = args.provider.into_provider().await?;
        if provider_config.chain_id != CHAIN_ID_ETH_MAINNET {
            eyre::bail!("unknown chain ID: {}", provider_config.chain_id);
        }
        load_stateless_input(
            &provider_config,
            &args.cache_dir,
            provider_config.chain_id,
            block_number,
            args.preimage_cache_nibbles,
        )
        .await?
    };

    // MakeInput: encode stateless_input as JSON and write to disk.
    if matches!(args.mode, BenchMode::MakeInput) {
        let words = openvm::serde::to_vec(&stateless_input)?;
        let bytes: Vec<u8> = words.into_iter().flat_map(|w: u32| w.to_le_bytes()).collect();
        let hex = format!("0x01{}", hex::encode(&bytes));
        let json = serde_json::json!({ "input": [hex] });

        if let Some(ref path) = args.generated_input_path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, serde_json::to_string(&json)?)?;
            info!("Wrote input JSON to {}", path.display());
        } else {
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        return Ok(());
    }

    // Host execution: run the stateless executor natively, no VM.
    if matches!(args.mode, BenchMode::ExecuteHost) {
        let program_name = format!("reth.{}.block_{}", args.mode, block_number);
        let executor = StatelessExecutor;
        let start = Instant::now();
        let header = info_span!("host.execute", group = program_name).in_scope(|| {
            info_span!("client.execute")
                .in_scope(|| executor.execute(ChainVariant::Mainnet, stateless_input))
        })?;
        let elapsed = start.elapsed();
        let block_hash = header.hash_slow();
        info!("Host execution: {:.6}s, block hash: {}", elapsed.as_secs_f64(), block_hash,);
        println!("BENCH_HOST_NS={}", elapsed.as_nanos());
        println!("BENCH_BLOCK_HASH={block_hash}");
        return Ok(());
    }

    let encoded_stateless_input: Vec<F> = {
        let words = openvm::serde::to_vec(&stateless_input)?;
        words.into_iter().flat_map(|w| w.to_le_bytes()).map(F::from_u8).collect()
    };

    let stdin = vec![encoded_stateless_input].into();

    run_with_metric_collection("OUTPUT_PATH", move || {
        info_span!("reth-block", block_number = block_number).in_scope(|| -> eyre::Result<()> {
            match args.mode {
                BenchMode::Execute => {
                    let public_values = info_span!("sdk.execute", group = program_name)
                        .in_scope(|| sdk.execute(exe, stdin))?;
                    let block_hash = hex::encode(&public_values);
                    info!("Execute completed, block hash: {}", block_hash);
                    println!("BENCH_BLOCK_HASH={block_hash}");
                }
                BenchMode::ExecuteMetered => {
                    let (public_values, _segments) =
                        info_span!("sdk.execute_metered", group = program_name)
                            .in_scope(|| sdk.execute_metered(exe, stdin))?;
                    let block_hash = hex::encode(&public_values);
                    info!("Execute metered completed, block hash: {}", block_hash);
                    println!("BENCH_BLOCK_HASH={block_hash}");
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
                #[cfg(feature = "evm-verify")]
                BenchMode::ProveEvm => {
                    let mut evm_prover = sdk.evm_prover(exe)?;
                    evm_prover.stark_prover.app_prover.set_program_name(&program_name);
                    let proof = evm_prover.prove_evm(stdin, &[])?;
                    let block_hash = &proof.user_public_values;
                    println!("block_hash (prove_evm): {}", hex::encode(block_hash));
                    let openvm_verifier = sdk.generate_halo2_verifier_solidity()?;
                    let gas_cost = Sdk::verify_evm_halo2_proof(&openvm_verifier, proof)?;
                    tracing::info!("EVM verifier gas cost: {gas_cost}");
                }
                BenchMode::Keygen => {
                    // Create output directory
                    fs::create_dir_all(&args.output_dir)?;

                    // Determine output paths
                    let app_pk_path =
                        args.app_pk_path.unwrap_or_else(|| args.output_dir.join("app.pk"));
                    let app_vk_path =
                        args.app_vk_path.unwrap_or_else(|| args.output_dir.join("app.vk"));
                    let agg_pk_path =
                        args.agg_pk_path.unwrap_or_else(|| args.output_dir.join("agg.pk"));

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
                    info!("  App PK: {}", app_pk_path.display());
                    info!("  App VK: {}", app_vk_path.display());
                    info!("  Agg PK: {}", agg_pk_path.display());
                }
                _ => {
                    // MakeInput, ExecuteHost, GenerateVmVkey, DumpAirStats handled earlier
                    unreachable!();
                }
            }

            Ok(())
        })
    })?;
    Ok(())
}

/// The SDK we construct at runtime — `PowdrSdkGpu` under `--features=cuda`,
/// `PowdrSdkCpu` otherwise. Both are `GenericSdk<_, SpecializedConfig…Builder>`
/// so the SDK methods we use (`app_keygen`, `agg_pk`, `prover`, `execute`,
/// `execute_metered`, `app_prover`, `prove`, `evm_prover`) all resolve via
/// the underlying `GenericSdk` impls.
#[cfg(feature = "cuda")]
type ActiveSdk = PowdrSdkGpu<RiscvISA>;
#[cfg(not(feature = "cuda"))]
type ActiveSdk = PowdrSdkCpu<RiscvISA>;

fn dump_air_stats(sdk: &ActiveSdk, output_path: &PathBuf) -> eyre::Result<()> {
    let (app_pk, _app_vk) = sdk.app_keygen();
    let mut file = fs::File::create(output_path)?;
    writeln!(
        file,
        "circuit,air_idx,air_name,num_monomials,monomial_ms,dag_size,max_rule_length,num_constraints"
    )?;

    dump_pk_stats("app", &app_pk.app_vm_pk.vm_pk, &mut file)?;

    let agg_pk = sdk.agg_pk();
    dump_pk_stats("agg_leaf", &agg_pk.prefix.leaf, &mut file)?;

    info!("AIR statistics written to {}", output_path.display());
    Ok(())
}

fn dump_pk_stats(
    label: &str,
    pk: &MultiStarkProvingKey<SC>,
    file: &mut fs::File,
) -> eyre::Result<()> {
    for (air_idx, air_pk) in pk.per_air.iter().enumerate() {
        let dag = &air_pk.vk.symbolic_constraints.constraints;
        let mono_start = Instant::now();
        #[cfg(feature = "cuda")]
        let num_monomials =
            openvm_cuda_backend::monomial::ExpandedMonomials::from_dag(dag).headers.len();
        #[cfg(not(feature = "cuda"))]
        let num_monomials = 0;
        let monomial_ms = mono_start.elapsed().as_millis();
        let dag_size = dag.nodes.len();
        let num_constraints = dag.constraint_idx.len();
        let max_rule_length = max_rule_length(dag);

        let air_name = air_pk.air_name.replace('"', "\"\"");
        writeln!(
            file,
            "{label},{air_idx},\"{air_name}\",{num_monomials},{monomial_ms},{dag_size},{max_rule_length},{num_constraints}",
        )?;
    }
    Ok(())
}

fn max_rule_length<F>(dag: &SymbolicExpressionDag<F>) -> usize {
    if dag.constraint_idx.is_empty() {
        return 0;
    }

    let mut visited = vec![0u32; dag.nodes.len()];
    let mut mark = 1u32;
    let mut max_len = 0usize;

    for &root in &dag.constraint_idx {
        let mut count = 0usize;
        let mut stack = vec![root];

        while let Some(idx) = stack.pop() {
            if visited[idx] == mark {
                continue;
            }
            visited[idx] = mark;
            count += 1;

            match &dag.nodes[idx] {
                SymbolicExpressionNode::Add { left_idx, right_idx, .. } |
                SymbolicExpressionNode::Sub { left_idx, right_idx, .. } |
                SymbolicExpressionNode::Mul { left_idx, right_idx, .. } => {
                    stack.push(*left_idx);
                    stack.push(*right_idx);
                }
                SymbolicExpressionNode::Neg { idx, .. } => {
                    stack.push(*idx);
                }
                _ => {}
            }
        }

        max_len = max_len.max(count);
        mark = mark.wrapping_add(1);
        if mark == 0 {
            visited.fill(0);
            mark = 1;
        }
    }

    max_len
}

fn try_load_input_from_cache(
    cache_dir: Option<&PathBuf>,
    chain_id: u64,
    block_number: u64,
) -> eyre::Result<Option<StatelessExecutorInput>> {
    Ok(if let Some(cache_dir) = cache_dir {
        let cache_path = cache_dir.join(format!("input/{chain_id}/{block_number}.bin"));

        if cache_path.exists() {
            // TODO: prune the cache if invalid instead
            let mut cache_file = std::fs::File::open(cache_path)?;
            let stateless_input: StatelessExecutorInput =
                bincode::serde::decode_from_std_read(&mut cache_file, bincode::config::standard())?;

            Some(stateless_input)
        } else {
            None
        }
    } else {
        None
    })
}

fn try_load_input_from_path(path: &PathBuf) -> eyre::Result<StatelessExecutorInput> {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    if ext.eq_ignore_ascii_case("json") {
        let s = std::fs::read_to_string(path)?;
        let v: serde_json::Value = serde_json::from_str(&s)?;
        let arr = v
            .get("input")
            .and_then(|v| v.as_array())
            .ok_or_else(|| eyre::eyre!("invalid JSON: missing 'input' array"))?;
        let hex_str = arr
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| eyre::eyre!("invalid JSON: 'input[0]' must be string"))?;
        let stripped = hex_str.trim_start_matches("0x");
        let mut bytes = hex::decode(stripped)?;
        if let Some(1u8) = bytes.first().copied() {
            bytes.remove(0);
        }
        if bytes.len() % 4 != 0 {
            eyre::bail!("input bytes length must be multiple of 4");
        }
        let input: StatelessExecutorInput = openvm::serde::from_slice(&bytes)
            .map_err(|e| eyre::eyre!("failed to decode input words using openvm::serde: {e:?}"))?;
        Ok(input)
    } else {
        let mut file = std::fs::File::open(path)?;
        let stateless_input: StatelessExecutorInput =
            bincode::serde::decode_from_std_read(&mut file, bincode::config::standard())?;
        Ok(stateless_input)
    }
}
