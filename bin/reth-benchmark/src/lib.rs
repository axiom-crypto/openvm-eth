#![cfg_attr(feature = "tco", allow(incomplete_features))]
#![cfg_attr(feature = "tco", feature(explicit_tail_calls))]
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

use alloy_provider::RootProvider;
use alloy_rpc_client::RpcClient;
use alloy_transport::layers::RetryBackoffLayer;
use clap::Parser;
use eyre::Result;
use openvm_circuit::arch::{
    execution_mode::metered::segment_ctx::DEFAULT_MAX_MEMORY, instructions::exe::VmExe,
    verify_segments, VmCircuitConfig,
};
use openvm_rpc_proxy::RpcExecutor;
use openvm_sdk::{
    config::{
        AggregationSystemParams, AggregationTreeConfig, AppConfig, DEFAULT_APP_LOG_BLOWUP,
        DEFAULT_APP_L_SKIP, DEFAULT_INTERNAL_LOG_BLOWUP, DEFAULT_LEAF_LOG_BLOWUP,
        DEFAULT_ROOT_LOG_BLOWUP,
    },
    fs::{read_object_from_file, write_object_to_file},
    Sdk, StdIn, SC,
};
use openvm_sdk_config::{SdkVmConfig, TranspilerConfig};
#[cfg(feature = "evm-verify")]
use openvm_stark_sdk::config::root_params_with_100_bits_security;
#[cfg(feature = "evm-verify")]
use openvm_stark_sdk::openvm_stark_backend::codec::Decode;
use openvm_stark_sdk::{
    bench::run_with_metric_collection,
    config::{
        app_params_with_100_bits_security, baby_bear_poseidon2::F,
        internal_params_with_100_bits_security, leaf_params_with_100_bits_security,
        MAX_APP_LOG_STACKED_HEIGHT, SECURITY_BITS_TARGET,
    },
    openvm_stark_backend::{
        air_builders::symbolic::{SymbolicExpressionDag, SymbolicExpressionNode},
        codec::Encode,
        keygen::types::MultiStarkProvingKey,
        SystemParams,
    },
};
use openvm_stateless_executor::{
    io::StatelessExecutorInput, ChainVariant, StatelessExecutor, CHAIN_ID_ETH_MAINNET,
};
use openvm_transpiler::{elf::Elf, openvm_platform::memory::MEM_SIZE, FromElf};
use openvm_verify_stark_host::{
    verify_vm_stark_proof_decoded,
    vk::{write_vk_to_file, VmStarkVerifyingKey},
};
pub use reth_ethereum_primitives as reth_primitives;
use tracing::{info, info_span};

const VM_MAX_CONSTRAINT_DEGREE: usize = 4;

mod cli;
mod soundness;
pub use cli::RethInputSource;

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
    /// Generate sequence of app proofs for continuation segments.
    ProveApp,
    /// Generate a full end-to-end STARK proof with aggregation.
    ProveStark,
    /// Generate the root STARK proof without halo2 wrapping.
    #[cfg(feature = "evm-verify")]
    ProveRoot,
    /// Generate a full end-to-end halo2 proof for EVM verifier.
    #[cfg(feature = "evm-verify")]
    ProveEvm,
    /// Generate proving and verifying keys for app and aggregation circuits.
    Keygen,
    /// Generate VM verifying key baseline artifact and write it to a local file.
    GenerateVmVkey,
    /// Dump per-AIR statistics and exit.
    DumpAirStats,
    /// Print the computed per-component security bits of the app and aggregation layers to stdout
    /// and exit.
    Soundness,
    /// Print the `soundcalc`-compatible config (TOML) for the app and aggregation layers to stdout
    /// and exit. Feed this to github.com/ethereum/soundcalc to compute the authoritative bits.
    Soundcalc,
}

impl std::fmt::Display for BenchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MakeInput => write!(f, "make_input"),
            Self::ExecuteHost => write!(f, "execute_host"),
            Self::Execute => write!(f, "execute"),
            Self::ExecuteMetered => write!(f, "execute_metered"),
            Self::ProveApp => write!(f, "prove_app"),
            Self::ProveStark => write!(f, "prove_stark"),
            #[cfg(feature = "evm-verify")]
            Self::ProveRoot => write!(f, "prove_root"),
            #[cfg(feature = "evm-verify")]
            Self::ProveEvm => write!(f, "prove_evm"),
            Self::Keygen => write!(f, "keygen"),
            Self::GenerateVmVkey => write!(f, "generate_vm_vkey"),
            Self::DumpAirStats => write!(f, "dump_air_stats"),
            Self::Soundness => write!(f, "soundness"),
            Self::Soundcalc => write!(f, "soundcalc"),
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

    /// Root level log blowup
    #[arg(long, default_value_t = DEFAULT_ROOT_LOG_BLOWUP)]
    pub root_log_blowup: usize,

    #[command(flatten)]
    pub agg_tree_config: AggregationTreeConfig,

    /// Estimated proving-memory cap per VM segment, in bytes
    #[arg(long, default_value_t = DEFAULT_MAX_MEMORY)]
    pub segment_max_memory: usize,
}

/// The arguments for the host executable.
#[derive(Debug, Parser)]
pub struct HostArgs {
    /// The execution mode.
    #[clap(long, value_enum)]
    mode: BenchMode,

    /// The path to the CSV file containing the execution data.
    #[clap(long, default_value = "report.csv")]
    report_path: PathBuf,
    /// The path to the CSV file containing per-AIR statistics.
    #[clap(long, default_value = "air_stats.csv")]
    air_stats_path: PathBuf,

    #[clap(flatten)]
    benchmark: BenchmarkCli,

    #[clap(flatten)]
    input: RethInputSource,

    /// Path to write the fixtures to. Only needed for mode=make_input
    #[arg(long)]
    pub fixtures_path: Option<PathBuf>,

    /// In make_input mode, this path is where the input JSON is written.
    #[arg(long)]
    pub generated_input_path: Option<PathBuf>,

    /// If specificed, the proof and other output is written to this dir.
    #[arg(long, default_value = "output")]
    pub output_dir: PathBuf,

    /// Optional directory used by prove-root to cache the intermediate stark proof. If set,
    /// the stark proof is written to (or loaded from) <proof_cache>/stark.bitcode. If not
    /// set, no proof caching is performed.
    #[arg(long)]
    pub proof_cache: Option<PathBuf>,

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

pub struct RethWorkload {
    pub exe: VmExe<F>,
    pub stdin: StdIn,
}

impl std::fmt::Debug for RethWorkload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RethWorkload")
            .field("exe", &self.exe)
            .field("stdin_buffer_len", &self.stdin.buffer.len())
            .field("stdin_deferrals_len", &self.stdin.deferrals.len())
            .finish()
    }
}

pub fn build_reth_workload(
    vm_config: &SdkVmConfig,
    stateless_input: &StatelessExecutorInput,
    openvm_client_eth_elf: &[u8],
) -> Result<RethWorkload> {
    let exe = build_reth_exe(vm_config, openvm_client_eth_elf)?;
    let encoded_stateless_input: Vec<u8> = {
        let words = openvm::serde::to_vec(stateless_input)?;
        words.into_iter().flat_map(|w| w.to_le_bytes()).collect()
    };
    let stdin = vec![encoded_stateless_input].into();
    Ok(RethWorkload { exe, stdin })
}

pub fn build_reth_exe(vm_config: &SdkVmConfig, openvm_client_eth_elf: &[u8]) -> Result<VmExe<F>> {
    let transpiler = vm_config.transpiler().clone();
    let elf = Elf::decode(openvm_client_eth_elf, MEM_SIZE as u32)?;
    Ok(VmExe::from_elf(elf, transpiler)?)
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

pub async fn load_reth_input(source: &RethInputSource) -> Result<StatelessExecutorInput> {
    let block_number = source
        .block_number
        .ok_or_else(|| eyre::eyre!("--block-number is required to load reth input"))?;

    if let Some(path) = &source.input_path {
        return try_load_input_from_path(path);
    }

    let provider_config = source.resolve_provider().await?;

    match provider_config.chain_id {
        #[allow(non_snake_case)]
        CHAIN_ID_ETH_MAINNET => (),
        _ => {
            eyre::bail!("unknown chain ID: {}", provider_config.chain_id);
        }
    };

    if let Some(stateless_input) = try_load_input_from_cache(
        source.cache_dir.as_deref(),
        provider_config.chain_id,
        block_number,
    )? {
        return Ok(stateless_input);
    }

    let Some(rpc_url) = provider_config.rpc_url else {
        eyre::bail!("cache not found and RPC URL not provided");
    };

    let client = RpcClient::builder().layer(RetryBackoffLayer::new(5, 1000, 100)).http(rpc_url);
    let provider = RootProvider::new(client);
    let rpc_executor = RpcExecutor::new(provider, source.preimage_cache_nibbles);
    let stateless_input = rpc_executor.execute(block_number).await?;

    if let Some(cache_dir) = &source.cache_dir {
        write_input_to_cache(cache_dir, provider_config.chain_id, block_number, &stateless_input)?;
    }

    Ok(stateless_input)
}

pub async fn run_reth_benchmark(args: HostArgs, openvm_client_eth_elf: &[u8]) -> Result<()> {
    // Initialize the environment variables.
    dotenv::dotenv().ok();

    #[cfg(feature = "cuda")]
    eprintln!("CUDA Backend Enabled");

    let mut vm_config = reth_vm_config();
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
    #[cfg(feature = "evm-verify")]
    let root_params =
        override_log_blowup(root_params_with_100_bits_security(), args.benchmark.root_log_blowup)?;

    // Resolve key paths: explicit flag wins; otherwise fall back to <output_dir>/<name>.pk
    // if the file exists. The chain agg->app and root->agg->app is enforced by the builder,
    // so skip later stages whenever an earlier stage isn't available.
    let app_pk_path = args.app_pk_path.clone().or_else(|| {
        let p = args.output_dir.join("app.pk");
        p.exists().then_some(p)
    });
    let agg_pk_path = args.agg_pk_path.clone().or_else(|| {
        let p = args.output_dir.join("agg.pk");
        p.exists().then_some(p)
    });
    // Whether we're running off persistent on-disk keys (vs. generating them on the fly). The
    // soundness modes prefer persisted keys but fall back to in-memory keygen, noting it on stderr.
    let (app_pk_loaded, agg_pk_loaded) = (app_pk_path.is_some(), agg_pk_path.is_some());

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

    #[cfg(feature = "evm-verify")]
    {
        let root_pk_path = args.output_dir.join("root.pk");
        if root_pk_path.exists() {
            info!("Loading root proving key from {}", root_pk_path.display());
            let root_pk = read_object_from_file(&root_pk_path)?;
            sdk_builder = sdk_builder.root_pk(root_pk);
        } else {
            sdk_builder = sdk_builder.root_params(root_params);
        }
    }

    let sdk = sdk_builder.build()?;

    if matches!(args.mode, BenchMode::DumpAirStats) {
        dump_air_stats(&sdk, &args.air_stats_path)?;
        return Ok(());
    }

    if matches!(args.mode, BenchMode::Soundness | BenchMode::Soundcalc) {
        use soundness::{security_bits_report, Layer, SoundcalcConfig};

        // Prefer persisted keys; fall back to in-memory keygen when they're absent. Note it on
        // stderr since keygen is slow and the report then reflects the current params rather than
        // a saved key set (stdout stays clean for the report itself).
        let missing: Vec<&str> =
            [(!app_pk_loaded).then_some("app.pk"), (!agg_pk_loaded).then_some("agg.pk")]
                .into_iter()
                .flatten()
                .collect();
        if !missing.is_empty() {
            eprintln!(
                "{} not found; generating proving keys in memory (run `--mode keygen` to persist)",
                missing.join(" and "),
            );
        }

        // The full proof stack: app, then the leaf / internal-for-leaf / internal-recursive
        // aggregation layers. Each layer's parameters come from the loaded (or freshly generated)
        // proving keys, so the output reflects this prover's exact production parameters.
        let agg_pk = sdk.agg_pk();
        let layers: Vec<Layer> = vec![
            ("app".to_string(), sdk.app_vk().vk),
            ("leaf".to_string(), agg_pk.prefix.leaf.get_vk()),
            ("internal_for_leaf".to_string(), agg_pk.prefix.internal_for_leaf.get_vk()),
            ("internal_recursive".to_string(), agg_pk.internal_recursive.get_vk()),
        ];

        match args.mode {
            BenchMode::Soundness => println!("{}", security_bits_report(&layers)),
            BenchMode::Soundcalc => {
                let config =
                    SoundcalcConfig::from_layers(openvm_sdk::OPENVM_VERSION.to_string(), &layers);
                println!("{}", toml::to_string(&config)?);
            }
            _ => unreachable!(),
        }
        return Ok(());
    }

    if matches!(args.mode, BenchMode::GenerateVmVkey) {
        let exe = build_reth_exe(&vm_config, openvm_client_eth_elf)?;
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
        .input
        .block_number
        .ok_or_else(|| eyre::eyre!("--block-number is required for mode {}", args.mode))?;

    let program_name = format!("reth.{}.block_{}", args.mode, block_number);

    let stateless_input = load_reth_input(&args.input).await?;

    // MakeInput: encode stateless_input as JSON and write to disk.
    if matches!(args.mode, BenchMode::MakeInput) {
        let words = openvm::serde::to_vec(&stateless_input)?;
        let bytes: Vec<u8> = words.into_iter().flat_map(|w: u64| w.to_le_bytes()).collect();
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
        let executor = StatelessExecutor;
        let start = Instant::now();
        let header = info_span!("host.execute", group = program_name).in_scope(|| {
            info_span!("client.execute")
                .in_scope(|| executor.execute(ChainVariant::Mainnet, stateless_input))
        })?;
        let elapsed = start.elapsed();
        let block_hash = header.hash_slow();
        info!("Host execution: {:.6}s, block hash: {}", elapsed.as_secs_f64(), block_hash);
        println!("BENCH_HOST_NS={}", elapsed.as_nanos());
        println!("BENCH_BLOCK_HASH={block_hash}");
        return Ok(());
    }

    let RethWorkload { exe, stdin } =
        build_reth_workload(&vm_config, &stateless_input, openvm_client_eth_elf)?;

    run_with_metric_collection("OUTPUT_PATH", move || {
        info_span!("reth-block", block_number = block_number).in_scope(|| -> Result<()> {
            match args.mode {
                BenchMode::Execute => {
                    let compiled = sdk.compile(exe)?;
                    let public_values = sdk.execute(&compiled, stdin)?;
                    let block_hash = hex::encode(&public_values);
                    info!("Execute completed, block hash: {}", block_hash);
                    println!("BENCH_BLOCK_HASH={block_hash}");
                }
                BenchMode::ExecuteMetered => {
                    let compiled = sdk.compile_metered(exe)?;
                    let (public_values, _) = sdk.execute_metered(&compiled, stdin)?;
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
                BenchMode::ProveRoot => {
                    let mut evm_prover = sdk.evm_prover_without_halo2(exe)?;
                    evm_prover.stark_prover.app_prover.set_program_name(&program_name);

                    let proof_file = args.proof_cache.as_ref().map(|d| d.join("stark.bitcode"));
                    let cached = proof_file.as_ref().filter(|p| p.exists());

                    let _root_proof = if let Some(proof_file) = cached {
                        info!("Loading cached stark proof from: {}", proof_file.display());
                        let stark_proof_file =
                            fs::File::open(proof_file).expect("failed to open stark file");
                        let mut stark_proof_reader = std::io::BufReader::new(stark_proof_file);
                        let (stark_proof, mut internal_meta) =
                            Decode::decode(&mut stark_proof_reader)
                                .expect("failed stark proof deserialization");
                        evm_prover
                            .prove_root_from_vm_stark_proof(stark_proof, &mut internal_meta)
                            .expect("failed to prove root from cached stark proof")
                    } else {
                        if let Some(p) = &proof_file {
                            info!("No cached stark proof at {}; generating fresh", p.display());
                        }
                        let (stark_proof, metadata) = evm_prover
                            .stark_prover
                            .prove(stdin, &[])
                            .expect("failed to prove stark");
                        let root_proof = evm_prover
                            .prove_root_from_vm_stark_proof(
                                stark_proof.clone(),
                                &mut metadata.clone(),
                            )
                            .expect("failed to prove root");
                        if let Some(proof_file) = &proof_file {
                            if let Some(parent) = proof_file.parent() {
                                fs::create_dir_all(parent)?;
                            }
                            info!("Writing stark proof cache to: {}", proof_file.display());
                            let stark_proof_file =
                                fs::File::create(proof_file).expect("failed to create stark file");
                            let mut stark_proof_writer = std::io::BufWriter::new(stark_proof_file);
                            (stark_proof, metadata)
                                .encode(&mut stark_proof_writer)
                                .expect("failed to write stark proof");
                        }
                        root_proof
                    };
                }
                #[cfg(feature = "evm-verify")]
                BenchMode::ProveEvm => {
                    let mut evm_prover = sdk.evm_prover(exe)?;
                    evm_prover.stark_prover.app_prover.set_program_name(&program_name);
                    let proof = evm_prover.prove_evm(stdin, &[])?;
                    let block_hash = &proof.user_public_values;
                    println!("block_hash (prove_evm): {}", hex::encode(block_hash));
                    let openvm_verifier = sdk.generate_halo2_verifier_solidity()?;
                    let gas_cost = Sdk::verify_evm_halo2_proof(&openvm_verifier, proof, None)?;
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

                    #[cfg(feature = "evm-verify")]
                    let root_pk_path = args.output_dir.join("root.pk");

                    info!("Generating app proving key...");
                    let (app_pk, app_vk) = sdk.app_keygen();

                    info!("Saving app proving key to: {}", app_pk_path.display());
                    write_object_to_file(&app_pk_path, &app_pk)?;

                    info!("Saving app verifying key to: {}", app_vk_path.display());
                    write_object_to_file(&app_vk_path, &app_vk)?;

                    #[cfg(feature = "evm-verify")]
                    {
                        info!("Generating root proving key...");
                        let root_pk = sdk.root_pk();
                        info!("Saving root proving key to: {}", root_pk_path.display());
                        write_object_to_file(&root_pk_path, &root_pk)?;
                    }

                    info!("Generating aggregation proving key...");
                    let agg_pk = sdk.agg_pk();

                    info!("Saving agg proving key to: {}", agg_pk_path.display());
                    write_object_to_file(&agg_pk_path, &agg_pk)?;

                    info!("Keygen completed successfully!");
                    info!("  App PK: {}", app_pk_path.display());
                    info!("  App VK: {}", app_vk_path.display());
                    info!("  Agg PK: {}", agg_pk_path.display());
                    #[cfg(feature = "evm-verify")]
                    info!("  Root PK: {}", root_pk_path.display());
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

fn dump_air_stats(sdk: &Sdk, output_path: &PathBuf) -> Result<()> {
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

fn dump_pk_stats(label: &str, pk: &MultiStarkProvingKey<SC>, file: &mut fs::File) -> Result<()> {
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
    cache_dir: Option<&Path>,
    chain_id: u64,
    block_number: u64,
) -> Result<Option<StatelessExecutorInput>> {
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

fn write_input_to_cache(
    cache_dir: &Path,
    chain_id: u64,
    block_number: u64,
    stateless_input: &StatelessExecutorInput,
) -> Result<()> {
    let input_folder = cache_dir.join(format!("input/{chain_id}"));
    fs::create_dir_all(&input_folder)?;

    let input_path = input_folder.join(format!("{block_number}.bin"));
    let mut cache_file = fs::File::create(input_path)?;
    bincode::serde::encode_into_std_write(
        stateless_input,
        &mut cache_file,
        bincode::config::standard(),
    )?;
    Ok(())
}

fn try_load_input_from_path(path: &Path) -> Result<StatelessExecutorInput> {
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
