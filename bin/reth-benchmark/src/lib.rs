#![cfg_attr(feature = "tco", allow(incomplete_features))]
#![cfg_attr(feature = "tco", feature(explicit_tail_calls))]
use std::{fs, io::Write, path::PathBuf, time::Instant};

use alloy_provider::RootProvider;
use alloy_rpc_client::RpcClient;
use alloy_transport::layers::RetryBackoffLayer;
use clap::Parser;
use openvm_circuit::arch::{instructions::exe::VmExe, *};
use openvm_rpc_proxy::{RpcExecutor, DEFAULT_PREIMAGE_CACHE_NIBBLES};
use openvm_sdk_config::{SdkVmConfig, TranspilerConfig};
use openvm_stark_sdk::{
    bench::run_with_metric_collection,
    config::baby_bear_poseidon2::{D_EF, F},
    openvm_stark_backend::{
        air_builders::symbolic::{SymbolicExpressionDag, SymbolicExpressionNode},
        codec::Encode,
        keygen::types::MultiStarkProvingKey,
        p3_field::PrimeCharacteristicRing,
    },
};
use openvm_stateless_executor::{io::StatelessExecutorInput, CHAIN_ID_ETH_MAINNET};
use openvm_transpiler::{elf::Elf, openvm_platform::memory::MEM_SIZE, FromElf};
use sdk_v2::{
    config::{
        default_app_params, default_compression_params, default_internal_params,
        default_leaf_params, AggregationSystemParams, AppConfig, DEFAULT_APP_LOG_BLOWUP,
        DEFAULT_APP_L_SKIP, DEFAULT_COMPRESSION_LOG_BLOWUP, DEFAULT_INTERNAL_LOG_BLOWUP,
        DEFAULT_LEAF_LOG_BLOWUP,
    },
    fs::write_object_to_file,
    Sdk, SC,
};
use tracing::{info, info_span};
use verify_stark::{
    verify_vm_stark_proof_decoded,
    vk::{write_vk_to_file, NonRootStarkVerifyingKey},
};

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

pub async fn run_reth_benchmark(args: HostArgs, openvm_client_eth_elf: &[u8]) -> eyre::Result<()> {
    // Initialize the environment variables.
    dotenv::dotenv().ok();

    let app_log_blowup = args.benchmark.app_log_blowup;
    let app_l_skip = args.benchmark.app_l_skip;
    let leaf_log_blowup = args.benchmark.leaf_log_blowup;
    let internal_log_blowup = args.benchmark.internal_log_blowup;

    #[cfg(feature = "cuda")]
    println!("CUDA Backend Enabled");

    let mut vm_config = reth_vm_config();
    if let Some(max_trace_height) = args.benchmark.max_segment_length {
        vm_config.as_mut().segmentation_config.limits.set_max_trace_height(max_trace_height);
    }
    if let Some(max_memory) = args.benchmark.segment_max_memory {
        vm_config.as_mut().segmentation_config.limits.set_max_memory(max_memory);
    }

    vm_config.as_mut().segmentation_config.main_cell_weight = 1 + (1 << app_log_blowup);
    vm_config.as_mut().segmentation_config.main_cell_secondary_weight =
        (D_EF * 2) as f64 / (1 << app_l_skip) as f64; // folding trace to MLE in EF, with rotation

    for (air_idx, air) in VmCircuitConfig::<SC>::create_airs(&vm_config)?.into_airs().enumerate() {
        tracing::debug!("air_idx={air_idx} | {}", air.name());
    }

    if args.app_pk_path.is_some() != args.agg_pk_path.is_some() {
        eyre::bail!("app_pk_path and agg_pk_path must be provided together");
    }
    if let Some(_app_pk_path) = args.app_pk_path {
        todo!();
    }

    let transpiler = vm_config.transpiler().clone();

    let app_n_stack = DEFAULT_LOG_STACKED_HEIGHT - app_l_skip;
    let app_params = default_app_params(app_log_blowup, app_l_skip, app_n_stack);

    // Setup: this can all be done once before receiving proof input
    let app_config = AppConfig::new(vm_config, app_params);
    let agg_params = AggregationSystemParams {
        leaf: default_leaf_params(leaf_log_blowup),
        internal: default_internal_params(internal_log_blowup),
        compression: Some(default_compression_params(DEFAULT_COMPRESSION_LOG_BLOWUP)),
    };
    let sdk = Sdk::new(app_config, agg_params)?;

    if matches!(args.mode, BenchMode::DumpAirStats) {
        dump_air_stats(&sdk, &args.air_stats_path)?;
        return Ok(());
    }

    let elf = Elf::decode(openvm_client_eth_elf, MEM_SIZE as u32)?;
    let exe = VmExe::from_elf(elf, transpiler)?;

    if matches!(args.mode, BenchMode::GenerateVmVkey) {
        let prover = sdk.prover(exe)?;
        let vk = NonRootStarkVerifyingKey {
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

    // Parse the command line arguments.
    let stateless_input_from_path =
        args.input_path.as_ref().map(|path| try_load_input_from_path(path).unwrap());

    let stateless_input = if let Some(stateless_input_from_path) = stateless_input_from_path {
        stateless_input_from_path
    } else {
        let provider_config = args.provider.into_provider().await?;
        match provider_config.chain_id {
            #[allow(non_snake_case)]
            CHAIN_ID_ETH_MAINNET => (),
            _ => {
                eyre::bail!("unknown chain ID: {}", provider_config.chain_id);
            }
        };
        let stateless_input_from_cache = try_load_input_from_cache(
            args.cache_dir.as_ref(),
            provider_config.chain_id,
            block_number,
        )?;

        match (stateless_input_from_cache, provider_config.rpc_url) {
            (Some(stateless_input_from_cache), _) => stateless_input_from_cache,
            (None, Some(rpc_url)) => {
                // Cache not found but we have RPC
                // Setup the provider.
                let client =
                    RpcClient::builder().layer(RetryBackoffLayer::new(5, 1000, 100)).http(rpc_url);
                let provider = RootProvider::new(client);

                // Setup the host executor.
                let rpc_executor = RpcExecutor::new(provider, args.preimage_cache_nibbles);

                // Execute the host.
                let stateless_input =
                    rpc_executor.execute(block_number).await.expect("failed to execute host");

                if let Some(cache_dir) = args.cache_dir {
                    let input_folder =
                        cache_dir.join(format!("input/{}", provider_config.chain_id));
                    if !input_folder.exists() {
                        std::fs::create_dir_all(&input_folder)?;
                    }

                    let input_path = input_folder.join(format!("{}.bin", block_number));
                    let mut cache_file = std::fs::File::create(input_path)?;

                    bincode::serde::encode_into_std_write(
                        &stateless_input,
                        &mut cache_file,
                        bincode::config::standard(),
                    )?;
                }

                stateless_input
            }
            (None, None) => {
                eyre::bail!("cache not found and RPC URL not provided")
            }
        }
    };

    let encoded_stateless_input: Vec<F> = {
        let words = openvm_v2::serde::to_vec(&stateless_input)?;
        words.into_iter().flat_map(|w| w.to_le_bytes()).map(F::from_u8).collect()
    };

    let stdin = vec![encoded_stateless_input].into();

    run_with_metric_collection("OUTPUT_PATH", move || {
        info_span!("reth-block", block_number = block_number).in_scope(|| -> eyre::Result<()> {
            match args.mode {
                BenchMode::ProveApp => {
                    let mut prover = sdk.app_prover(exe)?;
                    prover.set_program_name(program_name);
                    let app_proof = prover.prove(stdin)?;
                    let (_, app_vk) = sdk.app_keygen();
                    verify_segments(&prover.vm().engine, &app_vk.vk, &app_proof.per_segment)?;
                }
                BenchMode::ProveStark => {
                    let (proof, baseline) = sdk.prove(exe, stdin)?;
                    let vk = NonRootStarkVerifyingKey { mvk: (*sdk.agg_vk()).clone(), baseline };
                    let encoded = proof.encode_to_vec()?;
                    let compressed = zstd::encode_all(&encoded[..], 19)?;
                    tracing::info!(
                        "Proof Size (bytes): {}, Compressed Size: {}",
                        encoded.len(),
                        compressed.len()
                    );
                    verify_vm_stark_proof_decoded(&vk, &proof)?;
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

                    info!("✅ Keygen completed successfully!");
                    info!("  App PK: {}", app_pk_path.display());
                    info!("  App VK: {}", app_vk_path.display());
                    info!("  Agg PK: {}", agg_pk_path.display());
                }
                _ => {
                    // This case is handled earlier and should not reach here
                    todo!();
                }
            }

            Ok(())
        })
    })?;
    Ok(())
}

fn dump_air_stats(sdk: &Sdk, output_path: &PathBuf) -> eyre::Result<()> {
    let (app_pk, _app_vk) = sdk.app_keygen();
    let mut file = fs::File::create(output_path)?;
    writeln!(
        file,
        "circuit,air_idx,air_name,num_monomials,monomial_ms,dag_size,max_rule_length,num_constraints"
    )?;

    dump_pk_stats("app", &app_pk.app_vm_pk.vm_pk, &mut file)?;

    let agg_pk = sdk.agg_pk();
    dump_pk_stats("agg_leaf", &agg_pk.leaf_pk, &mut file)?;

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
        let input: StatelessExecutorInput = openvm_v2::serde::from_slice(&bytes)
            .map_err(|e| eyre::eyre!("failed to decode input words using openvm::serde: {e:?}"))?;
        Ok(input)
    } else {
        let mut file = std::fs::File::open(path)?;
        let stateless_input: StatelessExecutorInput =
            bincode::serde::decode_from_std_read(&mut file, bincode::config::standard())?;
        Ok(stateless_input)
    }
}
