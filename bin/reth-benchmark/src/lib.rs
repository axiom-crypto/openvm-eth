#![cfg_attr(feature = "tco", allow(incomplete_features))]
#![cfg_attr(feature = "tco", feature(explicit_tail_calls))]
use alloy_primitives::hex::ToHexExt;
use alloy_provider::RootProvider;
use alloy_rpc_client::RpcClient;
use alloy_transport::layers::RetryBackoffLayer;
use clap::Parser;
use openvm_benchmarks_prove::util::BenchmarkCli;
use openvm_circuit::{
    arch::*,
    openvm_stark_sdk::{
        bench::run_with_metric_collection, openvm_stark_backend::p3_field::PrimeField32,
    },
};
pub use openvm_native_circuit::NativeConfig;
use openvm_stateless_executor::{
    io::StatelessExecutorInput, ChainVariant, StatelessExecutor, CHAIN_ID_ETH_MAINNET,
};

use openvm_rpc_proxy::{RpcExecutor, DEFAULT_PREIMAGE_CACHE_NIBBLES};
use openvm_sdk::{
    config::{AppConfig, SdkVmBuilder, SdkVmConfig},
    fs::read_object_from_file,
    keygen::{AggProvingKey, AppProvingKey},
    prover::verify_app_proof,
    types::VersionedVmStarkProof,
    DefaultStarkEngine, Sdk, StdIn,
};
use openvm_stark_sdk::engine::StarkFriEngine;
use openvm_transpiler::{elf::Elf, openvm_platform::memory::MEM_SIZE};
pub use reth_ethereum_primitives as reth_primitives;
use serde_json::json;
use std::{fs, path::PathBuf};
use tracing::{info, info_span};

mod cli;

use cli::ProviderArgs;

/// Enum representing the execution mode of the host executable.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum BenchMode {
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
    /// Generate input file only.
    MakeInput,
    /// Generate fixtures file for futher benchmarking.
    GenerateFixtures,
}

impl std::fmt::Display for BenchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExecuteHost => write!(f, "execute_host"),
            Self::Execute => write!(f, "execute"),
            Self::ExecuteMetered => write!(f, "execute_metered"),
            Self::ProveApp => write!(f, "prove_app"),
            Self::ProveStark => write!(f, "prove_stark"),
            #[cfg(feature = "evm-verify")]
            Self::ProveEvm => write!(f, "prove_evm"),
            Self::MakeInput => write!(f, "make_input"),
            Self::GenerateFixtures => write!(f, "generate_fixtures"),
        }
    }
}

/// The arguments for the host executable.
#[derive(Debug, Parser)]
pub struct HostArgs {
    /// The block number of the block to execute.
    #[clap(long)]
    block_number: u64,
    #[clap(flatten)]
    provider: ProviderArgs,

    /// The execution mode.
    #[clap(long, value_enum)]
    mode: BenchMode,

    /// Optional path to the directory containing cached stateless input. A new cache file will be
    /// created from RPC data if it doesn't already exist.
    #[clap(long)]
    cache_dir: Option<PathBuf>,
    /// The path to the CSV file containing the execution data.
    #[clap(long, default_value = "report.csv")]
    report_path: PathBuf,

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
    #[arg(long)]
    pub output_dir: Option<PathBuf>,

    /// If specified, loads the app proving key from this path.
    #[arg(long)]
    pub app_pk_path: Option<PathBuf>,

    /// If specified, loads the agg proving key from this path.
    #[arg(long)]
    pub agg_pk_path: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    pub skip_comparison: bool,

    /// The number of nibbles to precompute for the preimage lookup table.
    /// Higher values increase startup time but reduce RPC calls for missing storage keys.
    #[clap(long, default_value_t = DEFAULT_PREIMAGE_CACHE_NIBBLES, value_parser = clap::value_parser!(u8).range(..=8))]
    pub preimage_cache_nibbles: u8,
}

pub fn reth_vm_config(app_log_blowup: usize) -> SdkVmConfig {
    let mut config =
        toml::from_str::<AppConfig<SdkVmConfig>>(include_str!("../../stateless-guest/openvm.toml"))
            .unwrap()
            .app_vm_config;
    config.system.config = config
        .system
        .config
        .with_max_constraint_degree((1 << app_log_blowup) + 1)
        .with_public_values(32);
    config
}

pub const RETH_DEFAULT_APP_LOG_BLOWUP: usize = 1;
pub const RETH_DEFAULT_LEAF_LOG_BLOWUP: usize = 1;

pub async fn run_reth_benchmark(args: HostArgs, openvm_client_eth_elf: &[u8]) -> eyre::Result<()> {
    // Initialize the environment variables.
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let mut args = args;

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
            args.block_number,
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
                    rpc_executor.execute(args.block_number).await.expect("failed to execute host");

                if let Some(cache_dir) = args.cache_dir {
                    let input_folder =
                        cache_dir.join(format!("input/{}", provider_config.chain_id));
                    if !input_folder.exists() {
                        std::fs::create_dir_all(&input_folder)?;
                    }

                    let input_path = input_folder.join(format!("{}.bin", args.block_number));
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

    let mut stdin = StdIn::default();
    stdin.write(&stateless_input);
    info!("input loaded");

    if matches!(args.mode, BenchMode::MakeInput) {
        let words: Vec<u32> = openvm::serde::to_vec(&stateless_input).unwrap();
        let bytes: Vec<u8> = words.into_iter().flat_map(|w| w.to_le_bytes()).collect();
        let hex_bytes = String::from("0x01") + &hex::encode(&bytes);
        let input = json!({
            "input": [hex_bytes]
        });
        let input = serde_json::to_string(&input).unwrap();
        fs::write(args.generated_input_path.unwrap(), input)?;
        return Ok(());
    }

    let app_log_blowup = args.benchmark.app_log_blowup.unwrap_or(RETH_DEFAULT_APP_LOG_BLOWUP);
    args.benchmark.app_log_blowup = Some(app_log_blowup);
    let leaf_log_blowup = args.benchmark.leaf_log_blowup.unwrap_or(RETH_DEFAULT_LEAF_LOG_BLOWUP);
    args.benchmark.leaf_log_blowup = Some(leaf_log_blowup);

    #[cfg(feature = "cuda")]
    println!("CUDA Backend Enabled");

    let vm_config = reth_vm_config(app_log_blowup);
    let app_config = args.benchmark.app_config(vm_config.clone());
    let sdk = Sdk::new(app_config.clone())?
        .with_agg_config(args.benchmark.agg_config())
        .with_agg_tree_config(args.benchmark.agg_tree_config);

    if args.app_pk_path.is_some() != args.agg_pk_path.is_some() {
        eyre::bail!("app_pk_path and agg_pk_path must be provided together");
    }
    if let Some(app_pk_path) = args.app_pk_path {
        let app_pk: AppProvingKey<SdkVmConfig> = read_object_from_file(app_pk_path)?;
        let agg_pk_path = args.agg_pk_path.unwrap();
        let agg_pk: AggProvingKey = read_object_from_file(agg_pk_path)?;
        let vm_config_loaded = app_pk.app_vm_pk.vm_config.clone();
        let vm_config_json =
            serde_json::to_value(&vm_config).expect("failed to serialize vm_config to json value");
        let vm_config_loaded_json = serde_json::to_value(&vm_config_loaded)
            .expect("failed to serialize vm_config_loaded to json value");
        assert_eq!(
            vm_config_json, vm_config_loaded_json,
            "vm_config mismatch between runtime config and proving key"
        );
        sdk.set_app_pk(app_pk).map_err(|_| eyre::eyre!("failed to set app pk"))?;
        sdk.set_agg_pk(agg_pk).map_err(|_| eyre::eyre!("failed to set agg pk"))?;
    }

    let elf = Elf::decode(openvm_client_eth_elf, MEM_SIZE as u32)?;
    let exe = sdk.convert_to_exe(elf.clone())?;

    let program_name = format!("reth.{}.block_{}", args.mode, args.block_number);
    // NOTE: args.benchmark.app_config resets SegmentationLimits if max_segment_length is set
    args.benchmark.max_segment_length = None;

    run_with_metric_collection("OUTPUT_PATH", || {
        info_span!("reth-block", block_number = args.block_number).in_scope(
            || -> eyre::Result<()> {
                // Run host execution for comparison
                if !args.skip_comparison {
                    let block_hash = info_span!("host.execute", group = program_name).in_scope(
                        || -> eyre::Result<_> {
                            let executor = StatelessExecutor;
                            // Create a child span to get the group label propagated
                            let header = info_span!("client.execute").in_scope(|| {
                                executor.execute(ChainVariant::Mainnet, stateless_input.clone())
                            })?;
                            let block_hash =
                                info_span!("header.hash_slow").in_scope(|| header.hash_slow());
                            Ok(block_hash)
                        },
                    )?;
                    println!("block_hash (execute-host): {}", ToHexExt::encode_hex(&block_hash));
                }

                // For ExecuteHost mode, only do host execution
                if matches!(args.mode, BenchMode::ExecuteHost) {
                    return Ok(());
                }

                // Execute for benchmarking:
                if !args.skip_comparison {
                    let pvs = info_span!("sdk.execute", group = program_name)
                        .in_scope(|| sdk.execute(elf.clone(), stdin.clone()))?;
                    let block_hash = pvs;
                    println!("block_hash (execute): {}", ToHexExt::encode_hex(&block_hash));
                }

                match args.mode {
                    BenchMode::Execute => {}
                    BenchMode::ExecuteMetered => {
                        let engine = DefaultStarkEngine::new(app_config.app_fri_params.fri_params);
                        let (vm, _) = VirtualMachine::new_with_keygen(
                            engine,
                            SdkVmBuilder,
                            app_config.app_vm_config,
                        )?;
                        let executor_idx_to_air_idx = vm.executor_idx_to_air_idx();
                        let interpreter =
                            vm.executor().metered_instance(&exe, &executor_idx_to_air_idx)?;
                        let metered_ctx = vm.build_metered_ctx(&exe);
                        let (segments, _) =
                            info_span!("interpreter.execute_metered", group = program_name)
                                .in_scope(|| interpreter.execute_metered(stdin, metered_ctx))?;
                        println!("Number of segments: {}", segments.len());
                    }
                    BenchMode::ProveApp => {
                        let mut prover = sdk.app_prover(elf)?.with_program_name(program_name);
                        let (_, app_vk) = sdk.app_keygen();
                        let proof = prover.prove(stdin)?;
                        verify_app_proof(&app_vk, &proof)?;
                    }
                    BenchMode::ProveStark => {
                        let mut prover = sdk.prover(elf)?.with_program_name(program_name);
                        let proof = prover.prove(stdin)?;
                        let block_hash = proof
                            .user_public_values
                            .iter()
                            .map(|pv| pv.as_canonical_u32() as u8)
                            .collect::<Vec<u8>>();
                        println!("block_hash (prove_stark): {}", ToHexExt::encode_hex(&block_hash));

                        if let Some(output_dir) = args.output_dir.as_ref() {
                            let versioned_proof = VersionedVmStarkProof::new(proof)?;
                            let json = serde_json::to_vec_pretty(&versioned_proof)?;
                            fs::write(output_dir.join("proof.json"), json)?;
                            println!("wrote proof json to {}", output_dir.display());
                        }
                    }
                    #[cfg(feature = "evm-verify")]
                    BenchMode::ProveEvm => {
                        let mut prover = sdk.evm_prover(elf)?.with_program_name(program_name);
                        let halo2_pk = sdk.halo2_pk();
                        tracing::info!(
                            "halo2_outer_k: {}",
                            halo2_pk.verifier.pinning.metadata.config_params.k
                        );
                        tracing::info!(
                            "halo2_wrapper_k: {}",
                            halo2_pk.wrapper.pinning.metadata.config_params.k
                        );
                        let proof = prover.prove_evm(stdin)?;
                        let block_hash = &proof.user_public_values;
                        println!("block_hash (prove_evm): {}", ToHexExt::encode_hex(block_hash));
                    }
                    BenchMode::GenerateFixtures => {
                        let mut prover = sdk.prover(elf)?.with_program_name(program_name);
                        let app_proof = prover.app_prover.prove(stdin)?;
                        let leaf_proofs = prover.agg_prover.generate_leaf_proofs(&app_proof)?;
                        let fixture_path = args.fixtures_path.unwrap();

                        let mut app_proof_path = fixture_path.clone();
                        app_proof_path.push("app_proof.bitcode");
                        fs::write(app_proof_path, bitcode::serialize(&app_proof)?)?;

                        let mut leaf_proofs_path = fixture_path.clone();
                        leaf_proofs_path.push("leaf_proofs.bitcode");
                        fs::write(leaf_proofs_path, bitcode::serialize(&leaf_proofs)?)?;

                        let mut app_pk_path = fixture_path.clone();
                        app_pk_path.push("app_pk.bitcode");
                        fs::write(app_pk_path, bitcode::serialize(sdk.app_pk())?)?;

                        let mut agg_pk_path = fixture_path.clone();
                        agg_pk_path.push("agg_pk.bitcode");
                        fs::write(agg_pk_path, bitcode::serialize(sdk.agg_pk())?)?;
                    }
                    _ => {
                        // This case is handled earlier and should not reach here
                        unreachable!();
                    }
                }

                Ok(())
            },
        )
    })?;
    Ok(())
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
