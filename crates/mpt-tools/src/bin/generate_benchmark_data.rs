use alloy_provider::RootProvider;
use alloy_rpc_client::RpcClient;
use bincode::config::standard;
use openvm_rpc_proxy::{upstream_http_client, RpcExecutor, DEFAULT_PREIMAGE_CACHE_NIBBLES};
use std::env;
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};
use url::Url;

fn print_usage() {
    println!("Usage: cargo run --bin generate_benchmark_data");
    println!("       BLOCK=18884864 cargo run --bin generate_benchmark_data");
    println!();
    println!("Environment:");
    println!("  BLOCK    Block number to fetch (default: 23992138)");
    println!("  RPC_1    Ethereum RPC endpoint (required)");
    println!();
    println!("Output: <block_number>.bin");
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args: Vec<String> = env::args().collect();

    // Check for help
    if args.len() > 1 && (args[1] == "--help" || args[1] == "-h") {
        print_usage();
        return Ok(());
    }

    // Get block number from environment
    let block_number = env::var("BLOCK")
        .unwrap_or_else(|_| "23992138".to_string())
        .parse::<u64>()
        .unwrap_or_else(|_| panic!("Invalid BLOCK number"));

    let output_file = format!("{}.bin", block_number);

    println!("Benchmark Data Generator");
    println!("Block number: {}", block_number);
    println!("Output file: {}", output_file);
    println!();

    // Initialize the environment variables.
    dotenv::dotenv().ok();

    // Initialize the logger.
    let _ = tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init();

    // Setup the provider.
    let env_var_key = "RPC_1";
    let rpc_url = Url::parse(
        std::env::var(env_var_key).expect("RPC_1 environment variable not set").as_str(),
    )?;
    let provider =
        RootProvider::new(RpcClient::new_http_with_client(upstream_http_client()?, rpc_url));

    // Setup the host executor.
    let rpc_executor = RpcExecutor::new(provider, DEFAULT_PREIMAGE_CACHE_NIBBLES);

    println!("Fetching block data from RPC...");
    // Execute the host.
    let stateless_input = rpc_executor.execute(block_number).await?;

    println!("Serializing stateless input...");
    // Save the input to a buffer.
    let bincode_config = standard();
    let buffer = bincode::serde::encode_to_vec(&stateless_input, bincode_config)?;

    // Save the buffer to a file for benchmarking
    std::fs::write(&output_file, &buffer)?;
    println!("Successfully generated benchmark data:");
    println!("  File: {}", output_file);
    println!("  Size: {} bytes", buffer.len());
    println!();
    println!("Next steps:");
    println!("  BLOCK={} cargo run --bin mpt_profiler", block_number);
    println!("  BLOCK={} cargo bench", block_number);

    Ok(())
}
