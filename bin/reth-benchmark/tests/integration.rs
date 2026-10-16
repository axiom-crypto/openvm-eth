use alloy_provider::RootProvider;
use alloy_rpc_client::RpcClient;
use bincode::config::standard;
use openvm_rpc_proxy::{upstream_http_client, RpcExecutor, DEFAULT_PREIMAGE_CACHE_NIBBLES};
use openvm_stateless_executor::{io::StatelessExecutorInput, ChainVariant, StatelessExecutor};
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};
use url::Url;

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_ethereum() {
    let env_var_key = "RPC_1";
    let block_number = 23992138;

    // Initialize the environment variables.
    dotenv::dotenv().ok();

    // Initialize the logger.
    let _ = tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init();

    // Setup the provider.
    let rpc_url =
        Url::parse(std::env::var(env_var_key).unwrap().as_str()).expect("invalid rpc url");
    let provider = RootProvider::new(RpcClient::new_http_with_client(
        upstream_http_client().unwrap(),
        rpc_url,
    ));

    // Setup the host executor.
    let rpc_executor = RpcExecutor::new(provider, DEFAULT_PREIMAGE_CACHE_NIBBLES);

    // Execute the host.
    let stateless_input = rpc_executor.execute(block_number).await.expect("failed to execute host");

    // Setup the stateless executor.
    let stateless_executor = StatelessExecutor;

    // Test serialization/deserialization round-trip
    let bincode_config = standard();
    let buffer = bincode::serde::encode_to_vec(&stateless_input, bincode_config).unwrap();
    let (deserialized_input, _): (StatelessExecutorInput, _) =
        bincode::serde::decode_from_slice(&buffer, bincode_config).unwrap();

    // Execute with the stateless input
    stateless_executor
        .execute(ChainVariant::Mainnet, stateless_input)
        .expect("failed to execute client");

    // Execute the client with the deserialized input to test round-trip
    stateless_executor
        .execute(ChainVariant::Mainnet, deserialized_input)
        .expect("failed to execute client with deserialized input");
}
