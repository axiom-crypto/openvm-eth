use std::path::PathBuf;

use alloy_provider::{network::Ethereum, Provider as _, RootProvider};
use clap::Args;
use openvm_rpc_proxy::DEFAULT_PREIMAGE_CACHE_NIBBLES;
use url::Url;

#[derive(Debug, Clone, Args)]
pub struct RethInputSource {
    /// The block number of the block to execute.
    #[clap(long)]
    pub block_number: Option<u64>,

    /// The rpc url used to fetch data about the block. If not provided, will use the
    /// RPC_{chain_id} env var.
    #[clap(long)]
    pub rpc_url: Option<Url>,

    /// The chain ID. If not provided, requires the rpc_url argument to be provided.
    #[clap(long)]
    pub chain_id: Option<u64>,

    /// Optional path to the directory containing cached client input. A new cache file will be
    /// created from RPC data if it doesn't already exist.
    #[clap(long)]
    pub cache_dir: Option<PathBuf>,

    /// Optional path to the input file.
    #[arg(long)]
    pub input_path: Option<PathBuf>,

    /// The number of nibbles to precompute for the preimage lookup table.
    /// Higher values increase startup time but reduce RPC calls for missing storage keys.
    ///
    /// Warning: This is a form of grinding, so higher values will be slower on machines with many
    /// CPU cores.
    #[clap(long, default_value_t = DEFAULT_PREIMAGE_CACHE_NIBBLES, value_parser = clap::value_parser!(u8).range(..=8))]
    pub preimage_cache_nibbles: u8,
}

pub(super) struct ProviderConfig {
    pub rpc_url: Option<Url>,
    pub chain_id: u64,
}

impl RethInputSource {
    pub fn new(block_number: u64) -> Self {
        Self {
            block_number: Some(block_number),
            rpc_url: None,
            chain_id: None,
            cache_dir: None,
            input_path: None,
            preimage_cache_nibbles: DEFAULT_PREIMAGE_CACHE_NIBBLES,
        }
    }

    pub(super) async fn resolve_provider(&self) -> eyre::Result<ProviderConfig> {
        // We don't need RPC when using cache with known chain ID, so we leave it as `Option<Url>`
        // here and decide on whether to panic later.
        //
        // On the other hand chain ID is always needed.
        let (rpc_url, chain_id) = match (self.rpc_url.as_ref(), self.chain_id) {
            (Some(rpc_url), Some(chain_id)) => (Some(rpc_url.clone()), chain_id),
            (None, Some(chain_id)) => {
                match std::env::var(format!("RPC_{chain_id}")) {
                    Ok(rpc_env_var) => {
                        // We don't always need it but if the value exists it has to be valid.
                        (Some(Url::parse(rpc_env_var.as_str()).expect("invalid rpc url")), chain_id)
                    }
                    Err(_) => {
                        // Not having RPC is okay because we know chain ID.
                        (None, chain_id)
                    }
                }
            }
            (Some(rpc_url), None) => {
                // We can find out about chain ID from RPC.
                let provider = RootProvider::<Ethereum>::new_http(rpc_url.clone());
                let chain_id = provider.get_chain_id().await?;

                (Some(rpc_url.clone()), chain_id)
            }
            (None, None) => {
                eyre::bail!("either --rpc-url or --chain-id must be used")
            }
        };

        Ok(ProviderConfig { rpc_url, chain_id })
    }
}
