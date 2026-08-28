//! Generates the Zilkworm (eth-act) guest-input ingredients for a mainnet
//! block: a `debug_executionWitness`-style witness JSON (built through the
//! same preflight pipeline the Reth benchmark uses) and a payload JSON with
//! the raw block data. Both files are consumed by zilkworm-stateless's
//! `conformance reth` subcommand, which assembles the SSZ `StatelessInput`.

use std::{fs, path::PathBuf, sync::Arc};

use alloy::eips::eip2718::Encodable2718;
use alloy_consensus::{transaction::Transaction as _, TxEnvelope};
use alloy_provider::{network::Ethereum, Provider, RootProvider};
use alloy_rpc_types::BlockNumberOrTag;
use clap::Parser;
use eyre::OptionExt;
use openvm_rpc_proxy::{execution_witness, PreimageLookup, DEFAULT_PREIMAGE_CACHE_NIBBLES};
use reth_chainspec::MAINNET;
use reth_evm_ethereum::EthEvmConfig;
use serde_json::json;

#[derive(Parser, Debug)]
struct Args {
    /// The RPC URL used to fetch block data and build the witness.
    #[clap(long, env = "RPC_1")]
    rpc_url: url::Url,

    /// The block number to generate input for.
    #[clap(long)]
    block_number: u64,

    /// Output directory for payload.json / witness.json.
    #[clap(long, default_value = ".")]
    out_dir: PathBuf,

    /// Number of nibbles to precompute for the preimage lookup table.
    #[clap(long, default_value_t = DEFAULT_PREIMAGE_CACHE_NIBBLES, value_parser = clap::value_parser!(u8).range(..=8))]
    preimage_cache_nibbles: u8,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let provider: RootProvider<Ethereum> = RootProvider::new_http(args.rpc_url.clone());
    let block_id = BlockNumberOrTag::Number(args.block_number);

    // Witness via the same preflight pipeline the Reth benchmark uses; the
    // result has the debug_executionWitness wire shape (state/codes/keys/
    // headers hex arrays) that zilkworm's `conformance reth` ingests.
    let evm_config = Arc::new(EthEvmConfig::ethereum(MAINNET.clone()));
    let lookup = Arc::new(PreimageLookup::new(args.preimage_cache_nibbles));
    let witness = execution_witness(evm_config, &provider, block_id, &lookup).await?;

    let block =
        provider.get_block_by_number(block_id).full().await?.ok_or_eyre("block not found")?;
    let header = &block.header;

    // Raw 2718-encoded transactions in payload order, and the concatenated
    // blob versioned hashes (newPayload's versioned_hashes parameter).
    let mut transactions = Vec::new();
    let mut versioned_hashes = Vec::new();
    for tx in block.transactions.clone().into_transactions() {
        let envelope = TxEnvelope::from(tx);
        if let Some(hashes) = envelope.blob_versioned_hashes() {
            versioned_hashes.extend(hashes.iter().map(|h| format!("{h:#x}")));
        }
        transactions.push(format!("0x{}", hex_encode(envelope.encoded_2718())));
    }

    let withdrawals = block
        .withdrawals
        .as_ref()
        .map(|ws| {
            ws.iter()
                .map(|w| {
                    json!({
                        "index": w.index,
                        "validatorIndex": w.validator_index,
                        "address": format!("{:#x}", w.address),
                        "amount": w.amount,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let payload = json!({
        "parentHash": format!("{:#x}", header.parent_hash),
        "feeRecipient": format!("{:#x}", header.beneficiary),
        "stateRoot": format!("{:#x}", header.state_root),
        "receiptsRoot": format!("{:#x}", header.receipts_root),
        "logsBloom": format!("{:#x}", header.logs_bloom),
        "prevRandao": format!("{:#x}", header.mix_hash),
        "blockNumber": header.number,
        "gasLimit": header.gas_limit,
        "gasUsed": header.gas_used,
        "timestamp": header.timestamp,
        "extraData": format!("{:#x}", header.extra_data),
        "baseFeePerGas": format!("{:#x}", header.base_fee_per_gas.ok_or_eyre("missing base fee")?),
        "blockHash": format!("{:#x}", header.hash),
        "transactions": transactions,
        "withdrawals": withdrawals,
        "blobGasUsed": header.blob_gas_used.ok_or_eyre("missing blobGasUsed")?,
        "excessBlobGas": header.excess_blob_gas.ok_or_eyre("missing excessBlobGas")?,
        "versionedHashes": versioned_hashes,
        "parentBeaconBlockRoot": format!("{:#x}", header.parent_beacon_block_root.ok_or_eyre("missing parentBeaconBlockRoot")?),
    });

    fs::create_dir_all(&args.out_dir)?;
    let payload_path = args.out_dir.join("payload.json");
    let witness_path = args.out_dir.join("witness.json");
    fs::write(&payload_path, serde_json::to_string(&payload)?)?;
    fs::write(&witness_path, serde_json::to_string(&witness)?)?;
    println!("payload: {}", payload_path.display());
    println!("witness: {}", witness_path.display());
    Ok(())
}

fn hex_encode(bytes: Vec<u8>) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}
