#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloy_eips::{eip7840::BlobParams, eip7892::BlobScheduleBlobParams};
use alloy_hardforks::mainnet::{MAINNET_BPO1_TIMESTAMP, MAINNET_BPO2_TIMESTAMP};
use reth_chainspec::{
    BaseFeeParams, BaseFeeParamsKind, Chain, ChainHardforks, ChainSpec, DepositContract,
    DEV_HARDFORKS,
};
use revm_primitives::{address, b256, U256};

/// Returns the [ChainSpec] for Ethereum mainnet.
/// It is much faster than using reth's MAINNET.clone()
pub fn mainnet() -> ChainSpec {
    // Spec extracted from:
    //
    // https://github.com/paradigmxyz/reth/blob/c228fe15808c3acbf18dc3af1a03ef5cbdcda07a/crates/chainspec/src/spec.rs#L35-L60
    let mut spec = ChainSpec {
        chain: Chain::mainnet(),
        // We don't need the genesis state. Using default to save cycles.
        genesis: Default::default(),
        paris_block_and_final_difficulty: Some((0, U256::ZERO)),
        hardforks: ChainHardforks::from(alloy_hardforks::EthereumHardfork::mainnet()),
        deposit_contract: Some(DepositContract::new(
            address!("00000000219ab540356cbb839cbe05303d7705fa"),
            11052984,
            b256!("649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"),
        )),
        base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
        prune_delete_limit: 20000,
        genesis_header: Default::default(),
        blob_params: BlobScheduleBlobParams::default().with_scheduled([
            (MAINNET_BPO1_TIMESTAMP, BlobParams::bpo1()),
            (MAINNET_BPO2_TIMESTAMP, BlobParams::bpo2()),
        ]),
    };
    spec.genesis.config.dao_fork_support = true;
    spec
}

/// Returns the [ChainSpec] for Reth's dev testnet.
pub fn dev() -> ChainSpec {
    // taken from:
    // https://github.com/paradigmxyz/reth/blob/c228fe15808c3acbf18dc3af1a03ef5cbdcda07a/crates/chainspec/src/spec.rs#L108-L125
    ChainSpec {
        chain: Chain::dev(),
        genesis: Default::default(),
        paris_block_and_final_difficulty: Some((0, U256::from(0))),
        hardforks: DEV_HARDFORKS.clone(),
        base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
        deposit_contract: None, // TODO: do we even have?
        ..Default::default()
    }
}
