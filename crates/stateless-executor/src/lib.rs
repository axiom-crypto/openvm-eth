#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod error;
/// Client program input data types.
pub mod io;

use alloc::{sync::Arc, vec, vec::Vec};
use core::fmt::Debug;

use alloy_consensus::{proofs::calculate_receipt_root, Header, TxReceipt};
use alloy_primitives::Bloom;
use openvm_chainspec::{dev, mainnet};
use reth_consensus::{Consensus, HeaderValidator};
use reth_ethereum_consensus::{validate_block_post_execution, EthBeaconConsensus};
use reth_evm::execute::{BasicBlockExecutor, Executor};
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::ExecutionOutcome;
use reth_primitives_traits::{block::Block as _, SealedHeader};
use reth_revm::db::CacheDB;

use bumpalo::Bump;

use crate::{
    error::StatelessExecutorError,
    io::{StatelessExecutorInput, StatelessExecutorInputWithState},
};

/// Chain ID for Ethereum Mainnet.
pub const CHAIN_ID_ETH_MAINNET: u64 = 0x1;

/// Initial capacity in bytes for the bump arena backing [`EthereumState`].
pub const BUMP_AREA_SIZE: usize = 1000 * 1000;

/// An executor that executes a block inside a zkVM.
#[derive(Debug, Clone, Default)]
pub struct StatelessExecutor;

/// EVM chain variants that implement different execution/validation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainVariant {
    Mainnet,
    Dev,
}

impl StatelessExecutor {
    pub fn execute(
        &self,
        chain_variant: ChainVariant,
        pre_input: StatelessExecutorInput,
    ) -> Result<Header, StatelessExecutorError> {
        let bump = Bump::with_capacity(BUMP_AREA_SIZE);
        let mut input = StatelessExecutorInputWithState::build(&pre_input, &bump)?;

        // Install OpenVM crypto optimizations
        #[cfg(feature = "openvm")]
        {
            openvm_revm_crypto::install_openvm_crypto()
                .expect("failed to install OpenVM crypto provider");
        }

        // Initialize the witnessed database with verified storage proofs.
        let witness_db = input.witness_db()?;
        let cache_db = CacheDB::new(&witness_db);

        // Execute the block.
        let spec = Arc::new(match chain_variant {
            ChainVariant::Mainnet => mainnet(),
            ChainVariant::Dev => dev(),
        });
        // Recover senders
        let current_block = input
            .input
            .current_block
            .clone()
            .try_into_recovered()
            .map_err(|err| StatelessExecutorError::BlockSenderRecoveryError(err.into()))?;

        // validate the block pre-execution
        {
            let consensus = EthBeaconConsensus::new(spec.clone());

            consensus
                .validate_header(current_block.sealed_header())
                .map_err(StatelessExecutorError::InvalidHeader)?;

            // The timestamp selects the fork rules, so it must be checked against the parent
            // before execution. `witness_db` has verified that the parent hashes to `parent_hash`.
            let parent =
                SealedHeader::new(input.parent_header().clone(), current_block.parent_hash);
            consensus
                .validate_header_against_parent(current_block.sealed_header(), &parent)
                .map_err(StatelessExecutorError::InvalidHeaderAgainstParent)?;

            consensus
                .validate_block_pre_execution(&current_block)
                .map_err(StatelessExecutorError::InvalidBlockPreExecution)?;
        };

        let block_executor = BasicBlockExecutor::new(EthEvmConfig::new(spec.clone()), cache_db);
        let executor_output = block_executor.execute(&current_block)?;

        // Pre-compute receipts root and logs bloom to avoid duplicate computation in validation.
        let receipts_with_bloom =
            executor_output.receipts.iter().map(TxReceipt::with_bloom_ref).collect::<Vec<_>>();
        let receipts_root = calculate_receipt_root(&receipts_with_bloom);
        let logs_bloom =
            receipts_with_bloom.iter().fold(Bloom::ZERO, |bloom, r| bloom | r.bloom_ref());

        // Validate the block post execution.
        validate_block_post_execution(
            &current_block,
            &spec,
            &executor_output,
            Some((receipts_root, logs_bloom)),
            None,
        )
        .map_err(StatelessExecutorError::InvalidBlockPostExecution)?;

        // Convert the output to an execution outcome.
        let executor_outcome = ExecutionOutcome::new(
            executor_output.state,
            vec![executor_output.result.receipts],
            input.input.current_block.header.number,
            vec![executor_output.result.requests],
        );

        drop(witness_db);

        // Verify the state root.
        let state_root = {
            input.state.update_from_bundle_state(&executor_outcome.bundle)?;
            input.state.state_trie.hash()
        };

        if state_root != input.input.current_block.state_root {
            return Err(StatelessExecutorError::StateRootMismatch {
                actual: state_root,
                expected: input.input.current_block.state_root,
            });
        }

        // Derive the block header.
        //
        // Note: the receipts root and gas used are verified by `validate_block_post_execution`.
        let mut header = input.input.current_block.header.clone();
        header.parent_hash = input.parent_header().hash_slow();
        header.ommers_hash = input.input.current_block.body.calculate_ommers_root();
        header.state_root = input.input.current_block.state_root;
        header.transactions_root = input.input.current_block.transactions_root;
        header.receipts_root = input.input.current_block.header.receipts_root;
        header.withdrawals_root = input.input.current_block.body.calculate_withdrawals_root();
        header.logs_bloom = logs_bloom;
        header.requests_hash = input.input.current_block.requests_hash;

        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::StatelessExecutorInput;
    use alloy_consensus::BlockBody;
    use alloy_eips::{eip1559::BaseFeeParams, eip7685::EMPTY_REQUESTS_HASH};
    use alloy_primitives::B256;
    use alloy_rlp::EMPTY_STRING_CODE;
    use alloy_trie::EMPTY_ROOT_HASH;
    use openvm_mpt::EthereumStateBytes;
    use reth_ethereum_primitives::Block;

    #[test]
    fn rejects_header_invalid_against_parent() {
        // An empty post-Osaka mainnet block on an empty state.
        let parent = Header {
            number: 24_000_000,
            timestamp: 1_770_000_000,
            gas_limit: 60_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            requests_hash: Some(EMPTY_REQUESTS_HASH),
            ..Default::default()
        };
        // Executes an empty child of `parent` that differs from it only in base fee.
        let execute_child = |base_fee| {
            let child = Header {
                number: parent.number + 1,
                parent_hash: parent.hash_slow(),
                timestamp: parent.timestamp + 12,
                base_fee_per_gas: Some(base_fee),
                ..parent.clone()
            };
            let body = BlockBody { withdrawals: Some(Default::default()), ..Default::default() };
            let input = StatelessExecutorInput {
                current_block: Block::new(child, body),
                ancestor_headers: vec![parent.clone()],
                parent_state_bytes: EthereumStateBytes {
                    state_trie: (1, vec![EMPTY_STRING_CODE, 0, 0, 0].into()), // empty trie
                    storage_tries: vec![],
                },
                bytecodes: vec![],
            };
            StatelessExecutor.execute(ChainVariant::Mainnet, input)
        };

        let base_fee = parent.next_block_base_fee(BaseFeeParams::ethereum()).unwrap();
        execute_child(base_fee).expect("child with the correct base fee is valid");
        let forged = execute_child(0);
        assert!(
            matches!(forged, Err(StatelessExecutorError::InvalidHeaderAgainstParent(_))),
            "{forged:?}"
        );
    }
}
