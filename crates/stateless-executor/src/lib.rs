pub mod error;
/// Client program input data types.
pub mod io;

use std::{fmt::Debug, sync::Arc};

use alloy_consensus::{proofs::calculate_receipt_root, Header, TxReceipt};
use alloy_primitives::Bloom;
use openvm_chainspec::{dev, mainnet};
use reth_consensus::{Consensus, HeaderValidator};
use reth_ethereum_consensus::{validate_block_post_execution, EthBeaconConsensus};
use reth_evm::execute::{BasicBlockExecutor, Executor};
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::ExecutionOutcome;
use reth_primitives_traits::block::Block as _;
use reth_revm::db::CacheDB;

use crate::{
    error::StatelessExecutorError,
    io::{StatelessExecutorInput, StatelessExecutorInputWithState},
};

/// Chain ID for Ethereum Mainnet.
pub const CHAIN_ID_ETH_MAINNET: u64 = 0x1;

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
        let mut input = StatelessExecutorInputWithState::build(pre_input)?;

        // Install OpenVM crypto optimizations
        #[cfg(feature = "openvm")]
        {
            println!("Installing OpenVM crypto optimizations");
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
