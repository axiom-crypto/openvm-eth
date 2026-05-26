use reth_evm::block::BlockExecutionError;
use reth_revm::primitives::alloy_primitives::B256;
use reth_storage_errors::provider::ProviderError;

#[derive(thiserror::Error, Debug)]
pub enum WitnessError {
    #[error("parent block not found for block hash {0}")]
    ParentBlockNotFound(B256),

    #[error(
        "witness is missing the state trie root node for parent state root {0}; the witness \
         `state` and `parent_state_root` describe different snapshots (e.g. a reorg during \
         witness generation)"
    )]
    StateRootNodeMissing(B256),

    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),

    #[error("block execution error: {0}")]
    BlockExecution(#[from] BlockExecutionError),

    #[error("RLP decoding error: {0}")]
    Rlp(#[from] alloy_rlp::Error),

    #[error("MPT error: {0}")]
    Mpt(#[from] openvm_mpt::Error),
}

pub type WitnessResult<T> = Result<T, WitnessError>;
