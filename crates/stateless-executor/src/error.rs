use alloy_consensus::crypto::RecoveryError;
use openvm_mpt::witness::WitnessError;
use reth_consensus::ConsensusError;
use reth_evm::block::BlockExecutionError;
use revm_primitives::B256;

#[derive(thiserror::Error, Debug)]
pub enum StatelessExecutorError {
    #[error("parent state root mismatch: got {actual}, expected {expected}")]
    ParentStateRootMismatch { actual: B256, expected: B256 },

    #[error("parent storage root mismatch on hashed account {hashed_account}: got {actual}, expected {expected}")]
    ParentStorageRootMismatch { hashed_account: B256, actual: B256, expected: B256 },

    #[error(transparent)]
    Witness(#[from] WitnessError),

    #[error("failed to recover block sender: {0}")]
    BlockSenderRecoveryError(#[from] RecoveryError),

    #[error("block header validation failed: {0}")]
    InvalidHeader(ConsensusError),

    #[error("block pre-execution validation failed: {0}")]
    InvalidBlockPreExecution(ConsensusError),

    #[error("block post-execution validation failed: {0}")]
    InvalidBlockPostExecution(ConsensusError),

    #[error("block execution failed: {0}")]
    BlockExecutionError(#[from] BlockExecutionError),

    #[error("state root mismatch: got {actual}, expected {expected}")]
    StateRootMismatch { actual: B256, expected: B256 },

    #[error("MPT error: {0}")]
    MptError(#[from] openvm_mpt::Error),
}
