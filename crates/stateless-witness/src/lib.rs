//! Crate providing middleware for Reth stateless [ExecutionWitness] generation and conversion to
//! the input format used by the OpenVM stateless executor. The provided functions are intended for
//! use either within the Reth SDK, as part of a Reth ExEx, or by Reth RPC clients.
use alloy_consensus::{BlockHeader as _, Header};
use alloy_rpc_types_debug::ExecutionWitness;
use bumpalo::Bump;
use itertools::Itertools;
use openvm_mpt::{resolver::MptResolver, EthereumState};
use openvm_stateless_executor::io::StatelessExecutorInput;
use reth_ethereum::{
    trie::{TrieAccount, EMPTY_ROOT_HASH},
    EthPrimitives,
};
use reth_ethereum_primitives::Block;
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_node_api::{FullNodeComponents, NodeTypes};
use reth_primitives_traits::{NodePrimitives, RecoveredBlock};
use reth_provider::{HeaderProvider, StateProviderFactory};
use reth_revm::{
    database::StateProviderDatabase,
    primitives::{keccak256, Bytes, HashMap, B256},
    state::Bytecode,
    witness::ExecutionWitnessRecord,
    State,
};
use reth_trie::{ExecutionWitnessMode, HashedPostState};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tracing::{info_span, instrument};

mod error;
mod utils;

pub use crate::error::{WitnessError, WitnessResult};
use crate::utils::time;

/// Includes the output of `debug_executionWitness` in field `execution_witness` and also other
/// block data necessary to construct the [StatelessExecutorInput].
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockExecutionWitness {
    pub execution_witness: ExecutionWitness,
    /// Parent block's state root
    pub parent_state_root: B256,
    /// The current block (which will be executed inside the client).
    pub current_block: Block,
}

#[instrument(skip_all)]
pub fn generate_stateless_input_from_witness(
    witness: BlockExecutionWitness,
) -> WitnessResult<StatelessExecutorInput> {
    let ancestor_headers = decode_ancestor_headers(&witness.execution_witness.headers)?;

    generate_stateless_input_from_witness_and_ancestor_headers(witness, ancestor_headers)
}

fn decode_ancestor_headers(headers: &[Bytes]) -> WitnessResult<Vec<Header>> {
    let mut ancestor_headers = Vec::with_capacity(headers.len());
    for header_bytes in headers {
        let sealed = Header::decode_sealed(&mut &header_bytes[..])?;
        ancestor_headers.push(sealed.into_inner());
    }
    // Ancestor headers start from most recent.
    ancestor_headers.reverse();
    Ok(ancestor_headers)
}

#[instrument(skip_all)]
pub fn generate_stateless_input_from_witness_and_ancestor_headers(
    witness: BlockExecutionWitness,
    ancestor_headers: Vec<Header>,
) -> WitnessResult<StatelessExecutorInput> {
    let ExecutionWitness { state: reth_state, codes, keys, headers: _ } = witness.execution_witness;

    let bump = Bump::new();
    let ethereum_state = time!(
        "ethereum_state_resolve",
        resolve_ethereum_state(&bump, witness.parent_state_root, reth_state, keys)
    )?;

    let bytecodes = {
        let mut bytecodes = Vec::with_capacity(codes.len());
        for code in codes {
            bytecodes.push(Bytecode::new_raw(code));
        }
        bytecodes
    };

    let parent_state_bytes = ethereum_state.encode_to_state_bytes();
    Ok(StatelessExecutorInput {
        current_block: witness.current_block,
        ancestor_headers,
        parent_state_bytes,
        bytecodes,
    })
}

/// Returns `(block_execution_witness, ancestor_headers)`. The `ancestor_headers` are serialized
/// within `block_execution_witness` and returned in deserialized form for execution.
#[instrument(skip(provider, evm_config, recovered_block))]
pub fn generate_block_execution_witness<Node>(
    provider: Node::Provider,
    evm_config: Node::Evm,
    recovered_block: RecoveredBlock<
        <<Node::Types as NodeTypes>::Primitives as NodePrimitives>::Block,
    >,
) -> WitnessResult<(BlockExecutionWitness, /* ancestor_headers */ Vec<Header>)>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = EthPrimitives>>,
{
    let number = recovered_block.number;

    let parent_hash = recovered_block.parent_hash();
    let parent_header =
        provider.header(parent_hash)?.ok_or(WitnessError::ParentBlockNotFound(parent_hash))?;
    let state_provider = {
        let sp = provider.state_by_block_hash(parent_hash)?;
        let sp_root = sp.state_root(HashedPostState::default())?;
        if sp_root != parent_header.state_root {
            return Err(WitnessError::StateProviderRootMismatch {
                actual: sp_root,
                expected: parent_header.state_root,
            });
        }
        sp
    };
    let db = StateProviderDatabase::new(&state_provider);
    let executor = evm_config.executor(db);

    let execution_witness = time!("reth_input_gen", {
        let span = info_span!("reth_input_gen");
        span.in_scope(|| -> WitnessResult<_> {
            let mut execution_witness = None;
            let _ =
                executor.execute_with_state_closure(&recovered_block, |statedb: &State<_>| {
                    execution_witness =
                        Some(ExecutionWitnessRecord::new(statedb).into_execution_witness(
                            state_provider.as_ref(),
                            &provider,
                            number,
                            ExecutionWitnessMode::Legacy,
                        ));
                })?;

            Ok(execution_witness.expect("state closure is called after successful execution")?)
        })?
    });

    let ancestor_headers = decode_ancestor_headers(&execution_witness.headers)?;

    // Sort for deterministic witness ordering.
    let ExecutionWitness { state, codes, keys, headers } = execution_witness;
    let execution_witness = ExecutionWitness {
        state: state.into_iter().sorted().collect(),
        codes: codes.into_iter().sorted().collect(),
        keys: keys.into_iter().sorted().collect(),
        headers,
    };

    Ok((
        BlockExecutionWitness {
            execution_witness,
            parent_state_root: parent_header.state_root(),
            current_block: recovered_block.into_block(),
        },
        ancestor_headers,
    ))
}

/// Resolves an [`EthereumState`] from an execution witness. All trie data is allocated in `bump`.
#[instrument(skip(bump, reth_state, keys))]
pub fn resolve_ethereum_state<'a>(
    bump: &'a Bump,
    state_root: B256,
    reth_state: Vec<Bytes>,
    keys: Vec<Bytes>,
) -> WitnessResult<EthereumState<'a>> {
    let mut node_store = Vec::with_capacity(reth_state.len());
    let mut has_state_root_node = state_root == EMPTY_ROOT_HASH;
    for node in reth_state {
        let hash = keccak256(&node);
        has_state_root_node |= hash == state_root;
        node_store.push((hash, node));
    }

    // Parent state root must be present in the witness
    if !has_state_root_node {
        return Err(WitnessError::StateRootNodeMissing(state_root));
    }

    let mpt_resolver = MptResolver::from_iter(node_store);

    let state_trie = mpt_resolver.resolve(bump, &state_root)?;
    assert_eq!(state_trie.hash(), state_root);
    tracing::debug!(state_root=%state_root, num_nodes=state_trie.num_nodes(), "resolved state trie");

    let mut storage_tries = HashMap::new();

    // Filter accounts
    for key in keys.iter().filter(|k| k.len() == 20) {
        let hashed_address = keccak256(key);
        let storage_root = state_trie
            .get_rlp::<TrieAccount>(hashed_address.as_slice())?
            .map_or(EMPTY_ROOT_HASH, |a| a.storage_root);

        let storage_trie = mpt_resolver.resolve(bump, &storage_root)?;
        assert_eq!(storage_trie.hash(), storage_root);
        tracing::debug!(
            account=%key,
            storage_root=%storage_root,
            num_nodes=storage_trie.num_nodes(),
            "resolved storage trie"
        );

        storage_tries.insert(hashed_address, storage_trie);
    }
    Ok(EthereumState::from_tries(state_trie, storage_tries, bump))
}
