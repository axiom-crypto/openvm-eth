//! Crate providing middleware for Reth stateless [ExecutionWitness] generation and conversion to
//! the input format used by the OpenVM stateless executor. The provided functions are intended for
//! use either within the Reth SDK, as part of a Reth ExEx, or by Reth RPC clients.
use alloy_rlp::Encodable;
use alloy_rpc_types_debug::ExecutionWitness;
use itertools::Itertools;
use openvm_mpt::{resolver::MptResolver, EthereumState};
use openvm_stateless_executor::io::StatelessExecutorInput;
use reth_ethereum::{
    trie::{TrieAccount, EMPTY_ROOT_HASH},
    EthPrimitives,
};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_node_api::{FullNodeComponents, NodeTypes};
use reth_primitives::{Block, Header, RecoveredBlock, TransactionSigned};
use reth_primitives_traits::NodePrimitives;
use reth_provider::{BlockReaderIdExt, HeaderProvider, StateProviderFactory};
use reth_revm::{
    database::StateProviderDatabase,
    primitives::{alloy_primitives::BlockNumber, keccak256, Bytes, HashMap, B256},
    state::Bytecode,
    witness::ExecutionWitnessRecord,
    State,
};
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
    #[serde_as(
        as = "reth_primitives_traits::serde_bincode_compat::Block<'_, TransactionSigned, Header>"
    )]
    pub current_block: Block<TransactionSigned, Header>,
}

#[instrument(skip_all)]
pub fn generate_stateless_input_from_witness(
    witness: BlockExecutionWitness,
) -> WitnessResult<StatelessExecutorInput> {
    let ExecutionWitness { state: reth_state, codes, keys, headers } = witness.execution_witness;

    let ethereum_state = time!(
        "ethereum_state_resolve",
        resolve_ethereum_state(witness.parent_state_root, reth_state, keys)
    )?;

    let bytecodes = {
        let mut bytecodes = Vec::with_capacity(codes.len());
        for code in codes {
            bytecodes.push(Bytecode::new_raw(code));
        }
        bytecodes
    };

    let parent_state_bytes = ethereum_state.encode_to_state_bytes();
    let mut ancestor_headers = Vec::with_capacity(headers.len());
    for header_bytes in headers {
        let sealed = Header::decode_sealed(&mut &header_bytes[..])?;
        ancestor_headers.push(sealed.into_inner());
    }
    // Ancestor headers start from most recent
    ancestor_headers.reverse();

    Ok(StatelessExecutorInput {
        current_block: witness.current_block,
        ancestor_headers,
        parent_state_bytes,
        bytecodes,
    })
}

/// Returns `(block_execution_witness, ancestor_headers)`. The `ancestor_headers` are serialized
/// within `block_execution_witness` but we return it in deserialized form to avoid another
/// deserialization for performance.
#[instrument(skip(provider, evm_config, recovered_block))]
pub fn generate_block_execution_witness<Node>(
    provider: Node::Provider,
    evm_config: Node::Evm,
    number: BlockNumber,
    recovered_block: RecoveredBlock<
        <<Node::Types as NodeTypes>::Primitives as NodePrimitives>::Block,
    >,
) -> WitnessResult<(BlockExecutionWitness, /* ancestor_headers */ Vec<Header>)>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = EthPrimitives>>,
{
    let parent_block_number = number - 1;

    let parent_block = provider
        .block_by_id(parent_block_number.into())?
        .ok_or(WitnessError::ParentBlockNotFound(parent_block_number))?;
    let state_provider = provider.state_by_block_id(parent_block_number.into())?;
    let db = StateProviderDatabase::new(&state_provider);
    let executor = evm_config.executor(db);
    let mut witness_record = ExecutionWitnessRecord::default();

    let (reth_state, codes, keys, lowest_block_number) = time!("reth_input_gen", {
        let span = info_span!("reth_input_gen");
        span.in_scope(|| -> WitnessResult<_> {
            let _ =
                executor.execute_with_state_closure(&recovered_block, |statedb: &State<_>| {
                    witness_record.record_executed_state(statedb);
                })?;

            let ExecutionWitnessRecord { hashed_state, codes, keys, lowest_block_number } =
                witness_record;
            let reth_state = state_provider.witness(Default::default(), hashed_state)?;
            Ok((reth_state, codes, keys, lowest_block_number))
        })?
    });

    let (serialized_headers, mut ancestor_headers): (Vec<_>, Vec<_>) = {
        let smallest = match lowest_block_number {
            Some(smallest) => smallest,
            None => {
                // Return only the parent header, if there were no calls to the
                // BLOCKHASH opcode.
                number.saturating_sub(1)
            }
        };
        let range = smallest..number;
        provider
            .headers_range(range)?
            .into_iter()
            .map(|header| {
                let mut serialized_header = Vec::new();
                header.encode(&mut serialized_header);
                (serialized_header.into(), header)
            })
            .unzip()
    };
    // Ancestor headers start from most recent
    ancestor_headers.reverse();

    // Sort for deterministic witness ordering.
    let execution_witness = ExecutionWitness {
        state: reth_state.into_iter().sorted().collect(),
        codes: codes.into_iter().sorted().collect(),
        keys: keys.into_iter().sorted().collect(),
        headers: serialized_headers,
    };

    Ok((
        BlockExecutionWitness {
            execution_witness,
            parent_state_root: parent_block.state_root,
            current_block: recovered_block.into_block(),
        },
        ancestor_headers,
    ))
}

#[instrument(skip(reth_state, keys))]
pub fn resolve_ethereum_state(
    state_root: B256,
    reth_state: Vec<Bytes>,
    keys: Vec<Bytes>,
) -> WitnessResult<EthereumState> {
    let mut node_store = Vec::with_capacity(reth_state.len());
    for node in reth_state {
        node_store.push((keccak256(&node), node));
    }
    let mpt_resolver = MptResolver::from_iter(node_store);

    let state_trie = mpt_resolver.resolve(&state_root)?;
    assert_eq!(state_trie.hash(), state_root);
    tracing::debug!(state_root=%state_root, num_nodes=state_trie.num_nodes(), "resolved state trie");

    let mut storage_tries = HashMap::new();

    // Filter accounts
    for key in keys.iter().filter(|k| k.len() == 20) {
        let hashed_address = keccak256(key);
        let storage_root = state_trie
            .get_rlp::<TrieAccount>(hashed_address.as_slice())?
            .map_or(EMPTY_ROOT_HASH, |a| a.storage_root);

        let storage_trie = mpt_resolver.resolve(&storage_root)?;
        assert_eq!(storage_trie.hash(), storage_root);
        tracing::debug!(
            account=%key,
            storage_root=%storage_root,
            num_nodes=storage_trie.num_nodes(),
            "resolved storage trie"
        );

        storage_tries.insert(hashed_address, storage_trie);
    }
    Ok(EthereumState::from_tries(state_trie, storage_tries))
}
