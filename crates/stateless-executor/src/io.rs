use std::iter::once;

use crate::error::StatelessExecutorError;
use alloy_consensus::Header;
use alloy_rlp::{Decodable, Encodable};
use alloy_trie::{TrieAccount, EMPTY_ROOT_HASH};
use bumpalo::Bump;
use openvm_mpt::{EthereumState, EthereumStateBytes, Mpt};
// `WitnessDb` and `WitnessInput` now live in `openvm-mpt` (behind its `witness` feature) so they
// can be reused without copying. Re-exported here to preserve the `io::{WitnessDb, WitnessInput}`
// path.
pub use openvm_mpt::witness::{WitnessDb, WitnessInput};
use reth_ethereum_primitives::Block;
use revm::state::Bytecode;
use revm_primitives::{map::DefaultHashBuilder, HashMap, B256};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// The input for the client to execute a block and fully verify the STF (state transition
/// function).
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessExecutorInput {
    /// The current block (which will be executed inside the client).
    #[serde_as(as = "serde_bincode_compat::Block")]
    pub current_block: Block,
    /// The previous block headers starting from the most recent. There must be at least one header
    /// to provide the parent state root.
    #[serde_as(as = "Vec<alloy_consensus::serde_bincode_compat::Header>")]
    pub ancestor_headers: Vec<Header>,
    /// Network state as of the parent block.
    pub parent_state_bytes: EthereumStateBytes,
    /// Account bytecodes.
    pub bytecodes: Vec<Bytecode>,
}

pub mod serde_bincode_compat {
    use super::*;
    use serde::{de::Error as _, Deserializer, Serializer};
    use serde_with::{DeserializeAs, SerializeAs};

    /// Bincode-compatible block serde implementation.
    ///
    /// Alloy's default block serde can emit sequences without known lengths for transaction
    /// envelopes. Bincode rejects those, so cache the block as its canonical RLP bytes instead.
    #[derive(Debug)]
    pub struct Block;

    impl SerializeAs<super::Block> for Block {
        fn serialize_as<S>(source: &super::Block, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = Vec::with_capacity(source.length());
            source.encode(&mut bytes);
            bytes.serialize(serializer)
        }
    }

    impl<'de> DeserializeAs<'de, super::Block> for Block {
        fn deserialize_as<D>(deserializer: D) -> Result<super::Block, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let mut buf = bytes.as_slice();
            let block = <super::Block as Decodable>::decode(&mut buf).map_err(D::Error::custom)?;
            if !buf.is_empty() {
                return Err(D::Error::custom("trailing bytes in RLP block"));
            }
            Ok(block)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockBody, Signed, TxLegacy};
    use alloy_primitives::Signature;
    use reth_ethereum_primitives::TransactionSigned;

    fn encode_block(block: &Block) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(block.length());
        block.encode(&mut bytes);
        bytes
    }

    fn input_with_block(block: Block) -> StatelessExecutorInput {
        StatelessExecutorInput {
            current_block: block,
            ancestor_headers: vec![Header::default()],
            parent_state_bytes: EthereumStateBytes {
                state_trie: (0, Default::default()),
                storage_tries: vec![],
            },
            bytecodes: vec![],
        }
    }

    #[test]
    fn input_bincode_roundtrips_with_transactions() {
        let transaction = TransactionSigned::Legacy(Signed::new_unhashed(
            TxLegacy::default(),
            Signature::test_signature(),
        ));
        let block = Block::new(
            Header::default(),
            BlockBody { transactions: vec![transaction], ommers: vec![], withdrawals: None },
        );
        let expected_rlp = encode_block(&block);

        let encoded =
            bincode::serde::encode_to_vec(input_with_block(block), bincode::config::standard())
                .expect("input should encode with bincode");
        let (decoded, _): (StatelessExecutorInput, _) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard())
                .expect("input should decode with bincode");

        assert_eq!(encode_block(&decoded.current_block), expected_rlp);
    }
}

#[derive(Debug, Clone)]
pub struct StatelessExecutorInputWithState<'a> {
    pub input: &'a StatelessExecutorInput,
    pub state: EthereumState<'a>,
}

impl<'a> StatelessExecutorInputWithState<'a> {
    /// Parses `input.parent_state_bytes` into `EthereumState` and verifies state and storage
    /// roots. All trie data is allocated in `bump`; [`BUMP_AREA_SIZE`] is a reasonable initial
    /// capacity for it.
    pub fn build(
        input: &'a StatelessExecutorInput,
        bump: &'a Bump,
    ) -> Result<Self, StatelessExecutorError> {
        let state = {
            let (state_num_nodes, state_bytes) = &input.parent_state_bytes.state_trie;
            let state_trie = Mpt::decode_trie(bump, &mut state_bytes.as_ref(), *state_num_nodes)?;
            if state_trie.hash() != input.ancestor_headers[0].state_root {
                return Err(StatelessExecutorError::ParentStateRootMismatch {
                    actual: state_trie.hash(),
                    expected: input.ancestor_headers[0].state_root,
                });
            }

            let mut storage_tries = HashMap::with_capacity_and_hasher(
                input.parent_state_bytes.storage_tries.len(),
                DefaultHashBuilder::default(),
            );
            for (hashed_address, num_nodes, storage_trie_bytes) in
                &input.parent_state_bytes.storage_tries
            {
                let account_in_trie =
                    state_trie.get_rlp::<TrieAccount>(hashed_address.as_slice())?;
                let expected_storage_root =
                    account_in_trie.map_or(EMPTY_ROOT_HASH, |a| a.storage_root);

                let storage_trie =
                    Mpt::decode_trie(bump, &mut storage_trie_bytes.as_ref(), *num_nodes)?;
                if storage_trie.hash() != expected_storage_root {
                    return Err(StatelessExecutorError::ParentStorageRootMismatch {
                        hashed_account: *hashed_address,
                        actual: storage_trie.hash(),
                        expected: expected_storage_root,
                    });
                }

                storage_tries.insert(*hashed_address, storage_trie);
            }

            EthereumState { state_trie, storage_tries, bump }
        };

        Ok(Self { input, state })
    }
}

impl<'a> StatelessExecutorInputWithState<'a> {
    /// Gets the immediate parent block's header.
    #[inline(always)]
    pub fn parent_header(&self) -> &Header {
        &self.input.ancestor_headers[0]
    }

    /// Creates a [`WitnessDb`].
    pub fn witness_db(&self) -> Result<WitnessDb<'a, '_>, StatelessExecutorError> {
        Ok(<Self as WitnessInput>::witness_db(self)?)
    }
}

impl<'a> WitnessInput<'a> for StatelessExecutorInputWithState<'a> {
    #[inline(always)]
    fn state(&self) -> &EthereumState<'a> {
        &self.state
    }

    #[inline(always)]
    fn state_anchor(&self) -> B256 {
        self.parent_header().state_root
    }

    #[inline(always)]
    fn bytecodes(&self) -> impl Iterator<Item = &Bytecode> {
        self.input.bytecodes.iter()
    }

    #[inline(always)]
    fn headers(&self) -> impl Iterator<Item = &Header> {
        once(&self.input.current_block.header).chain(self.input.ancestor_headers.iter())
    }

    #[inline(always)]
    fn headers_len(&self) -> usize {
        1 + self.input.ancestor_headers.len()
    }
}
