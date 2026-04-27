use alloc::{boxed::Box, format, string::ToString, vec::Vec};
use core::iter::once;

use crate::error::StatelessExecutorError;
use alloy_trie::TrieAccount;
use bumpalo::Bump;
use itertools::Itertools;
use openvm_mpt::{EthereumState, EthereumStateBytes, Mpt};
use reth_evm::execute::ProviderError;
use reth_primitives::{Block, Header, TransactionSigned};
use revm::{
    state::{AccountInfo, Bytecode},
    DatabaseRef,
};
use revm_primitives::{keccak256, map::DefaultHashBuilder, Address, HashMap, B256, U256};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Bump area size in bytes.
const BUMP_AREA_SIZE: usize = 1000 * 1000;

/// The input for the client to execute a block and fully verify the STF (state transition
/// function).
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessExecutorInput {
    /// The current block (which will be executed inside the client).
    #[serde_as(
        as = "reth_primitives_traits::serde_bincode_compat::Block<'_, TransactionSigned, Header>"
    )]
    pub current_block: Block<TransactionSigned, Header>,
    /// The previous block headers starting from the most recent. There must be at least one header
    /// to provide the parent state root.
    #[serde_as(as = "Vec<alloy_consensus::serde_bincode_compat::Header>")]
    pub ancestor_headers: Vec<Header>,
    /// Network state as of the parent block.
    pub parent_state_bytes: EthereumStateBytes,
    /// Account bytecodes.
    pub bytecodes: Vec<Bytecode>,
}

#[derive(Debug, Clone)]
pub struct StatelessExecutorInputWithState {
    pub input: &'static StatelessExecutorInput,
    pub state: EthereumState,
}

impl StatelessExecutorInputWithState {
    /// Parses `input.parent_state_bytes` into `EthereumState` and verifies state and storage roots.
    pub fn build(input: StatelessExecutorInput) -> Result<Self, StatelessExecutorError> {
        let input = Box::leak(Box::new(input));
        let bump = Box::leak(Box::new(Bump::with_capacity(BUMP_AREA_SIZE)));

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
                    account_in_trie.map_or(alloy_trie::EMPTY_ROOT_HASH, |a| a.storage_root);

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

impl StatelessExecutorInputWithState {
    /// Gets the immediate parent block's header.
    #[inline(always)]
    pub fn parent_header(&self) -> &Header {
        &self.input.ancestor_headers[0]
    }

    /// Creates a [`WitnessDb`].
    pub fn witness_db(&self) -> Result<WitnessDb<'_>, StatelessExecutorError> {
        <Self as WitnessInput>::witness_db(self)
    }
}

impl WitnessInput for StatelessExecutorInputWithState {
    #[inline(always)]
    fn state(&self) -> &EthereumState {
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

/// A trait for constructing [`WitnessDb`].
pub trait WitnessInput {
    /// Gets a reference to the state from which account info and storage slots are loaded.
    fn state(&self) -> &EthereumState;

    /// Gets the state trie root hash that the state referenced by
    /// [state()](trait.WitnessInput#tymethod.state) must conform to.
    fn state_anchor(&self) -> B256;

    /// Gets an iterator over account bytecodes.
    fn bytecodes(&self) -> impl Iterator<Item = &Bytecode>;

    /// Gets an iterator over references to a consecutive, reverse-chronological block headers
    /// starting from the current block header.
    fn headers(&self) -> impl Iterator<Item = &Header>;

    /// Gets the number of headers.
    fn headers_len(&self) -> usize;

    /// Creates a [`WitnessDb`] from a [`WitnessInput`] implementation. To do so, it verifies the
    /// state root, ancestor headers and account bytecodes, and constructs the account and
    /// storage values by reading against state tries.
    ///
    /// NOTE: For some unknown reasons, calling this trait method directly from outside of the type
    /// implementing this trait causes a zkVM run to cost over 5M cycles more. To avoid this, define
    /// a method inside the type that calls this trait method instead.
    #[inline(always)]
    fn witness_db(&self) -> Result<WitnessDb<'_>, StatelessExecutorError> {
        let state = self.state();

        let bytecode_by_hash =
            self.bytecodes().map(|code| (code.hash_slow(), code)).collect::<HashMap<_, _>>();

        // Verify and build block hashes
        let mut block_hashes: HashMap<u64, B256, _> =
            HashMap::with_capacity_and_hasher(self.headers_len(), DefaultHashBuilder::default());
        for (child_header, parent_header) in self.headers().tuple_windows() {
            if parent_header.number != child_header.number - 1 {
                return Err(StatelessExecutorError::NonConsecutiveBlockHeaders {
                    parent_block_number: parent_header.number,
                    child_block_number: child_header.number,
                });
            }

            if parent_header.hash_slow() != child_header.parent_hash {
                return Err(StatelessExecutorError::ParentBlockHashMismatch {
                    parent_block_number: parent_header.number,
                    expected: parent_header.hash_slow(),
                    actual: child_header.parent_hash,
                });
            }

            block_hashes.insert(parent_header.number, child_header.parent_hash);
        }

        Ok(WitnessDb { inner: state, block_hashes, bytecode_by_hash })
    }
}

#[derive(Debug)]
pub struct WitnessDb<'a> {
    inner: &'a EthereumState,
    block_hashes: HashMap<u64, B256>,
    bytecode_by_hash: HashMap<B256, &'a Bytecode>,
}

impl<'a> WitnessDb<'a> {
    pub fn new(
        inner: &'a EthereumState,
        block_hashes: HashMap<u64, B256>,
        bytecode_by_hash: HashMap<B256, &'a Bytecode>,
    ) -> Self {
        Self { inner, block_hashes, bytecode_by_hash }
    }
}

fn trie_error_to_provider_error(trie_error: openvm_mpt::Error) -> ProviderError {
    match trie_error {
        openvm_mpt::Error::RlpError(error) => ProviderError::Rlp(error),
        _ => ProviderError::TrieWitnessError(trie_error.to_string()),
    }
}

impl DatabaseRef for WitnessDb<'_> {
    /// The database error type.
    type Error = ProviderError;

    /// Get basic account information.
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let hashed_address = keccak256(address);

        let account_in_trie = self
            .inner
            .state_trie
            .get_rlp::<TrieAccount>(hashed_address.as_slice())
            .map_err(trie_error_to_provider_error)?;

        let account = account_in_trie.map(|account_in_trie| AccountInfo {
            balance: account_in_trie.balance,
            nonce: account_in_trie.nonce,
            code_hash: account_in_trie.code_hash,
            code: None,
            account_id: None,
        });

        Ok(account)
    }

    /// Get account code by its hash.
    fn code_by_hash_ref(&self, hash: B256) -> Result<Bytecode, Self::Error> {
        // Cloning here is fine as `Bytes` is cheap to clone.
        self.bytecode_by_hash.get(&hash).map(|code| (*code).clone()).ok_or_else(|| {
            ProviderError::TrieWitnessError(format!("bytecode for {hash} not found"))
        })
    }

    /// Get storage value of address at index.
    ///
    /// Returns `U256::ZERO` if the slot is not found in the trie.
    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let hashed_address = keccak256(address);

        let storage_trie = self.inner.storage_tries.get(&hashed_address).ok_or_else(|| {
            ProviderError::TrieWitnessError(format!("storage trie for {address} not found"))
        })?;

        let hashed_slot = keccak256(index.to_be_bytes::<32>());
        let storage_value = storage_trie
            .get_rlp::<U256>(hashed_slot.as_slice())
            .map_err(trie_error_to_provider_error)?
            .unwrap_or_default();
        Ok(storage_value)
    }

    /// Get block hash by block number.
    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.block_hashes.get(&number).copied().ok_or(ProviderError::StateForNumberNotFound(number))
    }
}
