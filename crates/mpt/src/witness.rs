//! Reusable witness database backed by a borrowed [`EthereumState`].
//!
//! [`WitnessDb`] implements [`revm::DatabaseRef`] by reading accounts, storage slots and
//! bytecodes directly out of the state's tries, and [`WitnessInput`] verifies the ancestor
//! header chain and assembles a [`WitnessDb`] from any input that can expose the required
//! pieces. Both are generic over the concrete input type so downstreams (the OpenVM stateless
//! executor, and third-party executors with their own input encodings) can reuse them instead
//! of maintaining a copy.
//!
//! This module is gated behind the `witness` cargo feature because it pulls in `reth-evm`
//! (for [`ProviderError`]) and `alloy-consensus` (for [`Header`]).

use alloy_consensus::Header;
use alloy_trie::TrieAccount;
use itertools::Itertools;
use reth_evm::execute::ProviderError;
use revm::{
    state::{AccountInfo, Bytecode},
    DatabaseRef,
};
use revm_primitives::{keccak256, map::DefaultHashBuilder, Address, HashMap, B256, U256};

use crate::{Error, EthereumState};

/// Errors raised while verifying the ancestor header chain during [`WitnessDb`] construction.
#[derive(thiserror::Error, Debug)]
pub enum WitnessError {
    #[error(
        "non-consecutive block headers: parent block number {parent_block_number}, child block number {child_block_number}"
    )]
    NonConsecutiveBlockHeaders { parent_block_number: u64, child_block_number: u64 },

    #[error(
        "parent block hash mismatch at block number {parent_block_number}: expected {expected}, got {actual}"
    )]
    ParentBlockHashMismatch { parent_block_number: u64, expected: B256, actual: B256 },
}

/// A trait for constructing [`WitnessDb`]. The lifetime parameter `'a` is the lifetime of the
/// bump arena backing the state's tries.
pub trait WitnessInput<'a> {
    /// Gets a reference to the state from which account info and storage slots are loaded.
    fn state(&self) -> &EthereumState<'a>;

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
    fn witness_db(&self) -> Result<WitnessDb<'a, '_>, WitnessError> {
        let state = self.state();

        let bytecode_by_hash =
            self.bytecodes().map(|code| (code.hash_slow(), code)).collect::<HashMap<_, _>>();

        // Verify and build block hashes
        let mut block_hashes: HashMap<u64, B256, _> =
            HashMap::with_capacity_and_hasher(self.headers_len(), DefaultHashBuilder::default());
        for (child_header, parent_header) in self.headers().tuple_windows() {
            if parent_header.number != child_header.number - 1 {
                return Err(WitnessError::NonConsecutiveBlockHeaders {
                    parent_block_number: parent_header.number,
                    child_block_number: child_header.number,
                });
            }

            if parent_header.hash_slow() != child_header.parent_hash {
                return Err(WitnessError::ParentBlockHashMismatch {
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

/// A database that loads account info and storage slots from a borrowed [`EthereumState`]. The
/// lifetime parameter `'a` is the lifetime of the bump arena backing the state's tries, and `'b`
/// is the lifetime of the borrows of the state and bytecodes.
#[derive(Debug)]
pub struct WitnessDb<'a, 'b> {
    inner: &'b EthereumState<'a>,
    block_hashes: HashMap<u64, B256>,
    bytecode_by_hash: HashMap<B256, &'b Bytecode>,
}

impl<'a, 'b> WitnessDb<'a, 'b> {
    pub fn new(
        inner: &'b EthereumState<'a>,
        block_hashes: HashMap<u64, B256>,
        bytecode_by_hash: HashMap<B256, &'b Bytecode>,
    ) -> Self {
        Self { inner, block_hashes, bytecode_by_hash }
    }
}

fn trie_error_to_provider_error(trie_error: Error) -> ProviderError {
    match trie_error {
        Error::RlpError(error) => ProviderError::Rlp(error),
        _ => ProviderError::TrieWitnessError(trie_error.to_string()),
    }
}

impl DatabaseRef for WitnessDb<'_, '_> {
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
