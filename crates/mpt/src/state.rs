use alloc::{vec, vec::Vec};

use alloy_trie::TrieAccount;
use bumpalo::Bump;
use revm::database::BundleState;
use revm_primitives::{keccak256, map::DefaultHashBuilder, HashMap, B256};

use crate::{Error, Mpt};

/// Serialized Ethereum state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EthereumStateBytes {
    pub state_trie: (usize, bytes::Bytes),
    pub storage_tries: Vec<(B256, usize, bytes::Bytes)>,
}

#[derive(Debug, Clone)]
pub struct EthereumState<'a> {
    pub state_trie: Mpt<'a>,
    pub storage_tries: HashMap<B256, Mpt<'a>>,
    pub bump: &'a Bump,
}

impl<'a> EthereumState<'a> {
    /// Creates an empty state whose tries allocate from `bump`.
    pub fn new_in(bump: &'a Bump) -> Self {
        Self {
            state_trie: Mpt::new(bump),
            storage_tries: HashMap::with_capacity_and_hasher(1, DefaultHashBuilder::default()),
            bump,
        }
    }

    /// Creates a state from existing tries. `bump` is used for allocations made by future
    /// updates; the tries must allocate from a bump that lives at least as long as it.
    pub fn from_tries(
        state_trie: Mpt<'a>,
        storage_tries: impl IntoIterator<Item = (B256, Mpt<'a>)>,
        bump: &'a Bump,
    ) -> Self {
        Self { state_trie, storage_tries: storage_tries.into_iter().collect(), bump }
    }

    pub fn update_from_bundle_state(&mut self, bundle_state: &BundleState) -> Result<(), Error> {
        // removals must happen last, otherwise unresolved orphans might still exist
        let mut removed_accounts = vec![];
        for (address, account) in &bundle_state.state {
            let hashed_address = keccak256(address);

            let Some(info) = &account.info else {
                removed_accounts.push(hashed_address);
                continue;
            };

            let storage_trie =
                self.storage_tries.entry(hashed_address).or_insert(Mpt::new(self.bump));

            if account.status.was_destroyed() {
                *storage_trie = Mpt::new(self.bump);
            }

            let mut removed_slots = vec![];
            for (slot, value) in &account.storage {
                let hashed_slot = keccak256(slot.to_be_bytes::<32>());
                if !value.present_value.is_zero() {
                    storage_trie.insert_rlp(hashed_slot.as_slice(), value.present_value)?;
                } else {
                    removed_slots.push(hashed_slot);
                }
            }

            // storage removals also must happen last, otherwise unresolved orphans might still
            // exist
            for removed_slot in removed_slots {
                storage_trie.delete(removed_slot.as_slice())?;
            }

            let storage_root = storage_trie.hash();
            let state_account = TrieAccount {
                nonce: info.nonce,
                balance: info.balance,
                storage_root,
                code_hash: info.code_hash,
            };
            self.state_trie.insert_rlp(hashed_address.as_slice(), state_account)?;
        }

        for removed_account in removed_accounts {
            self.state_trie.delete(removed_account.as_slice())?;
            self.storage_tries.remove(&removed_account);
        }

        Ok(())
    }

    #[cfg(feature = "host")]
    pub fn encode_to_state_bytes(&self) -> EthereumStateBytes {
        let state_num_nodes = self.state_trie.num_nodes();
        let state_bytes = bytes::Bytes::from(self.state_trie.encode_trie());
        let mut storage_bytes: Vec<_> = self
            .storage_tries
            .iter()
            .map(|(addr, trie)| (*addr, trie.num_nodes(), bytes::Bytes::from(trie.encode_trie())))
            .collect();
        storage_bytes.sort_by_key(|(addr, _, _)| *addr);

        EthereumStateBytes {
            state_trie: (state_num_nodes, state_bytes),
            storage_tries: storage_bytes,
        }
    }
}
