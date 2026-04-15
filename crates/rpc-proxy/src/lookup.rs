use alloy_primitives::{keccak256, B256, U256};
use rayon::prelude::*;
use risc0_ethereum_trie::Nibbles;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    OnceLock,
};
use tracing::info;

pub const DEFAULT_PREIMAGE_CACHE_NIBBLES: u8 = 7;

/// A lookup table for Keccak256 pre-images.
pub struct PreimageLookup {
    table: Vec<u64>,
    nibbles: usize,
}

impl PreimageLookup {
    /// Creates a new lookup table by precomputing hashes in parallel.
    pub fn new(prefix_length: u8) -> Self {
        if prefix_length == 0 {
            return Self { table: vec![], nibbles: 0 };
        }

        info!(%prefix_length, "Generating preimage cache");
        let prefix_count = 16usize.checked_pow(prefix_length as u32).expect("nibbles too large");

        let table: Vec<OnceLock<u64>> = (0..prefix_count).map(|_| OnceLock::new()).collect();
        let found = AtomicUsize::new(0);

        // use Rayon to parallelize the search over the nonce space
        let _ = (0..=u64::MAX).into_par_iter().try_for_each(|nonce| {
            // stop processing if we have found all prefixes
            if found.load(Ordering::Relaxed) >= prefix_count {
                return Err(());
            }

            let hash = keccak256(B256::from(U256::from(nonce)));
            let idx = get_index_from_hash(hash, prefix_length as usize);

            // if we successfully set the cell (it was empty), increment the counter
            if table[idx].set(nonce).is_ok() {
                found.fetch_add(1, Ordering::Relaxed);
            }

            Ok(())
        });
        info!("Preimage cache generated");

        let final_table = table.into_iter().map(|nonce| nonce.into_inner().unwrap()).collect();

        Self { table: final_table, nibbles: prefix_length as usize }
    }

    /// Finds a pre-image for a given nibble prefix.
    pub fn find(&self, prefix: &Nibbles) -> Option<B256> {
        if prefix.len() > self.nibbles {
            return None;
        }

        let idx = get_index_unchecked(prefix.as_slice());
        let nonce = self.table.get(idx).copied()?;

        Some(B256::from(U256::from(nonce)))
    }

    /// Returns the number of nibbles this lookup table covers.
    pub fn nibbles(&self) -> usize {
        self.nibbles
    }
}

fn get_index_from_hash(hash: B256, prefix_length: usize) -> usize {
    let nibbles = Nibbles::unpack(&hash[..prefix_length.div_ceil(2)]);
    get_index_unchecked(&nibbles[..prefix_length])
}

/// Calculate the little-endian index from the input nibbles.
/// E.g., for [A, B, C], the index will be 0x...CBA.
fn get_index_unchecked(nibbles: &[u8]) -> usize {
    nibbles.iter().rfold(0, |a, n| (a << 4) | *n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preimage_lookup() {
        let lookup = PreimageLookup::new(2);

        let preimage = lookup.find(&Nibbles::unpack([0xab])).unwrap();
        assert!(Nibbles::unpack(keccak256(preimage)).starts_with(&[0x0a, 0x0b]));

        let preimage = lookup.find(&Nibbles::from_nibbles([0xa])).unwrap();
        assert!(Nibbles::unpack(keccak256(preimage)).starts_with(&[0x0a]));

        assert!(lookup.find(&Nibbles::from_nibbles([])).is_some());
        assert!(lookup.find(&Nibbles::unpack(B256::ZERO)).is_none());
    }
}
