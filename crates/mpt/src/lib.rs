#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod trie;
pub use trie::*;

mod state;
pub use state::*;

mod bump_bufmut;
mod hp;
mod node;
mod rlp;

#[cfg(feature = "host")]
pub mod resolver;

#[cfg(test)]
mod tests;
