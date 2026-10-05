// The initial version of this crate is forked from Zeth <https://github.com/boundless-xyz/zeth/tree/main/crates/rpc-proxy> at tag v0.3.0.
// Changes:
// - Switch from `anyhow` to `eyre`
// - Populate `keys` field in `execution_witness` response
// - Include empty trie root in witness state
// - Added `RpcExecutor`
// - Fix: `execution_witness` should return header in oldest first ordering

//! This crate provides a proxy for the `debug_executionWitness` endpoint by using standard RPC
//! providers in environments without direct access to a Reth node. This crate is intended for usage
//! in development, testing, and benchmarking. Production use cases should prefer to use a direct
//! integration with Reth via an ExEx.
//!
//! **Warning**: The current RPC proxy implementation does **not** guarantee it can fully provide
//! the execution witness for all blocks. This is because of limitations of standard RPC providers
//! and the inability to perform storage key preimage lookups for all storage slots. For example,
//! standard RPC providers do not support `debug_storageRangeAt` with non-null `key` field in the
//! response.
//!
//! The current implementation mitigates this by pre-computing a lookup table of `nibbles ->
//! preimage` where `keccak256(preimage) = nibbles` for all hex strings (consisting of nibbles) of
//! length `2^cache_prefix_length`. The pre-computation is done by a form of grinding (i.e.,
//! guessing until all postimages are found). This lookup table can be used to reverse lookup the
//! prefix key when orphan nodes are encountered in the trie. If the `prefix_length` is set large
//! enough (larger than the maximum depth of the trie), then the implementation can guarantee the
//! full computation of the witness.

mod db;
mod execution;
mod lookup;
mod transport;
mod trie;
mod witness;

pub use execution::RpcExecutor;
pub use lookup::{PreimageLookup, DEFAULT_PREIMAGE_CACHE_NIBBLES};
pub use transport::{upstream_http_client, LogOnErrorLayer};
pub use witness::execution_witness;
