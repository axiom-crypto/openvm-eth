#![cfg_attr(all(not(feature = "std"), any(openvm_intrinsics, target_os = "openvm")), no_main)]
#![cfg_attr(not(feature = "std"), no_std)]

use openvm::io::{read, reveal_bytes32};
// Linked for the 256-bit instruction shims it exports, which `ruint` calls. Without a reference
// the rlib is dropped before those symbols reach the link.
use openvm_bigint_guest as _;
use openvm_stateless_executor::{io::StatelessExecutorInput, ChainVariant, StatelessExecutor};

openvm::entry!(main);

#[cfg(all(any(openvm_intrinsics, target_os = "openvm"), feature = "extensions"))]
openvm::init!();

pub fn main() {
    // Read the input.
    let input: StatelessExecutorInput = read();

    // Execute the block (crypto is installed inside executor).
    let executor = StatelessExecutor;
    let header = executor.execute(ChainVariant::Mainnet, input).expect("failed to execute client");
    let block_hash = header.hash_slow();

    // Reveal the block hash.
    reveal_bytes32(*block_hash);
}
