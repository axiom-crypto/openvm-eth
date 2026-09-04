#![cfg_attr(feature = "tco", allow(incomplete_features))]
#![cfg_attr(feature = "tco", feature(explicit_tail_calls))]

use clap_builder::Parser;
use openvm_reth_benchmark::{run_reth_benchmark, HostArgs};

const OPENVM_STATELESS_GUEST_ELF: &[u8] = include_bytes!("../elf/openvm-stateless-guest");

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = HostArgs::parse();
    run_reth_benchmark(args, OPENVM_STATELESS_GUEST_ELF).await
}
