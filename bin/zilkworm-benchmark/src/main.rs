use clap::Parser;
use openvm_zilkworm_benchmark::{run_zilkworm_benchmark, HostArgs};

fn main() -> eyre::Result<()> {
    let args = HostArgs::parse();
    run_zilkworm_benchmark(args)
}
