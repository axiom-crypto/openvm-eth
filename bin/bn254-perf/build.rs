//! Compiles `cuda/src/bench.cu` into `libbn254_perf.a` and emits the link
//! directives cargo needs to pull it into the final binary.

use std::process::exit;

use openvm_cuda_builder::{cuda_available, CudaBuilder};

fn main() {
    if !cuda_available() {
        eprintln!("cargo:warning=CUDA is not available");
        exit(1);
    }

    let builder = CudaBuilder::new()
        .library_name("bn254_perf")
        .include("cuda/include")
        .watch("cuda")
        .files_from_glob("cuda/src/**/*.cu");

    builder.emit_link_directives();
    builder.build();
}
