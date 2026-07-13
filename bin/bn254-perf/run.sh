#!/bin/bash
set -e

REPO_ROOT=$(git rev-parse --show-toplevel)

RUSTFLAGS="-Ctarget-cpu=native" cargo +nightly-2026-01-18 build \
  -p bn254-perf \
  --release \
  --features halo2-base/asm

"$REPO_ROOT/target/release/bn254-perf" "$@"
