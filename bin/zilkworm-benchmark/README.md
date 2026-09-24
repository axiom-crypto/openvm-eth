# OpenVM Zilkworm Benchmark

Benchmark host for [Zilkworm](https://github.com/eth-act/zilkworm-stateless)
(mirrored at [axiom-crypto/zilkworm-stateless](https://github.com/axiom-crypto/zilkworm-stateless)), a bare-metal C++
stateless Ethereum block validator compiled to an RV64IM ELF. The guest runs
on OpenVM's RV64 target (`rv64i + rv64m + io + keccak + sha2` extensions) and
goes through the same execute / prove pipeline as the Reth benchmark.

## Guest

Build the guest ELF from the `feat/openvm-rv64` branch of
`axiom-crypto/zilkworm-stateless` (requires cmake >= 3.28 and the xPack
`riscv-none-elf-gcc` toolchain, see that repo's README):

```bash
git clone https://github.com/axiom-crypto/zilkworm-stateless.git
cd zilkworm-stateless
git checkout feat/openvm-rv64
make guest_openvm    # produces build/openvm/z6m_guest.elf
```

## Input

The guest consumes one eth-act SSZ `StatelessInput` byte vector (the
`*_input.bin` format produced by the zilkworm `conformance` vector
generator) and reveals the SSZ `StatelessValidationResult`
(`root[32] || success[1] || offset[4] || chain_config`) as public values.

Generate the synthetic mock vector (note: the mock block intentionally
*fails* validation — assert `mock_expected_failure.bin`):

```bash
cd zilkworm-stateless/conformance
cargo run --release -- mock --out-dir vectors --name mock
```

EEST stateless fixtures can be converted with the same tool's `eest`
subcommand; real-block vectors with `real` (see `conformance/README.md`).

## Run

```bash
cargo run --bin openvm-zilkworm-benchmark --release -- \
  --mode execute \
  --guest-elf path/to/z6m_guest.elf \
  --input-path path/to/mock_input.bin \
  --expected-output path/to/mock_expected_failure.bin
```

Modes: `execute`, `execute-metered`, `prove-app`, `prove-stark`, `keygen`,
`generate-vm-vkey`. Proving parameters (`--app-log-blowup`, `--app-l-skip`,
`--leaf-log-blowup`, `--internal-log-blowup`, `--segment-max-memory`,
`--num-children-leaf`, `--num-children-internal`) match the Reth benchmark
host.

Feature flags also mirror the Reth host: `rvr` (recompile the guest to
native C for execution; needs `clang-22` and `lld`), `tco`, `cuda`,
`jemalloc`/`mimalloc`, `metrics`, `perf-metrics`, `unprotected`, `nvtx`.

## CI

The `Zilkworm Benchmark` workflow
(`.github/workflows/zilkworm-benchmark.yml`) runs parallel to the Reth
Benchmark: it builds the guest ELF from `axiom-crypto/zilkworm-stateless` with the
pinned xPack toolchain, prepares the input (`mock` or an `s3://` / `https://`
URL to a `StatelessInput` .bin), and uploads metrics / markdown to S3 and
gh-pages using the same tooling.
