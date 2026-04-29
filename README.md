# openvm-eth

A framework for generating zero-knowledge proofs of Ethereum block execution using [OpenVM](https://github.com/openvm-org/openvm) and [Reth](https://github.com/paradigmxyz/reth).

> [!CAUTION]
>
> This repository is still an active work-in-progress and is not audited or meant for production usage.

## Overview

This project provides a complete pipeline for:

1. **Fetching block data** from Ethereum JSON-RPC providers
2. **Stateless execution** of Ethereum blocks without full node state
3. **Proof generation** using OpenVM's RISC-V zkVM
4. **On-chain verification** via aggregated SNARK proofs

The system uses Merkle Patricia Trie (MPT) proofs to verify state without requiring a full node, making it suitable for trustless block verification and ZK rollup applications.

## Workspace Structure

```
openvm-eth/
├── bin/
│   ├── reth-benchmark/      # Host-side bare metal benchmark 
│   ├── reth-verify/         # Standalone stark proof + VK verifier
│   ├── stateless-guest/     # zkVM guest program
└── crates/
    ├── chainspec/           # Chain configuration (mainnet, dev)
    ├── mpt/                 # Merkle Patricia Trie implementation
    ├── mpt-tools/           # MPT profiling and benchmarking
    ├── revm-crypto/         # Crypto provider using OpenVM intrinsics
    ├── rpc-proxy/           # RPC proxy for witness generation
    ├── stateless-executor/  # Core block execution library
    └── stateless-witness/   # Witness generation from Reth
```

## Binary Crates

### `bin/reth-benchmark`

The main CLI tool for single machine bare metal benchmarks. Supports multiple benchmarking modes:

- **Execute**: Run block execution in the VM without generating proofs
- **ProveApp**: Generate individual segment proofs
- **ProveStark**: Generate full STARK proofs with aggregation
- **ProveEvm**: Generate final SNARK proofs for on-chain EVM verification

Handles RPC interaction, witness caching, guest program loading, and metrics collection. Supports Nvidia GPU acceleration.

### `bin/reth-verify`

Standalone host-side verifier for stark proofs using only:

- `--proof`
- `--vm-vk`

Example:

```bash
cargo run --release -p openvm-reth-verify -- \
  --proof /path/to/<proof_uuid>.proof.bin \
  --vm-vk /path/to/reth.vm.vk
```

### `bin/stateless-guest`

The RISC-V guest program that runs inside OpenVM. It receives serialized block data, executes all transactions using the stateless executor, verifies state root correctness, and outputs the block hash as proof of correct execution.

## Library Crates

### `crates/stateless-executor`

Core library implementing stateless Ethereum block execution. Executes blocks against witnessed state (storage proofs + bytecode), validates pre/post-execution conditions, and verifies state roots using MPT proofs. Integrates with Reth's EVM infrastructure.

**Features:**
- `openvm` - Enables OpenVM `CryptoProvider` for zkVM execution via `revm`

### `crates/stateless-witness`

Generates execution witnesses using Reth node API, designed for compatibility with the Reth ExEx framework. 
Provides utility functions for conversion from Reth's `ExecutionWitness` format to `StatelessExecutorInput`, handling storage proof resolution, bytecode collection, and state serialization.

### `crates/mpt`

Merkle Patricia Trie implementation for state and storage tree operations. Provides efficient state root computation and verification, optimized for both host and zkVM execution.

**Features:**
- `host` - Enables additional host-only functionality (resolver)

### `crates/revm-crypto`

OpenVM-optimized cryptographic operations for Revm and Alloy. Provides efficient implementations of:

- ECDSA signature recovery (secp256k1)
- SHA-256 and Keccak-256 hashing
- BN254 and BLS12-381 pairing operations
- KZG commitments

Uses OpenVM's ECC guest libraries when running in the zkVM, falling back to standard implementations on the host.

### `crates/chainspec`

Chain configuration for Ethereum mainnet and dev networks. Provides optimized chainspec loading suitable for zkVM execution (avoids expensive cloning operations).

### `crates/rpc-proxy`

HTTP proxy server that provides `debug_executionWitness` RPC endpoint using standard JSON-RPC providers. Useful for development and testing without direct Reth node access.

**Note:** Not recommended for production use due to RPC provider limitations.

### `crates/mpt-tools`

Development tools for MPT profiling and benchmarking. Includes memory profiling (via dhat) and performance benchmarks (via Criterion).

## Getting Started

### Prerequisites

- Rust toolchain (see `rust-toolchain.toml`)
- Access to either Reth node or an archive Ethereum RPC node
- KZG trusted setup (for EVM proof generation)

### Running Benchmarks

See [Benchmark README](./bin/reth-benchmark/README.md).

## Acknowledgements

- The zkVM framework uses [OpenVM](https://github.com/openvm-org/openvm).
- The underlying Rust libraries make heavy use of [Reth](https://github.com/paradigmxyz/reth) and [Revm](https://github.com/bluealloy/revm/).
- This repo was forked from [RSP](https://github.com/succinctlabs/rsp/tree/main)
- The RSP repo builds on work from [Zeth](https://github.com/risc0/zeth) and we also forked Zeth's `rpc-proxy` crate.
