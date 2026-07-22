# OpenVM KZG

## Quickstart

To run the guest tests, run:

```bash
# Proves a single test vector through the full app proving pipeline:
cargo test --release test_single_valid_verify_kzg -- --show-output
# Execute (without proving) all valid and invalid test vectors:
cargo test --release test_multiple_valid_verify_kzg -- --show-output
cargo test --release test_multiple_invalid_verify_kzg -- --show-output
cargo test --release test_single_invalid_verify_kzg -- --show-output
```

## Crates

### `openvm-kzg`

This is a fork of [kzg-rs](https://github.com/succinctlabs/kzg-rs) that replaces `verify_kzg_proof` with an implementation using OpenVM intrinsic functions from the modular arithmetic, complex field extension, elliptic curve cryptography, and optimal Ate pairing VM extensions.

## Test Crates

### tests/programs/verify_kzg

Guest program for running `verify_kzg_proof` with inputs from the host.
