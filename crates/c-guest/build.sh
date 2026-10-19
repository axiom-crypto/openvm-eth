#!/usr/bin/env bash
# Builds the static library for C guest programs,
# target/riscv64im-unknown-openvm-elf/release/libopenvm_c_guest.a.
#
# The OpenVM toolchain is the one of the OpenVM commit that Cargo.lock locks (see
# ci/openvm_toolchain.sh), unless OPENVM_RUST_TOOLCHAIN selects another.
set -euo pipefail

cd "$(dirname "$0")"
TOOLCHAIN="${OPENVM_RUST_TOOLCHAIN:-}"
if [ -z "$TOOLCHAIN" ]; then
  TOOLCHAIN=$(../../ci/openvm_toolchain.sh . | sed -n 's/^OPENVM_RUST_TOOLCHAIN=//p')
fi
TARGET=riscv64im-unknown-openvm-elf

# The OpenVM toolchain ships rustc without cargo, so run this checkout's cargo with the OpenVM
# toolchain's rustc, which is the rustc `cargo openvm build` uses too. The compiler flags are those
# of .cargo/config.toml, which RUSTFLAGS and its variants would replace.
if ! RUSTC=$(rustup which --toolchain "$TOOLCHAIN" rustc 2> /dev/null); then
  echo "error: the OpenVM toolchain $TOOLCHAIN isn't installed;" \
    "install it with \`cargo openvm toolchain install --version $TOOLCHAIN\`" >&2
  exit 1
fi
export RUSTC
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS \
  CARGO_TARGET_RISCV64IM_UNKNOWN_OPENVM_ELF_RUSTFLAGS
cargo build --release --locked --target "$TARGET" --target-dir "$PWD/target"

echo "Built $PWD/target/$TARGET/release/libopenvm_c_guest.a"
