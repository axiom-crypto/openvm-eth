#!/usr/bin/env bash
# Builds target/libopenvm_c_guest.a, the static library for C guest programs (see README.md).
#
# Cargo's static library keeps OpenVM's memory functions (`memcpy`, `memmove`, `memset`, `memcmp`
# and `bcmp`, from `openvm-mem`) in an object of their own: `openvm-mem` is `#![no_builtins]`,
# which keeps it out of LTO. A linker takes an object from a library only for a symbol that is
# still undefined, so a C program that defines weak memory functions, as Rust's compiler-builtins
# does, would never link that object, and its own functions would win. This script merges every
# object of the library except compiler_builtins' (whose definitions are weak) into one object.
# Every program links that object for `_start`, so OpenVM's memory functions take effect whatever
# the link order.
#
# The merge also wraps `main` (`--wrap=main`): OpenVM's `__start` then calls the library's
# `__wrap_main`, which runs the static constructors, calls the program's `main` and passes its
# return value to `exit` (src/rt.rs). The script then makes `__wrap_main` a local symbol, so that
# it doesn't clash with a program that wraps `main` itself.
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

HOST=$("$RUSTC" -vV | sed -n 's/^host: //p')
BIN="$("$RUSTC" --print sysroot)/lib/rustlib/$HOST/bin"
CARGO_LIB="$PWD/target/$TARGET/release/libopenvm_c_guest.a"
LIB="$PWD/target/libopenvm_c_guest.a"
# The C interface of the accelerators, which the library exports.
ACCELERATORS=$(grep -rhoE 'extern "C" fn zkvm_[a-z0-9_]+' ../accelerators/src | sed 's/.* fn //' | sort -u)
if [ -z "$ACCELERATORS" ]; then
  echo "error: found no accelerators in ../accelerators/src" >&2
  exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
MEMBERS=$("$BIN/llvm-ar" t "$CARGO_LIB")
# `llvm-ar x` would extract members with the same name over each other.
DUPLICATES=$(sort <<< "$MEMBERS" | uniq -d)
if [ -n "$DUPLICATES" ]; then
  echo "error: $CARGO_LIB has several members named:" >&2
  echo "$DUPLICATES" >&2
  exit 1
fi
"$BIN/llvm-ar" x "$CARGO_LIB"
MERGED=()
BUILTINS=()
while IFS= read -r member; do
  case "$member" in
    compiler_builtins-*) BUILTINS+=("$member") ;;
    *) MERGED+=("$member") ;;
  esac
done <<< "$MEMBERS"
"$BIN/rust-lld" -flavor gnu -r --wrap=main -o openvm_c_guest.o "${MERGED[@]}"
"$BIN/llvm-objcopy" --localize-symbol=__wrap_main openvm_c_guest.o

# The object with `_start` must define the memory functions and the library's interface strongly,
# and leave only the program's `main` undefined, not `__real_main`.
SYMBOLS=$("$BIN/llvm-nm" openvm_c_guest.o)
REQUIRED=("T _start" "T memcpy" "T memmove" "T memset" "T memcmp" "T read_input" "T write_output"
  "T exit" "T _Exit" "T abort" "T atexit" "T __cxa_atexit" "T __assert_fail" "T __assert_func"
  "R __dso_handle" "t __wrap_main" "U main")
for accelerator in $ACCELERATORS; do
  REQUIRED+=("T $accelerator")
done
for sym in "${REQUIRED[@]}"; do
  if ! grep -q " $sym\$" <<< "$SYMBOLS"; then
    echo "error: openvm_c_guest.o has no symbol '$sym'" >&2
    exit 1
  fi
done
for sym in "U __real_main" "T __wrap_main"; do
  if grep -q " $sym\$" <<< "$SYMBOLS"; then
    echo "error: openvm_c_guest.o has the symbol '$sym'" >&2
    exit 1
  fi
done
rm -f "$LIB.tmp"
"$BIN/llvm-ar" rcs "$LIB.tmp" openvm_c_guest.o "${BUILTINS[@]}"
mv -f "$LIB.tmp" "$LIB"
echo "Built $LIB"
