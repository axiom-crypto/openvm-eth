#!/usr/bin/env bash
# Links tests/link.c against target/libopenvm_c_guest.a (run build.sh first) and checks the ELF:
# its entry point is the library's `_start`, `memcpy` is the library's and not the program's weak
# one, the library's `__wrap_main` stays local, and the constructor is in `.init_array`.
#
# CC is a C compiler for RV64IM (default: clang, with --target=riscv64-unknown-elf); the link uses
# the rust-lld of build.sh's OpenVM toolchain (OPENVM_RUST_TOOLCHAIN, or that of the locked OpenVM
# commit).
set -euo pipefail

cd "$(dirname "$0")/.."
CC="${CC:-clang}"
TOOLCHAIN="${OPENVM_RUST_TOOLCHAIN:-}"
if [ -z "$TOOLCHAIN" ]; then
  TOOLCHAIN=$(../../ci/openvm_toolchain.sh . | sed -n 's/^OPENVM_RUST_TOOLCHAIN=//p')
fi
RUSTC=$(rustup which --toolchain "$TOOLCHAIN" rustc)
HOST=$("$RUSTC" -vV | sed -n 's/^host: //p')
BIN="$("$RUSTC" --print sysroot)/lib/rustlib/$HOST/bin"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
TARGET_FLAGS=()
case "$(basename "$CC")" in
  clang*) TARGET_FLAGS=(--target=riscv64-unknown-elf) ;;
esac
"$CC" "${TARGET_FLAGS[@]}" -march=rv64im -mabi=lp64 -ffreestanding -nostdlib -O2 \
  -ffunction-sections -fdata-sections -c tests/link.c -o "$WORK/link.o"
"$BIN/rust-lld" -flavor gnu -Ttext=0x00200800 -z separate-code --gc-sections \
  "$WORK/link.o" target/libopenvm_c_guest.a -o "$WORK/link.elf"

fail() {
  echo "error: $*" >&2
  exit 1
}
SYMBOLS=$("$BIN/llvm-nm" "$WORK/link.elf")
address() { awk -v s="$1" '$3 == s { print $1 }' <<< "$SYMBOLS"; }
ENTRY=$("$BIN/llvm-readobj" --file-headers "$WORK/link.elf" | awk '/Entry:/ { print $2 }')
[ -n "$(address _start)" ] || fail "no _start"
[ "$((ENTRY))" -eq "$((16#$(address _start)))" ] || fail "the entry point is not _start"
grep -q " T memcpy$" <<< "$SYMBOLS" || fail "memcpy is not a strong definition"
[ "$(address memcpy)" != "$(address decoy_memcpy)" ] || fail "memcpy is the program's weak one"
grep -q " t __wrap_main$" <<< "$SYMBOLS" || fail "__wrap_main is not the library's local symbol"
INIT_ARRAY=$("$BIN/llvm-readobj" --sections "$WORK/link.elf" | grep -c 'Name: .init_array')
[ "$INIT_ARRAY" -eq 1 ] || fail "no .init_array for the constructor"
echo "Linked tests/link.c against target/libopenvm_c_guest.a"
