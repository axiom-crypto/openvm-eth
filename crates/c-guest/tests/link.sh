#!/usr/bin/env bash
# Links tests/link.c against target/libopenvm_c_guest.a (run build.sh first) with openvm.ld, once
# with LLD and once with GNU ld, both with a build ID note, and checks each ELF:
# - its entry point is the library's `_start`;
# - its loadable segments are code at 0x0020_0800, read-only data and writable data, without
#   overlap, and the executable segment holds only `.text` and no data object;
# - the program's heap (`_heap_start` to `_heap_end`) lies after the program, its `.noinit` data
#   included, and below the library's heap (`__openvm_heap_start` up) and 2 GiB;
# - `memcpy` is the library's and not the program's weak one, the library's `__wrap_main` stays
#   local, and `.init_array` holds the constructor.
#
# CC is a C compiler for RV64IM (default: clang, with --target=riscv64-unknown-elf). LLD is the
# rust-lld of build.sh's OpenVM toolchain (OPENVM_RUST_TOOLCHAIN, or that of the locked OpenVM
# commit), and GNU_LD is GNU ld for RISC-V (default: riscv64-unknown-elf-ld, which Debian and Ubuntu
# package as binutils-riscv64-unknown-elf).
set -euo pipefail

cd "$(dirname "$0")/.."
CC="${CC:-clang}"
GNU_LD="${GNU_LD:-riscv64-unknown-elf-ld}"
TOOLCHAIN="${OPENVM_RUST_TOOLCHAIN:-}"
if [ -z "$TOOLCHAIN" ]; then
  TOOLCHAIN=$(../../ci/openvm_toolchain.sh . | sed -n 's/^OPENVM_RUST_TOOLCHAIN=//p')
fi
RUSTC=$(rustup which --toolchain "$TOOLCHAIN" rustc)
HOST=$("$RUSTC" -vV | sed -n 's/^host: //p')
BIN="$("$RUSTC" --print sysroot)/lib/rustlib/$HOST/bin"

fail() {
  echo "error: $*" >&2
  exit 1
}
command -v "$GNU_LD" > /dev/null ||
  fail "no GNU ld for RISC-V ($GNU_LD): install binutils-riscv64-unknown-elf or set GNU_LD"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
TARGET_FLAGS=()
case "$(basename "$CC")" in
  clang*) TARGET_FLAGS=(--target=riscv64-unknown-elf) ;;
esac
"$CC" "${TARGET_FLAGS[@]}" -march=rv64im -mabi=lp64 -ffreestanding -nostdlib -O2 \
  -ffunction-sections -fdata-sections -c tests/link.c -o "$WORK/link.o"
"$BIN/rust-lld" -flavor gnu --fatal-warnings --build-id -T openvm.ld --gc-sections \
  "$WORK/link.o" target/libopenvm_c_guest.a -o "$WORK/lld.elf"
"$GNU_LD" --fatal-warnings --build-id -T openvm.ld --gc-sections \
  "$WORK/link.o" target/libopenvm_c_guest.a -o "$WORK/gnu.elf"

# check <ELF> <linker>
check() {
  local symbols entry headers loads vaddr memsz flags layout="" load_end=0 exec addr sym
  symbols=$("$BIN/llvm-nm" "$1")
  address() { awk -v s="$1" '$3 == s { print $1 }' <<< "$symbols"; }
  for sym in _start _end _heap_start _heap_end __openvm_heap_start __init_array_start \
    __init_array_end link_magic noinit_buf; do
    [ -n "$(address "$sym")" ] || fail "$2: no $sym"
  done
  value() { echo "$((16#$(address "$1")))"; }
  entry=$("$BIN/llvm-readobj" --file-headers "$1" | awk '/Entry:/ { print $2 }')
  [ "$((entry))" -eq "$(value _start)" ] || fail "$2: the entry point is not _start"

  # The loadable segments by address, with their flags.
  headers=$("$BIN/llvm-readobj" --elf-output-style=GNU --program-headers --wide "$1")
  loads=$(awk '$1 == "LOAD" {
    flags = ""
    for (i = 7; i < NF; i++) flags = flags $i
    print $3, $6, flags
  }' <<< "$headers" | sort)
  while read -r vaddr memsz flags; do
    ((vaddr >= load_end)) || fail "$2: the segment at $vaddr overlaps the one before it"
    load_end=$((vaddr + memsz))
    layout="$layout $flags"
  done <<< "$loads"
  [ "$layout" = " RE R RW" ] || fail "$2: the segments are$layout, not RE R RW"
  read -r vaddr memsz flags <<< "$loads"
  ((vaddr == 0x00200800)) || fail "$2: the code doesn't start at 0x00200800"

  # The executable segment holds only `.text`, from the section to segment mapping, and no data
  # object.
  exec=$(awk '
    /^Program Headers:/ { table = 1; next }
    table && $1 == "Type" { n = 0; next }
    table && NF == 0 { table = 0 }
    table {
      flags = ""
      for (i = 7; i < NF; i++) flags = flags $i
      if ($1 == "LOAD" && flags ~ /E/) exec[sprintf("%02d", n)] = 1
      n++
    }
    /Segment Sections/ { mapping = 1; next }
    mapping && ($1 in exec) { $1 = ""; print }
  ' <<< "$headers" | xargs)
  [ "$exec" = ".text" ] || fail "$2: the executable segment holds $exec, not only .text"
  while read -r addr; do
    ((16#$addr < vaddr || 16#$addr >= vaddr + memsz)) ||
      fail "$2: the executable segment holds a data object, at 0x$addr"
  done < <("$BIN/llvm-readobj" --elf-output-style=GNU --symbols "$1" | awk '$4 == "OBJECT" { print $2 }')

  ((load_end <= $(value _end) && $(value _end) <= $(value _heap_start) &&
    $(value noinit_buf) + 64 <= $(value _heap_start) && $(value _heap_start) < $(value _heap_end) &&
    $(value _heap_end) <= $(value __openvm_heap_start) && $(value _heap_end) <= 0x80000000)) ||
    fail "$2: the heap doesn't lie between the program and the library's heap, below 2 GiB"

  grep -q " T memcpy$" <<< "$symbols" || fail "$2: memcpy is not a strong definition"
  [ "$(address memcpy)" != "$(address decoy_memcpy)" ] || fail "$2: memcpy is the program's weak one"
  grep -q " t __wrap_main$" <<< "$symbols" || fail "$2: __wrap_main is not the library's local symbol"
  (($(value __init_array_end) - $(value __init_array_start) >= 8)) ||
    fail "$2: .init_array doesn't hold the constructor"
}
check "$WORK/lld.elf" LLD
check "$WORK/gnu.elf" "GNU ld"
echo "Linked tests/link.c against target/libopenvm_c_guest.a with openvm.ld, with LLD and GNU ld"
