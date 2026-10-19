# openvm-c-guest

A static library that runs C programs as OpenVM guests, with the guest interfaces of
[zkevm-standards](https://github.com/eth-act/zkevm-standards):

| Interface | Standard | Implementation |
|---|---|---|
| Entry point (`_start`) and termination | [static-library-and-linker-script](https://github.com/eth-act/zkevm-standards/tree/main/standards/static-library-and-linker-script), [standard-termination-semantics](https://github.com/eth-act/zkevm-standards/tree/main/standards/standard-termination-semantics) | [`src/rt.rs`](src/rt.rs) |
| Linker script: segments, memory layout, `_heap_start` and `_heap_end` | [static-library-and-linker-script](https://github.com/eth-act/zkevm-standards/tree/main/standards/static-library-and-linker-script), [memory-layout-restrictions](https://github.com/eth-act/zkevm-standards/tree/main/standards/memory-layout-restrictions) | [`openvm.ld`](openvm.ld) |
| I/O (`zkvm_io.h`) | [io-interface](https://github.com/eth-act/zkevm-standards/tree/main/standards/io-interface) | [`src/io.rs`](src/io.rs) |
| Accelerators (`zkvm_accelerators.h`) | [c-interface-accelerators](https://github.com/eth-act/zkevm-standards/tree/main/standards/c-interface-accelerators) | [`crates/accelerators`](../accelerators) |
| `memcpy`, `memmove`, `memset`, `memcmp` | [accelerated-memory-operations](https://github.com/eth-act/zkevm-standards/tree/main/standards/accelerated-memory-operations) | OpenVM's `openvm-mem` |

The headers are the standards' own (`zkvm_io.h`, `zkvm_accelerators.h`); this crate doesn't ship
copies.

## Startup and termination

OpenVM's `_start` runs the static constructors (`.preinit_array`, then `.init_array`), calls
`int main(void)` and passes its return value to `exit`. `exit` runs the functions registered with
`atexit` and `__cxa_atexit` (where C++ compilers register the destructors of static objects) in
reverse order, then the static destructors of `.fini_array`, and terminates. The library also
provides `_Exit`, which terminates at once, `abort`, and the handlers of failed `assert`s
(`__assert_fail` for glibc's `assert.h`, `__assert_func` for newlib's), which print the assertion.

| Termination | OpenVM exit code |
|---|---|
| `main` returns 0, `exit(0)`, `_Exit(0)` | 0 (success) |
| any other status | the low byte of the status, or 1 if the low byte is 0 |
| `abort`, a failed `assert`, a Rust panic | 1 |

The linker must define the bounds of the constructor and destructor arrays
(`__init_array_start`, `__init_array_end`, and the same for `__preinit_array` and
`__fini_array`), as `openvm.ld` does.

## Build

Run:

```sh
crates/c-guest/build.sh
```

`build.sh` uses the OpenVM toolchain of the OpenVM commit that `Cargo.lock` locks
(`ci/openvm_toolchain.sh` prints both), or `OPENVM_RUST_TOOLCHAIN` if set. If that toolchain isn't
installed, it prints the command that installs it, `cargo openvm toolchain install --version
<toolchain>`.

The library is `crates/c-guest/target/libopenvm_c_guest.a`. `build.sh` builds the crate for
`riscv64im-unknown-openvm-elf` with the compiler flags of `cargo openvm build`
(`.cargo/config.toml`). It then merges the library's objects, except compiler_builtins', into one
object:

- That object holds `_start`, so every program links it, and its strong memory functions replace
  any weak ones that the program defines, whatever the link order. In Cargo's own `.a`,
  `openvm-mem` stays in an object of its own (it is `#![no_builtins]`, which keeps it out of LTO),
  which a linker skips when the program already defines the memory functions.
- The merge links with `--wrap=main`, so OpenVM's `__start` calls the library's `__wrap_main`,
  which runs the startup and termination above. Cargo's own `.a` leaves `__real_main` undefined.
  `build.sh` then makes `__wrap_main` a local symbol, so a program can wrap `main` itself.
- `build.sh` renames the library's reference to `_end`, where OpenVM's allocator starts its heap,
  to `__openvm_heap_start`, which `openvm.ld` defines above the program's heap (see below).

`Cargo.lock` is the part of the root `Cargo.lock` that the library needs, so the library builds
with the dependency versions that the root workspace tests. After changing dependencies, run
`crates/c-guest/sync-lock.sh`; CI checks that `Cargo.lock` is up to date.

## Link a program

Compile for RV64IM with the LP64 ABI, and link with the library's linker script,
[`openvm.ld`](openvm.ld), and the library after the program's objects:

```sh
riscv64-unknown-elf-gcc -march=rv64im -mabi=lp64 -nostdlib -T crates/c-guest/openvm.ld \
    main.c crates/c-guest/target/libopenvm_c_guest.a -o main.elf
```

`crates/c-guest/tests/link.sh` does the same with clang, links with LLD and with GNU ld, and checks
the results.

`openvm.ld` works with GNU ld and LLD, and the library needs it: it defines the library's
`__openvm_heap_start`. It sets the entry point to `_start` and puts the code, the read-only data and
the writable data in segments of their own: OpenVM transpiles every word of the executable segment
as an instruction, and a data word can make the transpiler fail. It lays out OpenVM's 4 GiB of
memory:

| Addresses | Region |
|---|---|
| below `0x0020_0400` | The stack, about 2 MiB, which grows down from `0x0020_0400`, where OpenVM's `_start` starts it |
| `0x0020_0800` to `_end` | The program: code, read-only data, data and BSS |
| `_heap_start` (`_end`) to `_heap_end` (`0x7FFF_F000`) | The program's heap, which the library doesn't use |
| `__openvm_heap_start` (`0x7FFF_F000`) to 4 GiB | The library's heap: OpenVM's allocator, which `read_input`, `atexit` and the accelerators use, and which never frees memory |

A program can run an allocator of its own on its heap, or a C library's `malloc`, which must keep
below `_heap_end`. `_end` is where an `sbrk` heap starts, and the script also defines `end` and
picolibc's `__heap_start` and `__heap_end`. `_heap_end` is below 2 GiB, so that code built for the
medlow code model can address it. The library's heap is about 2 GiB: `read_input` copies the whole
input there.

Large buffers are better on the heap than in the BSS: OpenVM's loader builds the initial memory
image word by word, with the zeros of the BSS. Uninitialized data must be in `.bss` or `.noinit`
sections, since a linker can put other uninitialized sections after `_heap_start`. The script
rejects thread-local storage, which OpenVM's `_start` doesn't set up, and `.ctors` and `.dtors`
tables, which nothing runs; RISC-V compilers use `.init_array` and `.fini_array`.

The library's memory functions (`memcpy`, `memmove`, `memset`, `memcmp` and `bcmp`) are strong, so
a program must not define them strongly, and a C library must come after this library on the
link line: a second strong definition is a duplicate-symbol error. Weak definitions, such as
compiler-builtins', are fine.

The library is not a C library: it has no `stdio.h` or `malloc`, for example. Besides the functions
above, it exports OpenVM's runtime symbols, among them the C math functions of OpenVM's Rust runtime
(`floor`, `exp`, ...), so a program must not define those or link another math library.

## Run

Run the ELF with OpenVM's standard VM configuration ([`openvm.toml`](openvm.toml),
`SdkVmConfig::standard()`), for which the accelerators are initialized. The private input is the
first vector of the input stream (on the host, `StdIn::write_bytes`). The host must write that
vector, empty if there is no input: OpenVM fails the execution when the program calls `read_input`
and the input stream has no vector.

`write_output` writes the public output to OpenVM's user public values, from byte 0 on. The VM
configuration sets their size (`SystemConfig::with_public_values`, in bytes: 8 times a power of
two; the default is 32 bytes), and an output longer than that fails the execution. `write_output`
reads any readable address: the interface doesn't treat NULL specially, and OpenVM lets programs
read address 0.

A call to an accelerator with a NULL pointer panics, which exits the guest with code 1; a NULL
buffer pointer with a zero length is an empty buffer.
