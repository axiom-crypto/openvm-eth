# openvm-c-guest

A static library that runs C programs as OpenVM guests, with the guest interfaces of
[zkevm-standards](https://github.com/eth-act/zkevm-standards):

| Interface | Standard | Implementation |
|---|---|---|
| Entry point (`_start`) and termination | [static-library-and-linker-script](https://github.com/eth-act/zkevm-standards/tree/main/standards/static-library-and-linker-script), [standard-termination-semantics](https://github.com/eth-act/zkevm-standards/tree/main/standards/standard-termination-semantics) | [`src/rt.rs`](src/rt.rs) |
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
`__fini_array`); GNU ld and LLD do with their default linker scripts.

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

`Cargo.lock` is the part of the root `Cargo.lock` that the library needs, so the library builds
with the dependency versions that the root workspace tests. After changing dependencies, run
`crates/c-guest/sync-lock.sh`; CI checks that `Cargo.lock` is up to date.

## Link a program

Compile for RV64IM with the LP64 ABI, and link at OpenVM's text address after the program's
objects:

```sh
riscv64-unknown-elf-gcc -march=rv64im -mabi=lp64 -nostdlib -Wl,-Ttext=0x00200800,-z,separate-code \
    main.c crates/c-guest/target/libopenvm_c_guest.a -o main.elf
```

`crates/c-guest/tests/link.sh` does the same with clang and LLD, and checks the result.

The library's memory functions (`memcpy`, `memmove`, `memset`, `memcmp` and `bcmp`) are strong, so
a program must not define them strongly, and a C library must come after this library on the
link line: a second strong definition is a duplicate-symbol error. Weak definitions, such as
compiler-builtins', are fine.

The library is not a C library: it has no `stdio.h` or `malloc`, for example. Besides the functions
above, it exports OpenVM's runtime symbols, among them the C math functions of OpenVM's Rust runtime
(`floor`, `exp`, ...), so a program must not define those or link another math library. The
library's heap (OpenVM's bump allocator, which `read_input`, `atexit` and the accelerators use)
starts at `_end` and grows up: a program must not use that memory for its own heap.

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
