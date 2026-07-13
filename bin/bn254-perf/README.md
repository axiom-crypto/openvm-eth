# bn254-perf

Micro-benchmark comparing single-threaded CPU vs single-thread GPU BN254 scalar
(`Fr`) arithmetic. Workloads are derived from the hot ops in the halo2
static-verifier tracegen (see `bin/static-verifier-tracegen-arithonly/`).

## Workloads

Six chained loops, each with a data dependency between iterations so the ops
can't be reordered or parallelized:

| Op             | Chain                       | Ops/iter |
|----------------|-----------------------------|----------|
| `mul`          | `x <- x * a`                | 1 mul    |
| `sqr`          | `x <- x * x`                | 1 sqr    |
| `sbox (x^5)`   | `x <- (x^2)^2 * x`          | 3 muls   |
| `mul_add`      | `x <- x * a + b`            | 1 mul + 1 add |
| `add`          | `x <- x + a`                | 1 add    |
| `inv`          | `x <- x.invert() + a`       | 1 inv + 1 add |

Default iteration count: 1M for the mul/sqr/sbox/add/mul_add chains, 50k for
`inv` (inversion is ~50-100× a mul, so we scale it down).

## Implementations

**CPU** — `halo2curves-axiom` `Fr`, built with `-Ctarget-cpu=native` and
`halo2-base/asm` which pulls in tuned x86-64 assembly (`mul_mont_sparse_256` /
`sqr_mont_sparse_256` from BLST). Same code path the arithonly tracegen uses.

**GPU** — sppark-style `mont_t<254, ALT_BN128_r, 0xefffffff, ...>` from
`openvm-cuda-common` (locally vendored under `cuda/include/ff/`), compiled with
nvcc. Every kernel is launched with `<<<1, 1>>>` — one CUDA thread runs the
entire chain, so we're measuring **single-thread latency**, not throughput.

Correctness check: after each workload, the CPU result and the GPU result (read
back via `cudaMemcpy`) are compared bit-for-bit and the program panics on
divergence. Fr values are transported as raw 4-limb Montgomery-form limbs — both
sides use the same limb layout and Montgomery constant `M0 =
0xc2e1f593efffffff`, so no conversion is needed at the boundary.

## Build & run

```bash
RUSTFLAGS="-Ctarget-cpu=native" cargo +nightly-2026-01-18 build \
  -p bn254-perf --release --features halo2-base/asm
./target/release/bn254-perf
```

Or with the wrapper:

```bash
bin/bn254-perf/run.sh
```

Env vars:
- `BN254_ITERS` (default 1_000_000): iteration count for non-inversion chains.
- `BN254_INV_ITERS` (default 50_000): iteration count for `inv`.

## Layout

```
bin/bn254-perf/
├── Cargo.toml
├── build.rs                     # invokes openvm-cuda-builder → libbn254_perf.a
├── run.sh
├── cuda/
│   ├── include/ff/
│   │   ├── alt_bn128.cuh        # local copy; adds host-side fr_t/fp_t stubs
│   │   └── mont_t.cuh           # local copy of sppark's Montgomery template
│   └── src/bench.cu             # 6 single-thread kernels + FFI launcher
└── src/main.rs                  # CPU workloads, timing harness, comparison
```

`cuda/include/ff/alt_bn128.cuh` is a copy from `openvm-cuda-common` with a
`#ifndef __CUDA_ARCH__` host-side stub added: nvcc's host-compile pass sees
`fr_t` as a POD `{ uint32_t val[8]; }` with no-op operators so kernel signatures
type-check in both passes; the device-compile pass gets the real
`mont_t<254, ...>` and its operators. Only sizeof matters at the CPU↔GPU
boundary.

## Representative results (RTX 5090 · AMD 9950X3D · CUDA 13.0)

```
op                  iters       cpu (ms)       gpu (ms)    gpu/cpu    cpu (ns/op)
--------------------------------------------------------------------------------
mul               1000000         21.749        141.553       6.51x          21.75
sqr               1000000         19.471        238.616      12.26x          19.47
sbox (x^5)        1000000         64.575        382.380       5.92x          21.52
mul_add           1000000         28.122        160.411       5.70x          14.06
add               1000000          3.498         21.692       6.20x           3.50
inv                 50000        100.385       1425.331      14.20x        2007.70
```

Interpretation:

- **CPU is 6-14× faster than a single CUDA thread** for BN254 scalar chains,
  which is expected. CPU has tuned mulx-based Montgomery in x86-64 asm
  (~22 ns per `Fr::mul` including the modular reduction); GPU single-thread
  Montgomery via sppark's u32-limb school-book runs at similar per-op latency
  in cycles but the GPU clock is much lower (~2 GHz vs CPU's ~5 GHz boost).
- `sqr` is only ~10% faster than `mul` on CPU (BLST does actual `sqr_mont`) but
  ~1.7× *slower* than `mul` on GPU because sppark's device-side `sqr(x)` is
  implemented as `x * x` without a specialized squaring path.
- `add` shows the raw modular-add cost: ~3.5 ns on CPU, ~22 ns on GPU. This
  ratio (~6×) is a reasonable floor for the CPU↔GPU single-thread gap on this
  hardware.
- `inv` on CPU is ~2 μs per binary-GCD inversion (BLST's `eucl_inverse`).
  Roughly 92× a `mul` — matches the "50-150×" ballpark cited in halo2
  documentation, and validates why the arithonly `FrRepr` variant paid a
  measurable cost only when `is_zero` chains inversions.

The takeaway: **for the arithonly tracegen workload — mostly sequential Fr muls
with data dependencies — moving to GPU makes sense only if you can parallelize
across many independent chains** (e.g. many Merkle-path Poseidon2 hashes at
once, one CUDA thread per hash). A single-threaded kernel is always going to
lose to a single CPU thread with tuned assembly.
