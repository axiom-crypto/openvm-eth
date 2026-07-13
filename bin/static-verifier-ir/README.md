# static-verifier-ir

IR-generation pipeline for the halo2 static-verifier tracegen
(`populate_verify_stark_constraints`). The same generic chip/verify code runs
under two backends:

- **eager** (`src/eager/`): computes every op immediately, appending each
  result to a witness stream (`Vec<Fr>`, one slot per op output in program
  order). This is the golden reference and the perf baseline.
- **IR** (`src/ir/`): emits a straight-line SSA program (`Opcode` + slot ids)
  and captures the concrete inputs. The program can be interpreted in Rust
  (`ir/interp.rs`), compiled to C (`src/cgen/`): chunked codegen → `cc` →
  `dlopen` → run in-process, or evaluated in parallel:
  - `ir/par_eval.rs`: lock-free, threads claim fixed-size chunks of the
    topologically-sorted instruction vec and spin on per-slot atomic done
    flags for operands.
  - `ir/level_eval.rs`: levelized — instructions are counting-sorted by ASAP
    dependency level; everything within one level is independent, so threads
    run disjoint slices with no per-slot flags, one spin barrier per level.
    Each instruction carries its write offset into the witness buffer, so
    reordering needs no output permutation.

Because both backends share the chip code, the witness streams are identical
by construction; the harness asserts bit-equality end to end.

## Running

Needs the caches produced by the sibling binary (`static_verifier_pk.bin`,
`root_proof.bitcode` in `./cache` or `$STATIC_VERIFIER_CACHE_DIR`):

```
cargo run -p static-verifier-tracegen --release   # once, to build caches
cargo run -p static-verifier-ir --release         # from the workspace root
cargo test -p static-verifier-ir --release
```

## Env knobs

| Variable | Default | Meaning |
| --- | --- | --- |
| `STATIC_VERIFIER_CACHE_DIR` | `cache` | pk/proof cache directory |
| `SVIR_ITERS` | `3` | timed iterations for eager and C runs |
| `SVIR_OUT_DIR` | `output/svir-gen` | IR dump + generated C output dir |
| `SVIR_OPS_PER_FN` | `4096` | IR insts per generated C function |
| `SVIR_FNS_PER_FILE` | `4` | chunk functions per generated `.c` file |
| `SVIR_CC` | `cc` | C compiler |
| `SVIR_CFLAGS` | `-O0` | flags for chunk files (see below) |
| `SVIR_OPS_CFLAGS` | `-O3 -march=native` | flags for `ops.c` (field arithmetic) |
| `SVIR_SKIP_C` | unset | set to skip the C codegen/compile/run stage |
| `SVIR_PAR_THREADS` | available parallelism | threads for the parallel evaluators |
| `SVIR_PAR_CHUNK` | `16384` | instructions per claimed chunk (chunked parallel evaluator) |

The generated chunk files are huge straight-line functions; gcc's time and
memory blow up super-linearly on them at `-O1+` (tens of minutes / multi-GB),
so chunks default to `-O0` and all field math lives in `ops.c`, compiled once
at `-O3 -march=native` and called through extern functions.

## Baseline numbers (2026-07-13, 16-core x86-64, gcc 13)

Program: 373,225 insts / 941,072 witness slots / 42,126 inputs / 342 consts.
Dependency graph: depth 5,523, max level width 47,366 (level 1), mean width
59.9 but **median 5** — a long thin chain with wide bursts. Microbenched
op latencies × graph structure give critical path T_inf ≈ 15.5 ms (a chain
of ~1,700 Poseidon2 permutations) and a zero-barrier levelized bound of
~21.6 ms at 16 threads.

| Stage | Time |
| --- | --- |
| eager witness gen (per iter) | ~151 ms |
| IR build | ~21 ms |
| IR interpret | ~176 ms |
| C codegen (26 files, 92 chunks) | ~0.11 s |
| C compile + link | ~29 s |
| C run (per iter) | ~249 ms (0.75x eager) |
| chunked par eval metadata build | ~10 ms (excluded from run time) |
| chunked par eval run (per iter) | ~145 ms (1.04x eager) |
| levelized eval metadata build | ~31 ms (excluded from run time) |
| levelized eval run (per iter, 12 threads) | ~63 ms (2.4x eager) |

The serial C run is slower than eager because eager uses halo2curves'
hand-optimized Montgomery mul while the C backend uses portable CIOS plus
call overhead.

The chunked evaluator plateaus near 1x: profiling shows ~1.2 s of CPU spin
vs ~130 ms of eval across 16 threads — the program order interleaves
dependent instructions tightly, so chunk pipelining only overlaps adjacent
chunks.

The levelized evaluator sweep: 2 threads 108 ms, 4 → 87 ms, 8 → 69 ms,
12 → 63 ms, 16 → 64 ms. It stops scaling because with median level width 5,
most of the 5,523 barriers synchronize threads that had almost no work; the
gap to the ~22 ms bound is barrier overhead. Closing it would need level
fusion (merge narrow adjacent levels into one thread's serial run) or
dropping to fewer threads on narrow regions.
