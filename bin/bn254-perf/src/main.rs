//! CPU vs single-thread-GPU BN254 scalar micro-benchmarks.
//!
//! Six workloads, each a chained sequence of BN254 Fr ops representative of the
//! arithonly tracegen hot path:
//!
//! - `mul`       : `x <- x * a`                    (single Fr mul per iter)
//! - `sqr`       : `x <- x * x`                    (single Fr sqr per iter)
//! - `sbox`      : `x <- x^5`                      (Poseidon2 sbox: 3 muls per iter)
//! - `mul_add`   : `x <- x * a + b`                (mul + add per iter — Horner/FMA)
//! - `add`       : `x <- x + a`                    (single Fr add per iter)
//! - `inv`       : `x <- x.invert() + a`           (Fr binary-GCD invert per iter)
//!
//! CPU: `halo2curves-axiom` Fr, `-C target-cpu=native` + `--features halo2-asm`
//! swaps in tuned x86-64 assembly for `mul_mont_sparse_256`.
//! GPU: sppark-style `mont_t<254, ...>` from `openvm-cuda-common`, launched with
//! `<<<1, 1>>>` so we measure single-thread Montgomery cost, not throughput.

use std::hint::black_box;
use std::time::Instant;

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
// `Field` trait needed for `.square()` / `.invert()` methods on Fr.
use halo2_base::halo2_proofs::arithmetic::Field;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct BenchResult {
    elapsed_ms: f32,
    result: [u64; 4],
}

#[link(name = "bn254_perf", kind = "static")]
unsafe extern "C" {
    fn bn254_perf_run(
        op: libc::c_int,
        x_limbs: *const u64,
        a_limbs: *const u64,
        b_limbs: *const u64,
        n: u64,
        out: *mut BenchResult,
    ) -> libc::c_int;
}

#[derive(Copy, Clone, Debug)]
#[repr(i32)]
enum Op {
    Mul = 0,
    Sqr = 1,
    Sbox = 2,
    MulAdd = 3,
    Add = 4,
    Inv = 5,
}

impl Op {
    fn label(&self) -> &'static str {
        match self {
            Op::Mul => "mul",
            Op::Sqr => "sqr",
            Op::Sbox => "sbox (x^5)",
            Op::MulAdd => "mul_add",
            Op::Add => "add",
            Op::Inv => "inv",
        }
    }

    /// Roughly how many field ops per outer iteration.
    fn ops_per_iter(&self) -> u64 {
        match self {
            Op::Mul | Op::Sqr | Op::Add | Op::Inv => 1,
            Op::MulAdd => 2,
            Op::Sbox => 3,
        }
    }
}

// -- Fr <-> u64[4] helpers --------------------------------------------------

/// Extract the raw *Montgomery-form* 4-limb representation from a `Fr`.
///
/// `halo2curves-axiom` stores `Fr` internally as `[u64; 4]` in Montgomery form
/// (see the type comment in `bn256/fr.rs`). The public `to_repr` API converts
/// **out** of Montgomery form — which is not what we want for round-tripping
/// with the device-side `mont_t<254, ...>` (also Montgomery-form).
///
/// The internal `[u64; 4]` field is `pub(crate)` so we can't destructure it,
/// but `Fr` is a single-field tuple struct over `[u64; 4]` with derived `Copy`,
/// so `sizeof(Fr) == sizeof([u64; 4])` and a byte-level reinterpret preserves
/// the Montgomery limbs bit-for-bit. `size_of` asserts pin this at compile
/// time.
const _: () = assert!(std::mem::size_of::<Fr>() == 32);

fn fr_to_limbs(fr: Fr) -> [u64; 4] {
    unsafe { std::mem::transmute::<Fr, [u64; 4]>(fr) }
}

fn limbs_to_fr(limbs: [u64; 4]) -> Fr {
    unsafe { std::mem::transmute::<[u64; 4], Fr>(limbs) }
}

// -- CPU workloads ----------------------------------------------------------

// Each workload uses `black_box` on the loop variable and constants so LLVM
// can't hoist / eliminate the chain. The compiler still keeps the arithmetic
// in registers, but every op has a data dependency on the previous result.

fn cpu_mul(x0: Fr, a: Fr, n: u64) -> Fr {
    let a = black_box(a);
    let mut x = black_box(x0);
    for _ in 0..n {
        x *= a;
    }
    black_box(x)
}

fn cpu_sqr(x0: Fr, n: u64) -> Fr {
    let mut x = black_box(x0);
    for _ in 0..n {
        x = x.square();
    }
    black_box(x)
}

fn cpu_sbox(x0: Fr, n: u64) -> Fr {
    let mut x = black_box(x0);
    for _ in 0..n {
        let x2 = x.square();
        let x4 = x2.square();
        x = x4 * x;
    }
    black_box(x)
}

fn cpu_mul_add(x0: Fr, a: Fr, b: Fr, n: u64) -> Fr {
    let a = black_box(a);
    let b = black_box(b);
    let mut x = black_box(x0);
    for _ in 0..n {
        x = x * a + b;
    }
    black_box(x)
}

fn cpu_add(x0: Fr, a: Fr, n: u64) -> Fr {
    let a = black_box(a);
    let mut x = black_box(x0);
    for _ in 0..n {
        x += a;
    }
    black_box(x)
}

fn cpu_inv(x0: Fr, a: Fr, n: u64) -> Fr {
    let a = black_box(a);
    let mut x = black_box(x0);
    for _ in 0..n {
        x = x.invert().unwrap() + a;
    }
    black_box(x)
}

fn run_cpu(op: Op, x: Fr, a: Fr, b: Fr, n: u64) -> (Fr, f64) {
    let start = Instant::now();
    let result = match op {
        Op::Mul => cpu_mul(x, a, n),
        Op::Sqr => cpu_sqr(x, n),
        Op::Sbox => cpu_sbox(x, n),
        Op::MulAdd => cpu_mul_add(x, a, b, n),
        Op::Add => cpu_add(x, a, n),
        Op::Inv => cpu_inv(x, a, n),
    };
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    (result, elapsed_ms)
}

fn run_gpu(op: Op, x: Fr, a: Fr, b: Fr, n: u64) -> (Fr, f64) {
    let x_limbs = fr_to_limbs(x);
    let a_limbs = fr_to_limbs(a);
    let b_limbs = fr_to_limbs(b);
    let mut out = BenchResult::default();
    let rc = unsafe {
        bn254_perf_run(
            op as libc::c_int,
            x_limbs.as_ptr(),
            a_limbs.as_ptr(),
            b_limbs.as_ptr(),
            n,
            &mut out,
        )
    };
    assert_eq!(rc, 0, "bn254_perf_run failed with rc={rc} on op={op:?}");
    (limbs_to_fr(out.result), out.elapsed_ms as f64)
}

fn main() {
    let n_default: u64 = 1_000_000;
    let n: u64 = std::env::var("BN254_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(n_default);
    // Inversion is ~50-150x slower than mul, so we scale down its iteration
    // count to keep the run under a reasonable wall-clock.
    let n_inv: u64 = std::env::var("BN254_INV_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50_000);

    // Deterministic non-trivial inputs. Reduce a > 1 so the chain doesn't
    // collapse to a fixed point on any op.
    let x = Fr::from(0x123456789abcdefu64);
    let a = Fr::from(0xcafebabecafeu64);
    let b = Fr::from(0xdeadbeefu64);

    // Warm-up: first GPU launch pays cudaMalloc / driver init.
    let _ = run_gpu(Op::Mul, x, a, b, 1);

    let ops = [Op::Mul, Op::Sqr, Op::Sbox, Op::MulAdd, Op::Add, Op::Inv];

    println!(
        "\n{:12} {:>12} {:>14} {:>14} {:>10} {:>14}",
        "op", "iters", "cpu (ms)", "gpu (ms)", "gpu/cpu", "cpu (ns/op)"
    );
    println!("{:-<80}", "");

    for op in ops {
        let iters = match op {
            Op::Inv => n_inv,
            _ => n,
        };

        let (cpu_result, cpu_ms) = run_cpu(op, x, a, b, iters);
        let (gpu_result, gpu_ms) = run_gpu(op, x, a, b, iters);

        // Sanity: both paths should produce the same Fr for the same op.
        assert_eq!(
            cpu_result, gpu_result,
            "cpu/gpu diverged on op={:?} (cpu={:?}, gpu={:?})",
            op, cpu_result, gpu_result,
        );

        let ratio = gpu_ms / cpu_ms;
        let cpu_ns_per_op = cpu_ms * 1e6 / (iters as f64 * op.ops_per_iter() as f64);
        println!(
            "{:12} {:>12} {:>14.3} {:>14.3} {:>10.2}x {:>14.2}",
            op.label(),
            iters,
            cpu_ms,
            gpu_ms,
            ratio,
            cpu_ns_per_op,
        );
    }

    println!(
        "\nNotes:"
    );
    println!("  - GPU launched with <<<1, 1>>> — single CUDA thread per chain.");
    println!("  - CPU uses halo2curves-axiom `Fr` with tuned x86-64 asm.");
    println!("  - Chains are data-dependent; results are checked to match bit-for-bit.");
}
