//! Static-verifier tracegen IR pipeline.
//!
//! Milestones:
//! 1. Eager witness generation vs. IR build + interpretation (equivalence).
//! 2. C codegen from the IR, compiled + dlopen'd, equivalence + perf.
//!
//! See README.md for env knobs and baseline numbers.

mod backend;
mod cgen;
mod chip;
mod eager;
mod hash;
mod hints;
mod ir;
mod proof_wire;
mod transcript;
mod verify;
mod wire;

use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use eyre::{eyre, Result};
use openvm_continuations::RootSC;
use openvm_sdk::fs::read_object_from_file;
use openvm_stark_sdk::{
    bench::run_with_metric_collection,
    openvm_stark_backend::{codec::Decode, proof::Proof},
};
use openvm_static_verifier::StaticVerifierProvingKey;
use tracing::info_span;

use backend::BabyBearExt4Inst;
use chip::{BabyBearChip, BabyBearExt4Chip, RangeChip};
use eager::{EagerBackend, EagerCtx};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use ir::{IrBackend, IrCtx};
use verify::full_pipeline::{constrained_verify, load_proof_wire};

fn cache_dir() -> PathBuf {
    match std::env::var("STATIC_VERIFIER_CACHE_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => Path::new("cache").to_path_buf(),
    }
}

/// Run the full pipeline (proof loading + constrained verify) once under
/// backend `B`, returning the finished context.
fn run_pipeline<B: BabyBearExt4Inst>(
    ctx: &mut B::Ctx,
    static_verifier_pk: &StaticVerifierProvingKey,
    root_proof: &Proof<RootSC>,
    lookup_bits: usize,
) {
    let range = Arc::new(RangeChip::<B>::new(lookup_bits));
    let base = BabyBearChip::<B>::new(range);
    let ext_chip = BabyBearExt4Chip::<B>::new(base);

    let proof_wire = load_proof_wire(
        ctx,
        &ext_chip,
        root_proof,
        &static_verifier_pk.circuit.log_heights_per_air,
    );
    constrained_verify(
        ctx,
        &ext_chip,
        &static_verifier_pk.circuit.root_vk,
        &proof_wire,
        &static_verifier_pk.circuit.trace_id_to_air_id,
        &static_verifier_pk.circuit.log_heights_per_air,
        &static_verifier_pk.circuit.stacked_layouts,
    );
}

fn run_eager(
    static_verifier_pk: &StaticVerifierProvingKey,
    root_proof: &Proof<RootSC>,
    lookup_bits: usize,
    iters: usize,
) -> (Vec<Fr>, std::time::Duration) {
    let mut golden = None;
    let start = Instant::now();
    info_span!("svir_eager", iters).in_scope(|| {
        for _ in 0..iters {
            let mut ctx = EagerCtx::new();
            run_pipeline::<EagerBackend>(&mut ctx, static_verifier_pk, root_proof, lookup_bits);
            if let Some(prev) = &golden {
                assert_eq!(*prev, ctx.witness, "witness stream must be deterministic");
            }
            golden = Some(ctx.witness);
        }
    });
    let elapsed = start.elapsed();
    let per_iter = elapsed / iters as u32;
    let golden = golden.unwrap();
    eprintln!(
        "[eager] {} iters: total {:?}, per-iter {:?}, witness slots: {}",
        iters,
        elapsed,
        per_iter,
        golden.len()
    );
    metrics::gauge!("svir.eager.per_iter_ns").set(per_iter.as_nanos() as f64);
    metrics::gauge!("svir.eager.witness_slots").set(golden.len() as f64);
    (golden, per_iter)
}

/// M1: build the IR, print stats, dump it, interpret it, and check the
/// interpreted witness stream is identical to the eager one.
fn run_ir_m1(
    static_verifier_pk: &StaticVerifierProvingKey,
    root_proof: &Proof<RootSC>,
    lookup_bits: usize,
    golden: &[Fr],
) -> Result<IrCtx> {
    let start = Instant::now();
    let mut ctx = IrCtx::new();
    info_span!("svir_ir_build").in_scope(|| {
        run_pipeline::<IrBackend>(&mut ctx, static_verifier_pk, root_proof, lookup_bits);
    });
    let build_time = start.elapsed();
    eprintln!("[ir] build: {build_time:?}");
    metrics::gauge!("svir.ir.build_ns").set(build_time.as_nanos() as f64);

    assert_eq!(
        ctx.prog.num_slots as usize,
        golden.len(),
        "IR slot count must match eager witness length"
    );
    ir::stats::print_stats(&ctx.prog);

    let out_dir = std::env::var("SVIR_OUT_DIR").unwrap_or_else(|_| "output/svir-gen".into());
    std::fs::create_dir_all(&out_dir)?;
    let ir_path = Path::new(&out_dir).join("program.svir");
    let start = Instant::now();
    let mut writer = std::io::BufWriter::new(File::create(&ir_path)?);
    ir::serde::write_program(&mut writer, &ctx.prog, &ctx.inputs)?;
    std::io::Write::flush(&mut writer)?;
    let dump_time = start.elapsed();
    eprintln!(
        "[ir] dumped {} ({} bytes) in {:?}",
        ir_path.display(),
        std::fs::metadata(&ir_path)?.len(),
        dump_time
    );

    let start = Instant::now();
    let interpreted =
        info_span!("svir_ir_interp").in_scope(|| ir::interp::interpret(&ctx.prog, &ctx.inputs));
    let interp_time = start.elapsed();
    eprintln!("[ir] interpret: {interp_time:?}");
    metrics::gauge!("svir.ir.interp_ns").set(interp_time.as_nanos() as f64);

    if let Some(bad_slot) = (0..golden.len()).find(|&i| interpreted[i] != golden[i]) {
        report_mismatch(&ctx.prog, &interpreted, golden, bad_slot);
        return Err(eyre!("M1 FAIL: interpreted IR diverges at slot {bad_slot}"));
    }
    eprintln!("[M1 PASS] interpreted IR == eager witness stream ({} slots)", golden.len());
    Ok(ctx)
}

/// M2: generate C from the IR, compile it to a shared object, dlopen it, run
/// it, and compare against the golden witness stream. Reports codegen /
/// compile / run timings and speedup vs. eager.
fn run_c_m2(
    ir_ctx: &IrCtx,
    golden: &[Fr],
    iters: usize,
    eager_per_iter: std::time::Duration,
) -> Result<()> {
    cgen::assert_fr_layout();

    let out_dir = std::env::var("SVIR_OUT_DIR").unwrap_or_else(|_| "output/svir-gen".into());
    let dir = Path::new(&out_dir).join("c");
    let start = Instant::now();
    let generated =
        info_span!("svir_c_codegen").in_scope(|| cgen::codegen::generate(&ir_ctx.prog, &dir))?;
    let codegen_time = start.elapsed();
    eprintln!(
        "[c] codegen: {} files, {} chunks in {:?}",
        generated.c_files.len(),
        generated.num_chunks,
        codegen_time
    );
    metrics::gauge!("svir.c.codegen_ns").set(codegen_time.as_nanos() as f64);

    let start = Instant::now();
    let so = info_span!("svir_c_compile")
        .in_scope(|| cgen::compile::compile(&dir, &generated.c_files))?;
    let compile_time = start.elapsed();
    eprintln!("[c] compile+link: {:?} -> {}", compile_time, so.display());
    metrics::gauge!("svir.c.compile_ns").set(compile_time.as_nanos() as f64);

    let compiled = cgen::runner::Compiled::load(&so)?;
    let num_slots = ir_ctx.prog.num_slots as usize;

    // Warm-up + equivalence check.
    let got = compiled.run(&ir_ctx.inputs, num_slots);
    if let Some(bad_slot) = (0..golden.len()).find(|&i| got[i] != golden[i]) {
        report_mismatch(&ir_ctx.prog, &got, golden, bad_slot);
        return Err(eyre!("M2 FAIL: C witness diverges at slot {bad_slot}"));
    }

    let start = Instant::now();
    info_span!("svir_c_run", iters).in_scope(|| {
        for _ in 0..iters {
            std::hint::black_box(compiled.run(&ir_ctx.inputs, num_slots));
        }
    });
    let per_iter = start.elapsed() / iters as u32;
    metrics::gauge!("svir.c.per_iter_ns").set(per_iter.as_nanos() as f64);

    eprintln!("[M2 PASS] C witness == eager witness stream ({} slots)", golden.len());
    eprintln!(
        "[c] per-iter {:?} vs eager {:?} ({:.2}x)",
        per_iter,
        eager_per_iter,
        eager_per_iter.as_secs_f64() / per_iter.as_secs_f64()
    );
    Ok(())
}

fn par_threads() -> usize {
    std::env::var("SVIR_PAR_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(8, |n| n.get()))
}

/// Graph analysis: level-width histogram, per-op microbenchmarks, and the
/// theoretical lower bounds they imply for parallel execution.
fn run_analysis(ir_ctx: &IrCtx, eager_per_iter: std::time::Duration) {
    ir::stats::print_level_histogram(&ir_ctx.prog);
    let op_ns = ir::microbench::measure_op_ns(&ir_ctx.prog);
    ir::stats::print_lower_bound(&ir_ctx.prog, &op_ns, par_threads(), eager_per_iter);
}

/// Parallel lock-free graph evaluation of the IR. Metadata build and the
/// per-run atomic-flag reset are reported but excluded from the benchmarked
/// run time.
fn run_par(ir_ctx: &IrCtx, golden: &[Fr], iters: usize, eager_per_iter: std::time::Duration) {
    let n_threads = par_threads();
    let chunk_size: usize =
        std::env::var("SVIR_PAR_CHUNK").ok().and_then(|s| s.parse().ok()).unwrap_or(16384);

    let start = Instant::now();
    let evaluator = ir::par_eval::ParEvaluator::new(&ir_ctx.prog);
    let meta_time = start.elapsed();
    eprintln!("[par] metadata build: {meta_time:?} (excluded from run time)");
    metrics::gauge!("svir.par.meta_ns").set(meta_time.as_nanos() as f64);

    // Warm-up + equivalence check.
    evaluator.reset();
    let got = evaluator.run(&ir_ctx.inputs, n_threads, chunk_size);
    if let Some(bad_slot) = (0..golden.len()).find(|&i| got[i] != golden[i]) {
        report_mismatch(&ir_ctx.prog, &got, golden, bad_slot);
        panic!("PAR FAIL: parallel witness diverges at slot {bad_slot}");
    }

    // Instrumented run: per-op eval time + spin time (excluded from the
    // benchmark; timer reads inflate cheap ops).
    let t = Instant::now();
    for _ in 0..1_000_000 {
        std::hint::black_box(Instant::now());
    }
    let timer_ns = t.elapsed().as_nanos() as f64 / 1e6;
    evaluator.reset();
    let start = Instant::now();
    let (_, prof) = evaluator.run_profiled(&ir_ctx.inputs, n_threads, chunk_size);
    let prof_wall = start.elapsed();
    let eval_total_ns: u64 = prof.op_ns.iter().sum();
    let n_insts: u64 = prof.op_count.iter().sum();
    eprintln!(
        "[par] profiled run: wall {:?}; cpu across threads: eval {:.1} ms, spin {:.1} ms \
         (timer overhead ~{:.0} ns/sample, ~{:.1} ms total)",
        prof_wall,
        eval_total_ns as f64 * 1e-6,
        prof.spin_ns as f64 * 1e-6,
        timer_ns,
        2.0 * timer_ns * n_insts as f64 * 1e-6,
    );
    let mut rows: Vec<usize> = (0..prof.op_ns.len()).filter(|&i| prof.op_count[i] > 0).collect();
    rows.sort_by_key(|&i| std::cmp::Reverse(prof.op_ns[i]));
    for i in rows {
        eprintln!(
            "[par]   {:<18} {:>6} insts  {:>8.2} ms total  {:>8.1} ns avg  ({:>4.1}% of eval)",
            ir::ir::ALL_OPCODES[i].name(),
            prof.op_count[i],
            prof.op_ns[i] as f64 * 1e-6,
            prof.op_ns[i] as f64 / prof.op_count[i] as f64,
            100.0 * prof.op_ns[i] as f64 / eval_total_ns as f64,
        );
    }
    metrics::gauge!("svir.par.spin_ms").set(prof.spin_ns as f64 * 1e-6);

    let mut total = std::time::Duration::ZERO;
    info_span!("svir_par_run", iters, n_threads, chunk_size).in_scope(|| {
        for _ in 0..iters {
            evaluator.reset();
            let start = Instant::now();
            let w = evaluator.run(&ir_ctx.inputs, n_threads, chunk_size);
            total += start.elapsed();
            std::hint::black_box(w);
        }
    });
    let per_iter = total / iters as u32;
    metrics::gauge!("svir.par.per_iter_ns").set(per_iter.as_nanos() as f64);

    eprintln!("[PAR PASS] parallel witness == eager witness stream ({} slots)", golden.len());
    eprintln!(
        "[par] threads {}, chunk {}: per-iter {:?} vs eager {:?} ({:.2}x)",
        n_threads,
        chunk_size,
        per_iter,
        eager_per_iter,
        eager_per_iter.as_secs_f64() / per_iter.as_secs_f64()
    );
}

/// Levelized parallel evaluation: instructions reordered by dependency
/// level, one spin barrier per level, no per-slot flags. Metadata build is
/// reported but excluded from the benchmarked run time; no per-run reset
/// exists.
fn run_level(ir_ctx: &IrCtx, golden: &[Fr], iters: usize, eager_per_iter: std::time::Duration) {
    let n_threads = par_threads();

    let start = Instant::now();
    let evaluator = ir::level_eval::LevelEvaluator::new(&ir_ctx.prog);
    let meta_time = start.elapsed();
    eprintln!("[lvl] metadata build (levelize + sort): {meta_time:?} (excluded from run time)");
    metrics::gauge!("svir.lvl.meta_ns").set(meta_time.as_nanos() as f64);

    // Warm-up + equivalence check.
    let got = evaluator.run(&ir_ctx.inputs, n_threads);
    if let Some(bad_slot) = (0..golden.len()).find(|&i| got[i] != golden[i]) {
        report_mismatch(&ir_ctx.prog, &got, golden, bad_slot);
        panic!("LVL FAIL: levelized witness diverges at slot {bad_slot}");
    }

    let mut total = std::time::Duration::ZERO;
    info_span!("svir_lvl_run", iters, n_threads).in_scope(|| {
        for _ in 0..iters {
            let start = Instant::now();
            let w = evaluator.run(&ir_ctx.inputs, n_threads);
            total += start.elapsed();
            std::hint::black_box(w);
        }
    });
    let per_iter = total / iters as u32;
    metrics::gauge!("svir.lvl.per_iter_ns").set(per_iter.as_nanos() as f64);

    eprintln!("[LVL PASS] levelized witness == eager witness stream ({} slots)", golden.len());
    eprintln!(
        "[lvl] threads {}: per-iter {:?} vs eager {:?} ({:.2}x)",
        n_threads,
        per_iter,
        eager_per_iter,
        eager_per_iter.as_secs_f64() / per_iter.as_secs_f64()
    );
}

fn report_mismatch(prog: &ir::ir::Program, interpreted: &[Fr], golden: &[Fr], bad_slot: usize) {
    ir::ir::walk(prog, |idx, op, inst, args, out_base| {
        let n_out = op.out_count(inst.aux);
        if (out_base as usize..out_base as usize + n_out).contains(&bad_slot) {
            eprintln!(
                "[ir] mismatch at slot {bad_slot}: inst #{idx} {} aux={} args={:?}",
                op.name(),
                inst.aux,
                args
            );
            for &a in args {
                eprintln!("[ir]   arg slot {a}: {:?}", interpreted[a as usize]);
            }
            eprintln!(
                "[ir]   interpreted: {:?}\n[ir]   eager:       {:?}",
                interpreted[bad_slot], golden[bad_slot]
            );
        }
    });
}

fn main() -> Result<()> {
    let cache = cache_dir();
    let pk_path = cache.join("static_verifier_pk.bin");
    let root_proof_path = cache.join("root_proof.bitcode");

    if !pk_path.exists() {
        return Err(eyre!(
            "static_verifier_pk cache not found at {:?}. \
             Generate it by running the sibling binary first: \
             `cargo run -p static-verifier-tracegen --release`.",
            pk_path
        ));
    }
    if !root_proof_path.exists() {
        return Err(eyre!("root_proof cache not found at {:?}.", root_proof_path));
    }

    eprintln!("reusing static verifier pk from {:?}", pk_path);
    let mut reader = BufReader::new(File::open(&pk_path)?);
    let static_verifier_pk = StaticVerifierProvingKey::decode(&mut reader)?;
    let root_proof: Proof<RootSC> = read_object_from_file(&root_proof_path)?;

    let lookup_bits = static_verifier_pk.pinning.metadata.config_params.lookup_bits.unwrap_or(15);
    let iters: usize = std::env::var("SVIR_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    eprintln!("running eager pipeline {iters}x (lookup_bits={lookup_bits})");

    run_with_metric_collection("OUTPUT_PATH", || -> Result<()> {
        let (golden, eager_per_iter) =
            run_eager(&static_verifier_pk, &root_proof, lookup_bits, iters);
        let ir_ctx = run_ir_m1(&static_verifier_pk, &root_proof, lookup_bits, &golden)?;
        run_analysis(&ir_ctx, eager_per_iter);
        if std::env::var("SVIR_SKIP_C").is_err() {
            run_c_m2(&ir_ctx, &golden, iters, eager_per_iter)?;
        }
        run_par(&ir_ctx, &golden, iters, eager_per_iter);
        run_level(&ir_ctx, &golden, iters, eager_per_iter);
        Ok(())
    })?;

    Ok(())
}
