//! Per-opcode microbenchmarks of [`eval_inst`]. Each op is run in a
//! dependency-chained loop (the first operand of iteration k+1 is an output
//! of iteration k) so the measured time is latency, not just throughput.

use std::time::Instant;

use halo2_base::halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};

use super::{
    interp::eval_inst,
    ir::{Opcode, Program, ALL_OPCODES, NUM_OPCODES},
};

const ITERS: u32 = 20_000;
const WARMUP: u32 = 1_000;

/// Most common aux among the program's instances of `target` (falls back to
/// a sane default), so aux-dependent ops (Decompose limb count, DivModU32
/// divisor) are measured on representative work.
fn representative_aux(prog: &Program, target: Opcode) -> u32 {
    let mut counts: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
    for inst in &prog.insts {
        if inst.op == target as u8 {
            *counts.entry(inst.aux).or_default() += 1;
        }
    }
    counts.into_iter().max_by_key(|&(_, c)| c).map(|(a, _)| a).unwrap_or(match target {
        Opcode::Decompose => (16 << 8) | 16,
        Opcode::DivModU32 => 0x78000001,
        _ => 0,
    })
}

fn bench_one(op: Opcode, aux: u32) -> f64 {
    let inputs = [Fr::from(0xdead_beef_u64)];
    let consts = [Fr::from(0x1234_u64)];
    // Non-zero pseudo-random operands: divisor-position args (BbDiv's b,
    // Ext4Div's b) stay fixed and invertible; av[0] is overwritten by the
    // dependency chain.
    let mut av = [Fr::ZERO; 9];
    for (i, v) in av.iter_mut().enumerate() {
        *v = Fr::from(0x9e37_79b9_7f4a_7c15_u64.wrapping_mul(i as u64 + 1) | 1);
    }
    let mut out = vec![Fr::ZERO; op.out_count(aux)];

    for _ in 0..WARMUP {
        eval_inst(op, aux, &inputs, &consts, &av, &mut out);
        av[0] = out[0];
    }
    let start = Instant::now();
    for _ in 0..ITERS {
        eval_inst(op, aux, &inputs, &consts, &av, &mut out);
        av[0] = out[0];
    }
    let elapsed = start.elapsed();
    std::hint::black_box((&av, &out));
    elapsed.as_nanos() as f64 / ITERS as f64
}

/// Measure the average latency of each opcode; prints a table alongside each
/// op's total contribution to the program's serial work.
pub fn measure_op_ns(prog: &Program) -> [f64; NUM_OPCODES] {
    let counts = super::stats::opcode_histogram(prog);
    let mut ns = [0f64; NUM_OPCODES];
    for op in ALL_OPCODES {
        let aux = match op {
            Opcode::Decompose | Opcode::DivModU32 => representative_aux(prog, op),
            _ => 0,
        };
        ns[op as usize] = bench_one(op, aux);
    }

    let mut rows: Vec<Opcode> =
        ALL_OPCODES.into_iter().filter(|&op| counts[op as usize] > 0).collect();
    rows.sort_by(|&a, &b| {
        let wa = ns[a as usize] * counts[a as usize] as f64;
        let wb = ns[b as usize] * counts[b as usize] as f64;
        wb.partial_cmp(&wa).unwrap()
    });
    eprintln!("[bench] per-op latency ({ITERS} chained iters each); program-weighted totals:");
    for op in rows {
        let t = ns[op as usize];
        let c = counts[op as usize];
        eprintln!(
            "[bench]   {:<18} {:>9.1} ns  x {:>6} insts = {:>8.2} ms",
            op.name(),
            t,
            c,
            t * c as f64 * 1e-6
        );
    }
    ns
}
