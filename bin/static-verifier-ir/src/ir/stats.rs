//! Opcode histogram and dependency-graph statistics (depth, level widths,
//! average parallelism).

use super::ir::{walk, Opcode, Program, ALL_OPCODES, NUM_OPCODES};

pub struct GraphStats {
    /// Longest dependency chain (levels; inputs/consts sit at level 0).
    pub depth: u32,
    /// Max instructions at any level >= 1, i.e. max evaluable in parallel.
    pub max_width: u64,
    /// Level at which `max_width` occurs.
    pub max_width_level: u32,
    /// Evaluable instructions (level >= 1) divided by depth.
    pub avg_parallelism: f64,
    /// Instructions at level 0 (Input/Const).
    pub level0_nodes: u64,
    /// Instructions at level >= 1.
    pub eval_nodes: u64,
}

/// Instruction count per ASAP level (index = level; level 0 = Input/Const).
pub fn level_width_table(prog: &Program) -> Vec<u64> {
    let mut slot_level = vec![0u32; prog.num_slots as usize];
    let mut width_at: Vec<u64> = Vec::new();
    walk(prog, |_idx, op, inst, args, out_base| {
        let level = match op {
            Opcode::Input | Opcode::Const => 0,
            _ => 1 + args.iter().map(|&a| slot_level[a as usize]).max().unwrap(),
        };
        let n_out = op.out_count(inst.aux);
        for s in out_base..out_base + n_out as u32 {
            slot_level[s as usize] = level;
        }
        if width_at.len() <= level as usize {
            width_at.resize(level as usize + 1, 0);
        }
        width_at[level as usize] += 1;
    });
    width_at
}

pub fn graph_stats(prog: &Program) -> GraphStats {
    let width_at = level_width_table(prog);
    let depth = (width_at.len() - 1) as u32;
    let (max_width_level, max_width) = width_at
        .iter()
        .enumerate()
        .skip(1)
        .max_by_key(|(_, w)| **w)
        .map(|(l, &w)| (l as u32, w))
        .unwrap_or((0, 0));
    let level0_nodes = width_at.first().copied().unwrap_or(0);
    let eval_nodes: u64 = width_at.iter().skip(1).sum();
    GraphStats {
        depth,
        max_width,
        max_width_level,
        avg_parallelism: eval_nodes as f64 / depth.max(1) as f64,
        level0_nodes,
        eval_nodes,
    }
}

/// Histogram of level widths (power-of-two buckets) plus mean/median/std of
/// the width over levels `1..=depth`.
pub fn print_level_histogram(prog: &Program) {
    let width_at = level_width_table(prog);
    let mut widths: Vec<u64> = width_at[1..].to_vec();
    let n = widths.len();
    let mean = widths.iter().sum::<u64>() as f64 / n as f64;
    let var = widths.iter().map(|&w| (w as f64 - mean).powi(2)).sum::<f64>() / n as f64;
    widths.sort_unstable();
    let median = widths[n / 2];
    let max = *widths.last().unwrap();
    eprintln!(
        "[ir] level widths over {} levels: mean {:.1}, median {}, std {:.1}, max {}",
        n,
        mean,
        median,
        var.sqrt(),
        max
    );

    let mut bucket_levels = [0u64; 64];
    let mut bucket_insts = [0u64; 64];
    for &w in &widths {
        let b = (63 - w.leading_zeros()) as usize; // floor(log2(w)); every level is non-empty
        bucket_levels[b] += 1;
        bucket_insts[b] += w;
    }
    eprintln!("[ir] level width histogram:");
    for b in 0..64 {
        if bucket_levels[b] == 0 {
            continue;
        }
        let lo = 1u64 << b;
        let hi = (1u64 << (b + 1)) - 1;
        eprintln!(
            "[ir]   width {:>5}-{:<5} : {:>5} levels, {:>7} insts ({:>4.1}% of levels)",
            lo,
            hi,
            bucket_levels[b],
            bucket_insts[b],
            100.0 * bucket_levels[b] as f64 / n as f64
        );
    }
}

/// Theoretical lower bounds on graph execution time given per-opcode times
/// (ns): critical path (infinite threads), work / `n_threads`, and a
/// levelized-schedule estimate with zero barrier overhead.
pub fn print_lower_bound(
    prog: &Program,
    op_ns: &[f64; NUM_OPCODES],
    n_threads: usize,
    eager_per_iter: std::time::Duration,
) {
    let mut finish = vec![0f64; prog.num_slots as usize];
    let mut slot_level = vec![0u32; prog.num_slots as usize];
    let mut level_work: Vec<f64> = Vec::new();
    let mut level_max: Vec<f64> = Vec::new();
    let mut total_work = 0f64;
    let mut critical_path = 0f64;
    walk(prog, |_idx, op, inst, args, out_base| {
        let t = op_ns[op as usize];
        total_work += t;
        let (start, arg_lvl) = args.iter().fold((0f64, 0u32), |(s, l), &a| {
            (s.max(finish[a as usize]), l.max(slot_level[a as usize]))
        });
        let level = match op {
            Opcode::Input | Opcode::Const => 0,
            _ => arg_lvl + 1,
        };
        let f = start + t;
        critical_path = critical_path.max(f);
        let n_out = op.out_count(inst.aux);
        for s in out_base..out_base + n_out as u32 {
            finish[s as usize] = f;
            slot_level[s as usize] = level;
        }
        if level_work.len() <= level as usize {
            level_work.resize(level as usize + 1, 0.0);
            level_max.resize(level as usize + 1, 0.0);
        }
        level_work[level as usize] += t;
        level_max[level as usize] = level_max[level as usize].max(t);
    });

    let p = n_threads as f64;
    let work_over_p = total_work / p;
    let lb = critical_path.max(work_over_p);
    let levelized: f64 = level_work.iter().zip(&level_max).map(|(&w, &m)| (w / p).max(m)).sum();
    let eager_ms = eager_per_iter.as_secs_f64() * 1e3;
    let ms = 1e-6;
    eprintln!(
        "[bound] total work {:.1} ms (serial sum of op times); eager {:.1} ms",
        total_work * ms,
        eager_ms
    );
    eprintln!(
        "[bound] critical path T_inf = {:.2} ms ({:.1}x eager max speedup, infinite threads)",
        critical_path * ms,
        eager_ms / (critical_path * ms)
    );
    eprintln!(
        "[bound] work / {} threads = {:.2} ms; lower bound LB({}) = max(T_inf, work/P) = {:.2} ms \
         ({:.1}x eager)",
        n_threads,
        work_over_p * ms,
        n_threads,
        lb * ms,
        eager_ms / (lb * ms)
    );
    eprintln!(
        "[bound] levelized schedule, zero barrier cost: sum_L max(work_L/P, max_op_L) = {:.2} ms \
         ({:.1}x eager)",
        levelized * ms,
        eager_ms / (levelized * ms)
    );
    metrics::gauge!("svir.bound.critical_path_ms").set(critical_path * ms);
    metrics::gauge!("svir.bound.levelized_ms").set(levelized * ms);
}

pub fn opcode_histogram(prog: &Program) -> [u64; NUM_OPCODES] {
    let mut counts = [0u64; NUM_OPCODES];
    for inst in &prog.insts {
        counts[inst.op as usize] += 1;
    }
    counts
}

pub fn print_stats(prog: &Program) {
    eprintln!(
        "[ir] insts: {}, slots: {}, inputs: {}, consts: {}, spill words: {}",
        prog.insts.len(),
        prog.num_slots,
        prog.num_inputs,
        prog.consts.len(),
        prog.spill.len()
    );
    let counts = opcode_histogram(prog);
    let mut sorted: Vec<(Opcode, u64)> =
        ALL_OPCODES.iter().map(|&op| (op, counts[op as usize])).filter(|&(_, c)| c > 0).collect();
    sorted.sort_by_key(|&(_, c)| std::cmp::Reverse(c));
    for (op, count) in sorted {
        eprintln!("[ir]   {:<18} {}", op.name(), count);
    }

    let g = graph_stats(prog);
    eprintln!(
        "[ir] graph: depth {}, max parallel {} (at level {}), avg parallelism {:.1} \
         ({} eval nodes, {} input/const nodes)",
        g.depth, g.max_width, g.max_width_level, g.avg_parallelism, g.eval_nodes, g.level0_nodes
    );
    metrics::gauge!("svir.ir.insts").set(prog.insts.len() as f64);
    metrics::gauge!("svir.ir.graph_depth").set(g.depth as f64);
    metrics::gauge!("svir.ir.max_parallelism").set(g.max_width as f64);
    metrics::gauge!("svir.ir.avg_parallelism").set(g.avg_parallelism);
}
