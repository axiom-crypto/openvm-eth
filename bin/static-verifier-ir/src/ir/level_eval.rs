//! Levelized parallel evaluator for a [`Program`].
//!
//! Instructions are reordered by ASAP dependency level (level 0 =
//! Input/Const, otherwise 1 + max level of the operands). Everything within
//! one level is mutually independent, so threads execute disjoint contiguous
//! slices of a level with no per-slot synchronization; one spin barrier per
//! level orders the levels. Each instruction carries its write offset into
//! the witness buffer (`MetaInst::out_base`), so reordering needs no output
//! permutation — the buffer stays in program-order slot layout.

use std::sync::atomic::{AtomicUsize, Ordering};

use halo2_base::halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};

use super::{
    interp::eval_inst,
    ir::{walk, Opcode, Program},
    par_eval::{MetaInst, WitnessPtr},
};

pub struct LevelEvaluator {
    /// Instructions sorted by level, stable (program order) within a level.
    insts: Vec<MetaInst>,
    /// Flattened operand slot offsets, in `insts` order.
    args: Vec<u32>,
    consts: Vec<Fr>,
    /// Level `L` occupies `insts[level_starts[L]..level_starts[L + 1]]`.
    level_starts: Vec<u32>,
    num_slots: usize,
}

/// Sense-reversing spin barrier. The generation release/acquire pair makes
/// every write before `wait()` visible to every thread after it.
struct SpinBarrier {
    count: AtomicUsize,
    generation: AtomicUsize,
    n: usize,
}

impl SpinBarrier {
    fn new(n: usize) -> Self {
        SpinBarrier { count: AtomicUsize::new(0), generation: AtomicUsize::new(0), n }
    }

    fn wait(&self) {
        let generation = self.generation.load(Ordering::Acquire);
        if self.count.fetch_add(1, Ordering::AcqRel) + 1 == self.n {
            self.count.store(0, Ordering::Relaxed);
            self.generation.store(generation + 1, Ordering::Release);
        } else {
            while self.generation.load(Ordering::Acquire) == generation {
                std::hint::spin_loop();
            }
        }
    }
}

impl LevelEvaluator {
    /// Compute levels and reorder the metadata (stable counting sort by
    /// level). Not part of the benchmarked run time.
    pub fn new(prog: &Program) -> Self {
        let n = prog.insts.len();
        let mut slot_level = vec![0u32; prog.num_slots as usize];
        let mut metas: Vec<(MetaInst, u32)> = Vec::with_capacity(n);
        let mut flat = Vec::new();
        let mut n_levels = 1u32;
        walk(prog, |_idx, op, inst, args, out_base| {
            let level = match op {
                Opcode::Input | Opcode::Const => 0,
                _ => 1 + args.iter().map(|&a| slot_level[a as usize]).max().unwrap(),
            };
            let n_out = op.out_count(inst.aux);
            for s in out_base..out_base + n_out as u32 {
                slot_level[s as usize] = level;
            }
            n_levels = n_levels.max(level + 1);
            let arg_off = flat.len() as u32;
            flat.extend_from_slice(args);
            metas.push((
                MetaInst {
                    op,
                    n_args: args.len() as u8,
                    n_out: n_out as u8,
                    aux: inst.aux,
                    out_base,
                    arg_off,
                },
                level,
            ));
        });

        let mut level_starts = vec![0u32; n_levels as usize + 1];
        for &(_, l) in &metas {
            level_starts[l as usize + 1] += 1;
        }
        for i in 1..level_starts.len() {
            level_starts[i] += level_starts[i - 1];
        }
        let mut cursor: Vec<u32> = level_starts[..n_levels as usize].to_vec();
        let mut order = vec![0u32; n];
        for (idx, &(_, l)) in metas.iter().enumerate() {
            order[cursor[l as usize] as usize] = idx as u32;
            cursor[l as usize] += 1;
        }

        let mut insts = Vec::with_capacity(n);
        let mut args = Vec::with_capacity(flat.len());
        for &idx in &order {
            let (mut m, _) = metas[idx as usize];
            let a = &flat[m.arg_off as usize..m.arg_off as usize + m.n_args as usize];
            m.arg_off = args.len() as u32;
            args.extend_from_slice(a);
            insts.push(m);
        }

        LevelEvaluator {
            insts,
            args,
            consts: prog.consts.clone(),
            level_starts,
            num_slots: prog.num_slots as usize,
        }
    }

    /// Evaluate the program with `n_threads` threads, level by level. No
    /// per-run reset is needed (there are no per-slot flags).
    pub fn run(&self, inputs: &[Fr], n_threads: usize) -> Vec<Fr> {
        let mut w = vec![Fr::ZERO; self.num_slots];
        let wp = WitnessPtr(w.as_mut_ptr());
        let barrier = SpinBarrier::new(n_threads);
        let n_levels = self.level_starts.len() - 1;
        std::thread::scope(|s| {
            for t in 0..n_threads {
                let barrier = &barrier;
                s.spawn(move || {
                    for l in 0..n_levels {
                        let start = self.level_starts[l] as usize;
                        let end = self.level_starts[l + 1] as usize;
                        let per = (end - start).div_ceil(n_threads);
                        let my_start = (start + t * per).min(end);
                        let my_end = (my_start + per).min(end);
                        for m in &self.insts[my_start..my_end] {
                            self.eval_one(m, inputs, wp);
                        }
                        barrier.wait();
                    }
                });
            }
        });
        w
    }

    fn eval_one(&self, m: &MetaInst, inputs: &[Fr], wp: WitnessPtr) {
        let args = &self.args[m.arg_off as usize..m.arg_off as usize + m.n_args as usize];
        let mut av = [Fr::ZERO; 9];
        for (i, &a) in args.iter().enumerate() {
            // Operands were produced in an earlier level, ordered by the
            // barrier's release/acquire.
            av[i] = unsafe { *wp.0.add(a as usize) };
        }
        // Exclusive: these output slots belong to this instruction alone.
        let out = unsafe {
            std::slice::from_raw_parts_mut(wp.0.add(m.out_base as usize), m.n_out as usize)
        };
        eval_inst(m.op, m.aux, inputs, &self.consts, &av, out);
    }
}
