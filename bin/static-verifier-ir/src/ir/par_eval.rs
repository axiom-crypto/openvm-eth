//! Lock-free parallel evaluator for a [`Program`].
//!
//! Metadata built once per program: each instruction gets the offset of its
//! output slots and the offsets of its operand slots (spill args flattened).
//! Execution: threads claim fixed-size chunks of the topologically-sorted
//! instruction vec via an atomic counter. Each instruction spins until all of
//! its operand slots are marked done (per-slot atomic flags), evaluates, then
//! marks its own output slots done. Chunks are claimed in increasing order,
//! so the earliest incomplete chunk only ever depends on finished chunks —
//! progress is guaranteed without locks.

use std::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Instant,
};

use halo2_base::halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};

use super::{
    interp::eval_inst,
    ir::{walk, Opcode, Program, NUM_OPCODES},
};

/// Execution metadata for one instruction (16 bytes). `out_base` is the
/// instruction's write offset into the witness buffer, so evaluators may
/// reorder instructions without permuting the output.
#[derive(Copy, Clone)]
pub(super) struct MetaInst {
    pub(super) op: Opcode,
    pub(super) n_args: u8,
    pub(super) n_out: u8,
    /// Opcode-specific immediate (input/const index, divisor, limb spec).
    pub(super) aux: u32,
    /// First output slot; outputs occupy `out_base..out_base + n_out`.
    pub(super) out_base: u32,
    /// Offset of this instruction's operand slot ids in the evaluator's flat
    /// args table.
    pub(super) arg_off: u32,
}

pub struct ParEvaluator {
    insts: Vec<MetaInst>,
    /// Flattened operand slot offsets for all instructions (spill resolved).
    args: Vec<u32>,
    consts: Vec<Fr>,
    /// One "done" flag per witness slot.
    done: Vec<AtomicBool>,
    num_slots: usize,
}

// Shared mutable witness buffer. Sound because every slot is written by
// exactly one instruction and reads are ordered after that write (via the
// per-slot done flag here, or the level barrier in the levelized evaluator).
#[derive(Clone, Copy)]
pub(super) struct WitnessPtr(pub(super) *mut Fr);
unsafe impl Send for WitnessPtr {}
unsafe impl Sync for WitnessPtr {}

impl ParEvaluator {
    /// Build the offset tables. Not part of the benchmarked run time.
    pub fn new(prog: &Program) -> Self {
        let mut insts = Vec::with_capacity(prog.insts.len());
        let mut args_flat = Vec::new();
        walk(prog, |_idx, op, inst, args, out_base| {
            let arg_off = args_flat.len() as u32;
            args_flat.extend_from_slice(args);
            insts.push(MetaInst {
                op,
                n_args: args.len() as u8,
                n_out: op.out_count(inst.aux) as u8,
                aux: inst.aux,
                out_base,
                arg_off,
            });
        });
        let num_slots = prog.num_slots as usize;
        ParEvaluator {
            insts,
            args: args_flat,
            consts: prog.consts.clone(),
            done: (0..num_slots).map(|_| AtomicBool::new(false)).collect(),
            num_slots,
        }
    }

    /// Clear the done flags for the next run. Not part of the benchmarked
    /// run time.
    pub fn reset(&self) {
        for f in &self.done {
            f.store(false, Ordering::Relaxed);
        }
    }

    /// Evaluate the program with `n_threads` threads over chunks of
    /// `chunk_size` instructions. `reset()` must have been called since the
    /// previous run.
    pub fn run(&self, inputs: &[Fr], n_threads: usize, chunk_size: usize) -> Vec<Fr> {
        let mut w = vec![Fr::ZERO; self.num_slots];
        let wp = WitnessPtr(w.as_mut_ptr());
        let n_chunks = self.insts.len().div_ceil(chunk_size);
        let next = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..n_threads {
                let next = &next;
                s.spawn(move || loop {
                    let c = next.fetch_add(1, Ordering::Relaxed);
                    if c >= n_chunks {
                        break;
                    }
                    let start = c * chunk_size;
                    let end = ((c + 1) * chunk_size).min(self.insts.len());
                    for m in &self.insts[start..end] {
                        self.eval_one(m, inputs, wp);
                    }
                });
            }
        });
        w
    }

    /// Same as [`run`](Self::run) but with per-opcode eval-time and spin-time
    /// accounting (~2 timer reads per instruction; not for benchmarking).
    /// `reset()` must have been called since the previous run.
    pub fn run_profiled(
        &self,
        inputs: &[Fr],
        n_threads: usize,
        chunk_size: usize,
    ) -> (Vec<Fr>, ParProfile) {
        let mut w = vec![Fr::ZERO; self.num_slots];
        let wp = WitnessPtr(w.as_mut_ptr());
        let n_chunks = self.insts.len().div_ceil(chunk_size);
        let next = AtomicUsize::new(0);
        let mut total = ParProfile::default();
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..n_threads)
                .map(|_| {
                    let next = &next;
                    s.spawn(move || {
                        let mut prof = ParProfile::default();
                        loop {
                            let c = next.fetch_add(1, Ordering::Relaxed);
                            if c >= n_chunks {
                                break;
                            }
                            let start = c * chunk_size;
                            let end = ((c + 1) * chunk_size).min(self.insts.len());
                            for m in &self.insts[start..end] {
                                self.eval_one_profiled(m, inputs, wp, &mut prof);
                            }
                        }
                        prof
                    })
                })
                .collect();
            for h in handles {
                total.merge(&h.join().unwrap());
            }
        });
        (w, total)
    }

    fn eval_one(&self, m: &MetaInst, inputs: &[Fr], wp: WitnessPtr) {
        let args = &self.args[m.arg_off as usize..m.arg_off as usize + m.n_args as usize];
        let mut av = [Fr::ZERO; 9];
        for (i, &a) in args.iter().enumerate() {
            while !self.done[a as usize].load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            av[i] = unsafe { *wp.0.add(a as usize) };
        }
        // Exclusive: these output slots belong to this instruction alone.
        let out = unsafe {
            std::slice::from_raw_parts_mut(wp.0.add(m.out_base as usize), m.n_out as usize)
        };
        eval_inst(m.op, m.aux, inputs, &self.consts, &av, out);
        for s in m.out_base..m.out_base + m.n_out as u32 {
            self.done[s as usize].store(true, Ordering::Release);
        }
    }

    fn eval_one_profiled(
        &self,
        m: &MetaInst,
        inputs: &[Fr],
        wp: WitnessPtr,
        prof: &mut ParProfile,
    ) {
        let args = &self.args[m.arg_off as usize..m.arg_off as usize + m.n_args as usize];
        let mut av = [Fr::ZERO; 9];
        for (i, &a) in args.iter().enumerate() {
            if !self.done[a as usize].load(Ordering::Acquire) {
                let spin_start = Instant::now();
                while !self.done[a as usize].load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                prof.spin_ns += spin_start.elapsed().as_nanos() as u64;
            }
            av[i] = unsafe { *wp.0.add(a as usize) };
        }
        let out = unsafe {
            std::slice::from_raw_parts_mut(wp.0.add(m.out_base as usize), m.n_out as usize)
        };
        let eval_start = Instant::now();
        eval_inst(m.op, m.aux, inputs, &self.consts, &av, out);
        prof.op_ns[m.op as usize] += eval_start.elapsed().as_nanos() as u64;
        prof.op_count[m.op as usize] += 1;
        for s in m.out_base..m.out_base + m.n_out as u32 {
            self.done[s as usize].store(true, Ordering::Release);
        }
    }
}

/// Merged per-thread accounting from a profiled run. Times are summed over
/// threads, i.e. CPU time, not wall time.
pub struct ParProfile {
    pub op_ns: [u64; NUM_OPCODES],
    pub op_count: [u64; NUM_OPCODES],
    pub spin_ns: u64,
}

impl Default for ParProfile {
    fn default() -> Self {
        ParProfile { op_ns: [0; NUM_OPCODES], op_count: [0; NUM_OPCODES], spin_ns: 0 }
    }
}

impl ParProfile {
    fn merge(&mut self, other: &ParProfile) {
        for i in 0..NUM_OPCODES {
            self.op_ns[i] += other.op_ns[i];
            self.op_count[i] += other.op_count[i];
        }
        self.spin_ns += other.spin_ns;
    }
}
