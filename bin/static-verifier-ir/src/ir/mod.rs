//! IR backend: allocates witness-slot ids and records instructions instead of
//! computing values. `input()` captures the concrete `Fr` so the recorded
//! program can be replayed against the same proof.

pub mod interp;
#[allow(clippy::module_inception)]
pub mod ir;
pub mod level_eval;
pub mod microbench;
pub mod par_eval;
pub mod serde;
pub mod stats;

use std::collections::HashMap;

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

use crate::backend::{BabyBearExt4Inst, BabyBearInst, Backend};
use ir::{Inst, Opcode, Program};

#[derive(Default)]
pub struct IrCtx {
    pub prog: Program,
    pub inputs: Vec<Fr>,
    const_cache: HashMap<[u8; 32], u32>,
}

impl IrCtx {
    pub fn new() -> Self {
        Self::default()
    }

    fn emit(&mut self, op: Opcode, aux: u32, args: &[u32]) -> u32 {
        debug_assert_eq!(args.len(), op.arg_count());
        let inst = if op.uses_spill() {
            let off = u32::try_from(self.prog.spill.len()).unwrap();
            self.prog.spill.extend_from_slice(args);
            Inst { op: op as u8, aux: off, args: [0; 3] }
        } else {
            let mut inline = [0u32; 3];
            inline[..args.len()].copy_from_slice(args);
            Inst { op: op as u8, aux, args: inline }
        };
        let out_base = self.prog.num_slots;
        self.prog.num_slots =
            out_base.checked_add(op.out_count(aux) as u32).expect("slot count overflow");
        self.prog.insts.push(inst);
        out_base
    }
}

#[derive(Copy, Clone, Debug)]
pub struct IrBackend;

impl Backend for IrBackend {
    const NAME: &'static str = "ir";

    type V = u32;
    type Ctx = IrCtx;

    fn input(ctx: &mut IrCtx, value: Fr) -> u32 {
        let idx = u32::try_from(ctx.inputs.len()).unwrap();
        ctx.inputs.push(value);
        ctx.prog.num_inputs += 1;
        ctx.emit(Opcode::Input, idx, &[])
    }

    fn constant(ctx: &mut IrCtx, value: Fr) -> u32 {
        if let Some(&slot) = ctx.const_cache.get(&value.to_bytes()) {
            return slot;
        }
        let idx = u32::try_from(ctx.prog.consts.len()).unwrap();
        ctx.prog.consts.push(value);
        let slot = ctx.emit(Opcode::Const, idx, &[]);
        ctx.const_cache.insert(value.to_bytes(), slot);
        slot
    }

    fn add(ctx: &mut IrCtx, a: u32, b: u32) -> u32 {
        ctx.emit(Opcode::Add, 0, &[a, b])
    }
    fn sub(ctx: &mut IrCtx, a: u32, b: u32) -> u32 {
        ctx.emit(Opcode::Sub, 0, &[a, b])
    }
    fn mul(ctx: &mut IrCtx, a: u32, b: u32) -> u32 {
        ctx.emit(Opcode::Mul, 0, &[a, b])
    }
    fn neg(ctx: &mut IrCtx, a: u32) -> u32 {
        ctx.emit(Opcode::Neg, 0, &[a])
    }
    fn mul_add(ctx: &mut IrCtx, a: u32, b: u32, c: u32) -> u32 {
        ctx.emit(Opcode::MulAdd, 0, &[a, b, c])
    }
    fn sub_mul(ctx: &mut IrCtx, a: u32, b: u32, c: u32) -> u32 {
        ctx.emit(Opcode::SubMul, 0, &[a, b, c])
    }
    fn select(ctx: &mut IrCtx, a: u32, b: u32, sel: u32) -> u32 {
        ctx.emit(Opcode::Select, 0, &[a, b, sel])
    }

    fn is_zero(ctx: &mut IrCtx, a: u32) -> (u32, u32) {
        let base = ctx.emit(Opcode::IsZero, 0, &[a]);
        (base, base + 1)
    }

    fn div_mod_u32(ctx: &mut IrCtx, a: u32, divisor: u32) -> (u32, u32) {
        assert!(divisor != 0);
        let base = ctx.emit(Opcode::DivModU32, divisor, &[a]);
        (base, base + 1)
    }

    fn decompose(ctx: &mut IrCtx, a: u32, num_limbs: u32, limb_bits: u32) -> Vec<u32> {
        assert!(num_limbs > 0 && num_limbs < (1 << 24) && limb_bits > 0 && limb_bits < 256);
        let aux = (num_limbs << 8) | limb_bits;
        let base = ctx.emit(Opcode::Decompose, aux, &[a]);
        (base..base + num_limbs).collect()
    }

    fn bn_to_bb_digits(ctx: &mut IrCtx, packed: u32) -> ([u32; 5], u32) {
        let base = ctx.emit(Opcode::BnToBb5, 0, &[packed]);
        (core::array::from_fn(|i| base + i as u32), base + 5)
    }

    fn poseidon2_t3(ctx: &mut IrCtx, state: [u32; 3]) -> [u32; 3] {
        let base = ctx.emit(Opcode::Poseidon2T3, 0, &state);
        core::array::from_fn(|i| base + i as u32)
    }

    fn poseidon2_t2(ctx: &mut IrCtx, state: [u32; 2]) -> [u32; 2] {
        let base = ctx.emit(Opcode::Poseidon2T2, 0, &state);
        core::array::from_fn(|i| base + i as u32)
    }
}

impl BabyBearInst for IrBackend {
    fn bb_add(ctx: &mut IrCtx, a: u32, b: u32) -> u32 {
        ctx.emit(Opcode::BbAdd, 0, &[a, b])
    }
    fn bb_sub(ctx: &mut IrCtx, a: u32, b: u32) -> u32 {
        ctx.emit(Opcode::BbSub, 0, &[a, b])
    }
    fn bb_neg(ctx: &mut IrCtx, a: u32) -> u32 {
        ctx.emit(Opcode::BbNeg, 0, &[a])
    }
    fn bb_mul(ctx: &mut IrCtx, a: u32, b: u32) -> u32 {
        ctx.emit(Opcode::BbMul, 0, &[a, b])
    }
    fn bb_mul_add(ctx: &mut IrCtx, a: u32, b: u32, c: u32) -> u32 {
        ctx.emit(Opcode::BbMulAdd, 0, &[a, b, c])
    }
    fn bb_reduce(ctx: &mut IrCtx, a: u32) -> u32 {
        ctx.emit(Opcode::BbReduce, 0, &[a])
    }
    fn bb_div(ctx: &mut IrCtx, a: u32, b: u32) -> u32 {
        ctx.emit(Opcode::BbDiv, 0, &[a, b])
    }
}

fn out4(base: u32) -> [u32; 4] {
    core::array::from_fn(|i| base + i as u32)
}

fn cat2(a: [u32; 4], b: [u32; 4]) -> [u32; 8] {
    core::array::from_fn(|i| if i < 4 { a[i] } else { b[i - 4] })
}

impl BabyBearExt4Inst for IrBackend {
    fn ext4_add(ctx: &mut IrCtx, a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
        out4(ctx.emit(Opcode::Ext4Add, 0, &cat2(a, b)))
    }
    fn ext4_sub(ctx: &mut IrCtx, a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
        out4(ctx.emit(Opcode::Ext4Sub, 0, &cat2(a, b)))
    }
    fn ext4_neg(ctx: &mut IrCtx, a: [u32; 4]) -> [u32; 4] {
        out4(ctx.emit(Opcode::Ext4Neg, 0, &a))
    }
    fn ext4_scalar_mul(ctx: &mut IrCtx, a: [u32; 4], b: u32) -> [u32; 4] {
        let args = [a[0], a[1], a[2], a[3], b];
        out4(ctx.emit(Opcode::Ext4ScalarMul, 0, &args))
    }
    fn ext4_scalar_mul_add(ctx: &mut IrCtx, a: [u32; 4], b: u32, c: [u32; 4]) -> [u32; 4] {
        let args = [a[0], a[1], a[2], a[3], b, c[0], c[1], c[2], c[3]];
        out4(ctx.emit(Opcode::Ext4ScalarMulAdd, 0, &args))
    }
    fn ext4_mul(ctx: &mut IrCtx, a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
        out4(ctx.emit(Opcode::Ext4Mul, 0, &cat2(a, b)))
    }
    fn ext4_reduce(ctx: &mut IrCtx, a: [u32; 4]) -> [u32; 4] {
        out4(ctx.emit(Opcode::Ext4Reduce, 0, &a))
    }
    fn ext4_div(ctx: &mut IrCtx, a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
        out4(ctx.emit(Opcode::Ext4Div, 0, &cat2(a, b)))
    }
}

/// Emits every opcode at least once, pinning the multi-output slot contract
/// across backends. Test-only helper shared with the C backend tests.
#[cfg(test)]
pub(crate) fn exercise_all_opcodes<B: BabyBearExt4Inst>(ctx: &mut B::Ctx) {
    let a = B::input(ctx, Fr::from(123_456_789u64));
    let b = B::input(ctx, Fr::from(987_654_321u64));
    let c = B::constant(ctx, Fr::from(7u64));
    let c_dup = B::constant(ctx, Fr::from(7u64)); // dedup: no new slot
    let d = B::add(ctx, a, b);
    let e = B::sub(ctx, d, c);
    let f = B::mul(ctx, e, a);
    let g = B::neg(ctx, f);
    let h = B::mul_add(ctx, a, b, g);
    let i = B::sub_mul(ctx, h, a, b);
    let sel = B::constant(ctx, Fr::from(1u64));
    let s = B::select(ctx, a, b, sel);
    let (_inv, _ind) = B::is_zero(ctx, s);
    let (_q, _r) = B::div_mod_u32(ctx, f, 0x78000001);
    let _limbs = B::decompose(ctx, h, 16, 16);
    let (_d5, _top) = B::bn_to_bb_digits(ctx, i);
    let p3 = B::poseidon2_t3(ctx, [a, b, d]);
    let _p2 = B::poseidon2_t2(ctx, [p3[0], p3[1]]);

    let x = B::bb_add(ctx, a, b);
    let y = B::bb_sub(ctx, x, a);
    let z = B::bb_neg(ctx, y);
    let m = B::bb_mul(ctx, x, y);
    let ma = B::bb_mul_add(ctx, x, y, z);
    let red = B::bb_reduce(ctx, ma);
    let _dv = B::bb_div(ctx, m, red);

    let ea = [a, b, d, e];
    let eb = [f, g, h, i];
    let s1 = B::ext4_add(ctx, ea, eb);
    let s2 = B::ext4_sub(ctx, s1, ea);
    let s3 = B::ext4_neg(ctx, s2);
    let s4 = B::ext4_scalar_mul(ctx, s3, a);
    let s5 = B::ext4_scalar_mul_add(ctx, s4, b, s1);
    let s6 = B::ext4_mul(ctx, s5, s2);
    let s7 = B::ext4_reduce(ctx, s6);
    let _s8 = B::ext4_div(ctx, s6, s7);
    let _ = c_dup;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eager::{EagerBackend, EagerCtx};

    fn build_ir() -> IrCtx {
        let mut ctx = IrCtx::new();
        exercise_all_opcodes::<IrBackend>(&mut ctx);
        ctx
    }

    #[test]
    fn all_opcodes_interp_matches_eager() {
        let mut eager = EagerCtx::new();
        exercise_all_opcodes::<EagerBackend>(&mut eager);

        let ir_ctx = build_ir();
        let hist = stats::opcode_histogram(&ir_ctx.prog);
        for op in ir::ALL_OPCODES {
            assert!(hist[op as usize] > 0, "opcode {} not exercised", op.name());
        }

        assert_eq!(ir_ctx.prog.num_slots as usize, eager.witness.len());
        let interpreted = interp::interpret(&ir_ctx.prog, &ir_ctx.inputs);
        assert_eq!(interpreted, eager.witness);
    }

    #[test]
    fn serde_round_trip() {
        let ir_ctx = build_ir();
        let mut buf = Vec::new();
        serde::write_program(&mut buf, &ir_ctx.prog, &ir_ctx.inputs).unwrap();
        let (prog, inputs) = serde::read_program(&mut buf.as_slice()).unwrap();

        assert_eq!(prog.num_inputs, ir_ctx.prog.num_inputs);
        assert_eq!(prog.num_slots, ir_ctx.prog.num_slots);
        assert_eq!(prog.insts.len(), ir_ctx.prog.insts.len());
        assert_eq!(prog.spill, ir_ctx.prog.spill);
        assert_eq!(prog.consts, ir_ctx.prog.consts);
        assert_eq!(inputs, ir_ctx.inputs);
        assert_eq!(
            interp::interpret(&prog, &inputs),
            interp::interpret(&ir_ctx.prog, &ir_ctx.inputs)
        );
    }

    #[test]
    fn all_opcodes_par_eval_matches_eager() {
        let mut eager = EagerCtx::new();
        exercise_all_opcodes::<EagerBackend>(&mut eager);

        let ir_ctx = build_ir();
        let ev = par_eval::ParEvaluator::new(&ir_ctx.prog);
        for chunk_size in [1, 3, 64] {
            ev.reset();
            let got = ev.run(&ir_ctx.inputs, 4, chunk_size);
            assert_eq!(got, eager.witness, "chunk_size {chunk_size}");
        }
    }

    #[test]
    fn all_opcodes_level_eval_matches_eager() {
        let mut eager = EagerCtx::new();
        exercise_all_opcodes::<EagerBackend>(&mut eager);

        let ir_ctx = build_ir();
        let ev = level_eval::LevelEvaluator::new(&ir_ctx.prog);
        for n_threads in [1, 4] {
            let got = ev.run(&ir_ctx.inputs, n_threads);
            assert_eq!(got, eager.witness, "n_threads {n_threads}");
        }
    }

    #[test]
    fn graph_stats_sane() {
        let ir_ctx = build_ir();
        let g = stats::graph_stats(&ir_ctx.prog);
        assert!(g.depth >= 1);
        assert!(g.max_width >= 1);
        assert_eq!(g.eval_nodes + g.level0_nodes, ir_ctx.prog.insts.len() as u64);
    }
}
