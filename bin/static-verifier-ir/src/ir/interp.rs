//! Reference interpreter: evaluates a [`Program`] over concrete `Fr` values.
//! Hint ops call the same `hints` functions as the eager backend, so the
//! output stream is bit-identical to eager by construction.

use halo2_base::halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};

use super::ir::{walk, Opcode, Program};
use crate::hints;

/// Evaluate one instruction: operand values in `av`, results written to
/// `out` (`out.len() == op.out_count(aux)`). Shared by the sequential
/// interpreter and the parallel evaluator.
pub(crate) fn eval_inst(
    op: Opcode,
    aux: u32,
    inputs: &[Fr],
    consts: &[Fr],
    av: &[Fr],
    out: &mut [Fr],
) {
    let g = |i: usize| av[i];
    use Opcode::*;
    match op {
        Input => out[0] = inputs[aux as usize],
        Const => out[0] = consts[aux as usize],
        Add | BbAdd => out[0] = g(0) + g(1),
        Sub | BbSub => out[0] = g(0) - g(1),
        Mul | BbMul => out[0] = g(0) * g(1),
        Neg | BbNeg => out[0] = -g(0),
        MulAdd | BbMulAdd => out[0] = g(0) * g(1) + g(2),
        SubMul => out[0] = g(0) - g(1) * g(2),
        Select => out[0] = (g(0) - g(1)) * g(2) + g(1),
        IsZero => {
            let (inv_or_zero, indicator) = hints::is_zero_hint(g(0));
            out[0] = inv_or_zero;
            out[1] = indicator;
        }
        DivModU32 => {
            let (quot, rem) = hints::div_mod_u32_hint(g(0), aux);
            out[0] = quot;
            out[1] = rem;
        }
        Decompose => {
            let num_limbs = aux >> 8;
            let limb_bits = aux & 0xff;
            let limbs = hints::decompose_hint(g(0), num_limbs, limb_bits);
            out[..num_limbs as usize].copy_from_slice(&limbs);
        }
        BnToBb5 => {
            let (digits, top) = hints::bn_to_bb_digits_hint(g(0));
            out[..5].copy_from_slice(&digits);
            out[5] = top;
        }
        Poseidon2T3 => {
            let s = hints::poseidon2_t3_hint([g(0), g(1), g(2)]);
            out[..3].copy_from_slice(&s);
        }
        Poseidon2T2 => {
            let s = hints::poseidon2_t2_hint([g(0), g(1)]);
            out[..2].copy_from_slice(&s);
        }
        BbReduce => out[0] = hints::bb_reduce_hint(g(0)),
        BbDiv => out[0] = hints::bb_div_hint(g(0), g(1)),
        Ext4Add => {
            for i in 0..4 {
                out[i] = g(i) + g(i + 4);
            }
        }
        Ext4Sub => {
            for i in 0..4 {
                out[i] = g(i) - g(i + 4);
            }
        }
        Ext4Neg => {
            for i in 0..4 {
                out[i] = -g(i);
            }
        }
        Ext4ScalarMul => {
            for i in 0..4 {
                out[i] = g(i) * g(4);
            }
        }
        Ext4ScalarMulAdd => {
            for i in 0..4 {
                out[i] = g(i) * g(4) + g(5 + i);
            }
        }
        Ext4Mul => {
            let r = hints::ext4_mul_fr([g(0), g(1), g(2), g(3)], [g(4), g(5), g(6), g(7)]);
            out[..4].copy_from_slice(&r);
        }
        Ext4Reduce => {
            for i in 0..4 {
                out[i] = hints::bb_reduce_hint(g(i));
            }
        }
        Ext4Div => {
            let r = hints::ext4_div_hint([g(0), g(1), g(2), g(3)], [g(4), g(5), g(6), g(7)]);
            out[..4].copy_from_slice(&r);
        }
    }
}

pub fn interpret(prog: &Program, inputs: &[Fr]) -> Vec<Fr> {
    assert_eq!(inputs.len(), prog.num_inputs as usize);
    let mut w = vec![Fr::ZERO; prog.num_slots as usize];
    walk(prog, |_idx, op, inst, args, out_base| {
        let mut av = [Fr::ZERO; 9];
        for (i, &a) in args.iter().enumerate() {
            av[i] = w[a as usize];
        }
        let out = out_base as usize;
        let n_out = op.out_count(inst.aux);
        eval_inst(op, inst.aux, inputs, &prog.consts, &av, &mut w[out..out + n_out]);
    });
    w
}
