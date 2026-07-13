//! Arithmetic-only clone of `openvm_static_verifier::stages::*`.

pub mod batch_constraints;
pub mod full_pipeline;
pub mod stacked_reduction;
pub mod whir;

use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeCharacteristicRing;

use crate::{
    backend::BabyBearExt4Inst,
    chip::BabyBearExt4Chip,
    wire::{ExtWire, Wire},
};
use openvm_stark_sdk::config::baby_bear_bn254_poseidon2::F as RootF;

pub(crate) fn column_openings_by_rot_assigned<B: BabyBearExt4Inst>(
    ctx: &mut B::Ctx,
    ext_chip: &BabyBearExt4Chip<B>,
    openings: &[ExtWire<B>],
    need_rot: bool,
) -> Vec<(ExtWire<B>, ExtWire<B>)> {
    if need_rot {
        assert!(openings.len().is_multiple_of(2));
        openings.chunks_exact(2).map(|c| (c[0], c[1])).collect()
    } else {
        let zero = ext_chip.zero(ctx);
        openings.iter().map(|o| (*o, zero)).collect()
    }
}

pub(crate) fn horner_eval_ext_poly_assigned<B: BabyBearExt4Inst>(
    ctx: &mut B::Ctx,
    ext_chip: &BabyBearExt4Chip<B>,
    coeffs: &[ExtWire<B>],
    x: &ExtWire<B>,
) -> ExtWire<B> {
    if coeffs.is_empty() {
        return ext_chip.zero(ctx);
    }
    let x_reduced = ext_chip.reduce_max_bits(ctx, *x);
    let mut acc = *coeffs.last().unwrap();
    for coeff in coeffs.iter().rev().skip(1) {
        acc = ext_chip.mul(ctx, acc, x_reduced);
        acc = ext_chip.add(ctx, acc, *coeff);
    }
    acc
}

pub(crate) fn horner_eval_ext_poly_f_assigned<B: BabyBearExt4Inst>(
    ctx: &mut B::Ctx,
    ext_chip: &BabyBearExt4Chip<B>,
    coeffs: &[ExtWire<B>],
    x: &Wire<B>,
) -> ExtWire<B> {
    if coeffs.is_empty() {
        return ext_chip.zero(ctx);
    }
    let x_reduced = ext_chip.base().reduce_max_bits(ctx, *x);
    let mut acc = *coeffs.last().unwrap();
    for coeff in coeffs.iter().rev().skip(1) {
        acc = ext_chip.scalar_mul_add(ctx, acc, x_reduced, *coeff);
    }
    acc
}

pub(crate) fn interpolate_quadratic_at_012_assigned<B: BabyBearExt4Inst>(
    ctx: &mut B::Ctx,
    ext_chip: &BabyBearExt4Chip<B>,
    evals: [&ExtWire<B>; 3],
    x: &ExtWire<B>,
) -> ExtWire<B> {
    let one = ext_chip.from_base_const(ctx, RootF::ONE);
    let two = ext_chip.from_base_const(ctx, RootF::TWO);
    let inv_two = RootF::ONE.halve();

    let x_minus_one = ext_chip.sub(ctx, *x, one);
    let x_minus_two = ext_chip.sub(ctx, *x, two);
    let x_times_x_minus_one = ext_chip.mul(ctx, *x, x_minus_one);
    let x_times_x_minus_two = ext_chip.mul(ctx, *x, x_minus_two);
    let x_minus_one_times_x_minus_two = ext_chip.mul(ctx, x_minus_one, x_minus_two);

    let l0 = ext_chip.mul_base_const(ctx, x_minus_one_times_x_minus_two, inv_two);
    let l1 = ext_chip.neg(ctx, x_times_x_minus_two);
    let l2 = ext_chip.mul_base_const(ctx, x_times_x_minus_one, inv_two);

    let term0 = ext_chip.mul(ctx, *evals[0], l0);
    let term1 = ext_chip.mul(ctx, *evals[1], l1);
    let term2 = ext_chip.mul(ctx, *evals[2], l2);
    let sum01 = ext_chip.add(ctx, term0, term1);
    ext_chip.add(ctx, sum01, term2)
}
