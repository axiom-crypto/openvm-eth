//! Arithmetic-only clone of `openvm_static_verifier::stages::*`.

pub mod batch_constraints;
pub mod full_pipeline;
pub mod stacked_reduction;
pub mod whir;

use openvm_stark_sdk::openvm_stark_backend::p3_field::{Field as _, PrimeCharacteristicRing};

use crate::chip::{BabyBearExt, BabyBearExtInst};
use crate::wire::{ExtWire, Wire};
use openvm_stark_sdk::config::baby_bear_bn254_poseidon2::F as RootF;

pub(crate) fn column_openings_by_rot_assigned<E: BabyBearExtInst>(
    ext_chip: &E,
    openings: &[ExtWire<E::R>],
    need_rot: bool,
) -> Vec<(ExtWire<E::R>, ExtWire<E::R>)> {
    if need_rot {
        assert!(openings.len().is_multiple_of(2));
        openings.chunks_exact(2).map(|c| (c[0], c[1])).collect()
    } else {
        let zero = ext_chip.zero();
        openings.iter().map(|o| (*o, zero)).collect()
    }
}

pub(crate) fn horner_eval_ext_poly_assigned<E: BabyBearExtInst>(
    ext_chip: &E,
    coeffs: &[ExtWire<E::R>],
    x: &ExtWire<E::R>,
) -> ExtWire<E::R> {
    if coeffs.is_empty() {
        return ext_chip.zero();
    }
    let x_reduced = ext_chip.reduce_max_bits(*x);
    let mut acc = *coeffs.last().unwrap();
    for coeff in coeffs.iter().rev().skip(1) {
        acc = ext_chip.mul(acc, x_reduced);
        acc = ext_chip.add(acc, *coeff);
    }
    acc
}

pub(crate) fn horner_eval_ext_poly_f_assigned<E: BabyBearExtInst>(
    ext_chip: &E,
    coeffs: &[ExtWire<E::R>],
    x: &Wire<E::R>,
) -> ExtWire<E::R> {
    if coeffs.is_empty() {
        return ext_chip.zero();
    }
    let x_reduced = ext_chip.base().reduce_max_bits(*x);
    let mut acc = *coeffs.last().unwrap();
    for coeff in coeffs.iter().rev().skip(1) {
        acc = ext_chip.scalar_mul_add(acc, x_reduced, *coeff);
    }
    acc
}

pub(crate) fn interpolate_quadratic_at_012_assigned<E: BabyBearExtInst>(
    ext_chip: &E,
    evals: [&ExtWire<E::R>; 3],
    x: &ExtWire<E::R>,
) -> ExtWire<E::R> {
    let one = ext_chip.from_base_const(RootF::ONE);
    let two = ext_chip.from_base_const(RootF::TWO);
    let inv_two = RootF::ONE.halve();

    let x_minus_one = ext_chip.sub(*x, one);
    let x_minus_two = ext_chip.sub(*x, two);
    let x_times_x_minus_one = ext_chip.mul(*x, x_minus_one);
    let x_times_x_minus_two = ext_chip.mul(*x, x_minus_two);
    let x_minus_one_times_x_minus_two = ext_chip.mul(x_minus_one, x_minus_two);

    let l0 = ext_chip.mul_base_const(x_minus_one_times_x_minus_two, inv_two);
    let l1 = ext_chip.neg(x_times_x_minus_two);
    let l2 = ext_chip.mul_base_const(x_times_x_minus_one, inv_two);

    let term0 = ext_chip.mul(*evals[0], l0);
    let term1 = ext_chip.mul(*evals[1], l1);
    let term2 = ext_chip.mul(*evals[2], l2);
    let sum01 = ext_chip.add(term0, term1);
    ext_chip.add(sum01, term2)
}
