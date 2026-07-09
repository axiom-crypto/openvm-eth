//! Arithmetic-only port of `stages/stacked_reduction/mod.rs`.

use std::collections::HashMap;

use openvm_stark_sdk::{
    config::baby_bear_bn254_poseidon2::BabyBearBn254Poseidon2Config as RootConfig,
    openvm_stark_backend::{p3_field::PrimeCharacteristicRing, prover::stacked_pcs::StackedLayout},
};

use openvm_stark_sdk::config::baby_bear_bn254_poseidon2::F as RootF;

use crate::chip::{BabyBearExt, BabyBearExtInst};
use crate::proof_wire::{
    BatchConstraintProofWire as _, StackedReductionIntermediatesWire, StackingProofWire,
};
use crate::transcript::TranscriptChip;
use crate::verify::batch_constraints::{
    eval_eq_mle_binary_assigned, eval_eq_prism_assigned, eval_eq_uni_at_one_assigned,
    eval_rot_kernel_prism_assigned,
};
use crate::verify::{
    column_openings_by_rot_assigned, horner_eval_ext_poly_assigned,
    interpolate_quadratic_at_012_assigned,
};
use crate::wire::{ExtWire, ReducedExtWire};

pub(crate) fn load_stacking_proof_wire(
    ext_chip: &impl BabyBearExtInst,
    stacking_proof: &openvm_stark_sdk::openvm_stark_backend::proof::StackingProof<RootConfig>,
) -> StackingProofWire {
    let univariate_round_coeffs = stacking_proof
        .univariate_round_coeffs
        .iter()
        .map(|&value| ext_chip.load_reduced_witness(value))
        .collect::<Vec<_>>();
    let sumcheck_round_polys = stacking_proof
        .sumcheck_round_polys
        .iter()
        .map(|poly| {
            poly.iter()
                .map(|&value| ext_chip.load_reduced_witness(value))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let stacking_openings = stacking_proof
        .stacking_openings
        .iter()
        .map(|row| {
            row.iter()
                .map(|&value| ext_chip.load_reduced_witness(value))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    StackingProofWire {
        univariate_round_coeffs,
        sumcheck_round_polys,
        stacking_openings,
    }
}

fn eval_in_uni_assigned(
    ext_chip: &impl BabyBearExtInst,
    l_skip: usize,
    n: isize,
    z: ExtWire,
) -> ExtWire {
    debug_assert!(n >= -(l_skip as isize));
    if n.is_negative() {
        let z_pow = ext_chip.pow_power_of_two(z, l_skip.wrapping_add_signed(n));
        eval_eq_uni_at_one_assigned(ext_chip, n.unsigned_abs(), &z_pow)
    } else {
        ext_chip.from_base_const(RootF::from_u64(1))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn constrain_stacked_reduction<E: BabyBearExtInst>(
    ext_chip: &E,
    transcript: &mut TranscriptChip<E::Base>,
    stacking_wire: &StackingProofWire,
    layouts: &[StackedLayout],
    need_rot_per_commit: &[Vec<bool>],
    l_skip: usize,
    n_stack: usize,
    batch_column_openings: &[Vec<Vec<ReducedExtWire>>],
    r: &[ExtWire],
) -> StackedReductionIntermediatesWire
where
    E::Base: Clone,
{
    let omega_order = 1usize << l_skip;
    let one = ext_chip.from_base_const(RootF::ONE);

    let mut lambda_idx = 0usize;
    let lambda_indices_per_layout = layouts
        .iter()
        .enumerate()
        .map(|(commit_idx, layout)| {
            let need_rot_for_commit = &need_rot_per_commit[commit_idx];
            layout
                .sorted_cols
                .iter()
                .map(|&(mat_idx, _col_idx, _slice)| {
                    lambda_idx += 1;
                    (lambda_idx - 1, need_rot_for_commit[mat_idx])
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let mut t_claims = Vec::with_capacity(lambda_idx);
    for (trace_idx, parts) in batch_column_openings.iter().enumerate() {
        let need_rot = need_rot_per_commit[0][trace_idx];
        let openings = parts[0].iter().map(ExtWire::from).collect::<Vec<_>>();
        t_claims.extend(column_openings_by_rot_assigned(ext_chip, &openings, need_rot));
    }
    let mut commit_idx = 1usize;
    for parts in batch_column_openings {
        for cols in parts.iter().skip(1) {
            let need_rot = need_rot_per_commit[commit_idx][0];
            let openings = cols.iter().map(ExtWire::from).collect::<Vec<_>>();
            t_claims.extend(column_openings_by_rot_assigned(ext_chip, &openings, need_rot));
            commit_idx += 1;
        }
    }

    let lambda = transcript.sample_ext();
    let lambda_sqr = ext_chip.mul(lambda, lambda);
    let mut lambda_sqr_powers = Vec::with_capacity(t_claims.len());
    let mut cur_lambda_sqr = one;
    for _ in 0..t_claims.len() {
        lambda_sqr_powers.push(cur_lambda_sqr);
        cur_lambda_sqr = ext_chip.mul(cur_lambda_sqr, lambda_sqr);
        cur_lambda_sqr = ext_chip.reduce_max_bits(cur_lambda_sqr);
    }

    let mut s_0 = ext_chip.zero();
    for (i, ((claim, claim_rot), lambda_pow)) in
        t_claims.iter().zip(lambda_sqr_powers.iter()).enumerate()
    {
        let claim_rot_lambda = ext_chip.mul(*claim_rot, lambda);
        let batched_claim = ext_chip.add(*claim, claim_rot_lambda);
        let term = if i == 0 {
            batched_claim
        } else {
            ext_chip.mul(batched_claim, *lambda_pow)
        };
        s_0 = ext_chip.add(s_0, term);
    }

    let univariate_round_coeffs = &stacking_wire.univariate_round_coeffs;
    let univariate_round_coeffs_raw: Vec<ExtWire> =
        univariate_round_coeffs.iter().map(ExtWire::from).collect();
    let mut s_0_sum_eval = ext_chip.zero();
    for coeff in univariate_round_coeffs_raw.iter().step_by(omega_order) {
        s_0_sum_eval = ext_chip.add(s_0_sum_eval, *coeff);
    }
    let s_0_sum_eval = ext_chip.mul_base_const(s_0_sum_eval, RootF::from_u64(omega_order as u64));
    ext_chip.assert_equal(s_0, s_0_sum_eval);

    for coeff in univariate_round_coeffs {
        transcript.observe_ext(coeff);
    }

    let mut u = Vec::with_capacity(n_stack + 1);
    u.push(transcript.sample_ext());

    let sumcheck_round_polys = &stacking_wire.sumcheck_round_polys;

    let mut final_claim =
        horner_eval_ext_poly_assigned(ext_chip, &univariate_round_coeffs_raw, &u[0]);
    for round_poly in sumcheck_round_polys {
        let s_j_1 = round_poly[0];
        let s_j_2 = round_poly[1];
        transcript.observe_ext(&s_j_1);
        transcript.observe_ext(&s_j_2);
        let u_j = transcript.sample_ext();
        let s_j_1: ExtWire = (&s_j_1).into();
        let s_j_2: ExtWire = (&s_j_2).into();
        let s_j_0 = ext_chip.sub(final_claim, s_j_1);
        final_claim = interpolate_quadratic_at_012_assigned(
            ext_chip,
            [&s_j_0, &s_j_1, &s_j_2],
            &u_j,
        );
        u.push(u_j);
    }

    let stacking_matrix_expected_widths = layouts
        .iter()
        .map(|layout| {
            layout
                .sorted_cols
                .last()
                .map(|(_, _, slice)| slice.col_idx + 1)
                .expect("stacked layout must contain at least one column")
        })
        .collect::<Vec<_>>();
    let mut derived_q_coeffs = stacking_matrix_expected_widths
        .iter()
        .map(|&width| {
            core::iter::repeat_with(|| ext_chip.zero())
                .take(width)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let any_need_rot = lambda_indices_per_layout
        .iter()
        .any(|indices| indices.iter().any(|&(_, rot)| rot));

    let mut n_cache: HashMap<isize, (ExtWire, ExtWire, ExtWire)> = HashMap::new();
    let mut eq_mle_cache: HashMap<(isize, usize), ExtWire> = HashMap::new();

    for (commit_idx, layout) in layouts.iter().enumerate() {
        let lambda_indices = &lambda_indices_per_layout[commit_idx];
        for (col_idx, &(_, _, s)) in layout.sorted_cols.iter().enumerate() {
            let (lambda_idx, need_rot) = lambda_indices[col_idx];
            let n = s.log_height() as isize - l_skip as isize;
            let n_lift = n.max(0) as usize;
            let b_key = s.row_idx >> (l_skip + n_lift);

            let eq_mle = *eq_mle_cache.entry((n, b_key)).or_insert_with(|| {
                let b_bits = (l_skip + n_lift..l_skip + n_stack)
                    .map(|j| ((s.row_idx >> j) & 1) == 1)
                    .collect::<Vec<_>>();
                eval_eq_mle_binary_assigned(ext_chip, &u[n_lift + 1..], &b_bits)
            });

            let &mut (ind, eq_prism, rot_kernel) = n_cache.entry(n).or_insert_with(|| {
                let ind = eval_in_uni_assigned(ext_chip, l_skip, n, u[0]);
                let (l, rs_n) = if n.is_negative() {
                    (
                        l_skip.wrapping_add_signed(n),
                        vec![ext_chip.pow_power_of_two(r[0], n.unsigned_abs())],
                    )
                } else {
                    (l_skip, r[..=n_lift].to_vec())
                };
                let eq_prism = eval_eq_prism_assigned(ext_chip, l, &u[..=n_lift], &rs_n);
                let rot_kernel = if any_need_rot {
                    eval_rot_kernel_prism_assigned(ext_chip, l, &u[..=n_lift], &rs_n)
                } else {
                    ext_chip.zero()
                };
                (ind, eq_prism, rot_kernel)
            });

            let mut batched = ext_chip.mul(lambda_sqr_powers[lambda_idx], eq_prism);
            if need_rot {
                let lambda_rot = ext_chip.mul(lambda, rot_kernel);
                let rot_term = ext_chip.mul(lambda_sqr_powers[lambda_idx], lambda_rot);
                batched = ext_chip.add(batched, rot_term);
            }
            let batched_ind = ext_chip.mul(batched, ind);
            let coeff = ext_chip.mul(eq_mle, batched_ind);
            let updated = ext_chip.add(derived_q_coeffs[commit_idx][s.col_idx], coeff);
            derived_q_coeffs[commit_idx][s.col_idx] = updated;
        }
    }

    let stacking_openings = &stacking_wire.stacking_openings;
    let mut final_sum = ext_chip.zero();
    for (coeff_row, opening_row) in derived_q_coeffs.iter().zip(stacking_openings.iter()) {
        for (coeff, opening) in coeff_row.iter().zip(opening_row.iter()) {
            transcript.observe_ext(opening);
            let term = ext_chip.mul(*coeff, opening.into());
            final_sum = ext_chip.add(final_sum, term);
        }
    }
    ext_chip.assert_equal(final_claim, final_sum);

    StackedReductionIntermediatesWire {
        stacking_openings: stacking_openings.clone(),
        u,
    }
}
