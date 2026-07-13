//! Arithmetic-only port of `stages/whir/mod.rs`.

use halo2_base::{halo2_proofs::halo2curves::bn256::Fr, utils::biguint_to_fe};
use openvm_stark_sdk::{
    config::baby_bear_bn254_poseidon2::{
        BabyBearBn254Poseidon2Config as RootConfig, Digest as RootDigest,
    },
    openvm_stark_backend::{
        keygen::types::MultiStarkVerifyingKey0,
        p3_field::{
            BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField, PrimeField64,
            TwoAdicField,
        },
        proof::WhirProof,
    },
};

use openvm_stark_sdk::config::baby_bear_bn254_poseidon2::{EF as RootEF, F as RootF};

use crate::{
    backend::BabyBearExt4Inst,
    chip::{baby_bear::BABYBEAR_MAX_BITS, BabyBearChip, BabyBearExt4Chip},
    hash::poseidon2::{compress_bn254_digests, hash_babybear_slice_to_digest},
    proof_wire::{MerklePathWire, WhirProofWire},
    transcript::{digest_wire_from_root, TranscriptChip},
    verify::{
        batch_constraints::{eval_eq_mle_assigned, eval_eq_mle_ef_f_assigned},
        horner_eval_ext_poly_assigned, horner_eval_ext_poly_f_assigned,
        interpolate_quadratic_at_012_assigned,
    },
    wire::{ExtWire, ReducedExtWire, ReducedWire, Wire},
};

pub(crate) fn load_whir_proof_wire<B: BabyBearExt4Inst>(
    ctx: &mut B::Ctx,
    ext_chip: &BabyBearExt4Chip<B>,
    whir_proof: &WhirProof<RootConfig>,
) -> WhirProofWire<B> {
    let base_chip = ext_chip.base();
    let mu_pow_witness = base_chip.load_reduced_witness(ctx, whir_proof.mu_pow_witness);
    let folding_pow_witnesses = whir_proof
        .folding_pow_witnesses
        .iter()
        .map(|&w| base_chip.load_reduced_witness(ctx, RootF::from_u64(w.as_canonical_u64())))
        .collect::<Vec<_>>();
    let query_phase_pow_witnesses = whir_proof
        .query_phase_pow_witnesses
        .iter()
        .map(|&w| base_chip.load_reduced_witness(ctx, RootF::from_u64(w.as_canonical_u64())))
        .collect::<Vec<_>>();
    let whir_sumcheck_polys = whir_proof
        .whir_sumcheck_polys
        .iter()
        .map(|poly| {
            poly.iter()
                .map(|&v| ext_chip.load_reduced_witness(ctx, v))
                .collect::<Vec<_>>()
                .try_into()
                .expect("two evaluations")
        })
        .collect::<Vec<_>>();
    let ood_values = whir_proof
        .ood_values
        .iter()
        .map(|&v| ext_chip.load_reduced_witness(ctx, v))
        .collect::<Vec<_>>();
    let final_poly = whir_proof
        .final_poly
        .iter()
        .map(|&v| ext_chip.load_reduced_witness(ctx, v))
        .collect::<Vec<_>>();
    let codeword_commitment_roots = whir_proof
        .codeword_commits
        .iter()
        .map(|&d| B::input(ctx, digest_to_fr(d)))
        .collect::<Vec<_>>();

    let initial_round_merkle_paths = whir_proof
        .initial_round_opened_rows
        .iter()
        .zip(whir_proof.initial_round_merkle_proofs.iter())
        .map(|(rows_per_query, proofs_per_query)| {
            rows_per_query
                .iter()
                .zip(proofs_per_query.iter())
                .map(|(opened_rows, merkle_proof)| {
                    let leaf_values = opened_rows
                        .iter()
                        .map(|row| {
                            row.iter()
                                .map(|&v| base_chip.load_reduced_witness(ctx, v))
                                .collect::<Vec<ReducedWire<B>>>()
                        })
                        .collect::<Vec<_>>();
                    let siblings = merkle_proof
                        .iter()
                        .map(|&d| B::input(ctx, digest_to_fr(d)))
                        .collect::<Vec<_>>();
                    MerklePathWire { leaf_values, siblings }
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let codeword_merkle_paths = whir_proof
        .codeword_opened_values
        .iter()
        .zip(whir_proof.codeword_merkle_proofs.iter())
        .map(|(values_per_query, proofs_per_query)| {
            values_per_query
                .iter()
                .zip(proofs_per_query.iter())
                .map(|(opened_values, merkle_proof)| {
                    let leaf_values = opened_values
                        .iter()
                        .map(|value| {
                            ext_to_coeffs(*value)
                                .iter()
                                .map(|&coeff| {
                                    base_chip.load_reduced_witness(ctx, RootF::from_u64(coeff))
                                })
                                .collect::<Vec<ReducedWire<B>>>()
                        })
                        .collect::<Vec<_>>();
                    let siblings = merkle_proof
                        .iter()
                        .map(|&d| B::input(ctx, digest_to_fr(d)))
                        .collect::<Vec<_>>();
                    MerklePathWire { leaf_values, siblings }
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    WhirProofWire {
        mu_pow_witness,
        folding_pow_witnesses,
        query_phase_pow_witnesses,
        whir_sumcheck_polys,
        ood_values,
        final_poly,
        codeword_commitment_roots,
        initial_round_merkle_paths,
        codeword_merkle_paths,
    }
}

const BABY_BEAR_EXT_DEGREE: usize = 4;

fn ext_to_coeffs(value: RootEF) -> [u64; BABY_BEAR_EXT_DEGREE] {
    core::array::from_fn(|i| {
        <RootEF as BasedVectorSpace<RootF>>::as_basis_coefficients_slice(&value)[i]
            .as_canonical_u64()
    })
}

fn digest_to_fr(digest: RootDigest) -> Fr {
    biguint_to_fe(&digest[0].as_canonical_biguint())
}

fn eval_mobius_eq_mle_assigned<B: BabyBearExt4Inst>(
    ctx: &mut B::Ctx,
    ext_chip: &BabyBearExt4Chip<B>,
    u: &[ExtWire<B>],
    x: &[ExtWire<B>],
) -> ExtWire<B> {
    assert_eq!(u.len(), x.len());
    let one = ext_chip.from_base_const(ctx, RootF::ONE);
    let two = ext_chip.from_base_const(ctx, RootF::TWO);
    let three = RootF::from_u64(3);
    let mut acc = one;
    for (u_i, x_i) in u.iter().zip(x.iter()) {
        let one_minus_x = ext_chip.sub(ctx, one, *x_i);
        let three_x_minus_two = ext_chip.mul_base_const(ctx, *x_i, three);
        let three_x_minus_two = ext_chip.sub(ctx, three_x_minus_two, two);
        let u_term = ext_chip.mul(ctx, *u_i, three_x_minus_two);
        let factor = ext_chip.add(ctx, one_minus_x, u_term);
        acc = ext_chip.mul(ctx, acc, factor);
    }
    acc
}

fn eval_mle_evals_at_point_assigned<B: BabyBearExt4Inst>(
    ctx: &mut B::Ctx,
    ext_chip: &BabyBearExt4Chip<B>,
    evals: &[ExtWire<B>],
    x: &[ExtWire<B>],
) -> ExtWire<B> {
    assert_eq!(evals.len(), 1usize << x.len());
    let mut values = evals.to_vec();
    let mut len = values.len();
    for xj in x.iter().rev() {
        len >>= 1;
        for i in 0..len {
            let lo = values[i];
            let hi = values[i + len];
            let diff = ext_chip.sub(ctx, hi, lo);
            let weighted = ext_chip.mul(ctx, diff, *xj);
            values[i] = ext_chip.add(ctx, lo, weighted);
        }
    }
    values.first().copied().unwrap()
}

fn invert_base_assigned<B: BabyBearExt4Inst>(
    ctx: &mut B::Ctx,
    base_chip: &BabyBearChip<B>,
    value: Wire<B>,
) -> Wire<B> {
    let one = base_chip.one(ctx);
    base_chip.div(ctx, one, value)
}

fn query_root_from_bits_assigned<B: BabyBearExt4Inst>(
    ctx: &mut B::Ctx,
    base_chip: &BabyBearChip<B>,
    query_bits: &[B::V],
    log_rs_domain_size: usize,
) -> Wire<B> {
    let gate = base_chip.gate();
    let omega = RootF::two_adic_generator(log_rs_domain_size);
    let mut root: Option<Wire<B>> = None;
    for (bit_idx, &bit) in query_bits.iter().enumerate() {
        let omega_pow = omega.exp_u64(1u64 << bit_idx).as_canonical_u64();
        let omega_val = B::constant(ctx, Fr::from(omega_pow));
        let one_val = B::constant(ctx, Fr::from(1u64));
        let value = gate.select(ctx, omega_val, one_val, bit);
        let selected = Wire::new(value, BABYBEAR_MAX_BITS);
        if let Some(prev) = &mut root {
            *prev = base_chip.mul(ctx, *prev, selected);
        } else {
            root = Some(selected);
        }
    }
    root.unwrap()
}

fn binary_k_fold_assigned<B: BabyBearExt4Inst>(
    ctx: &mut B::Ctx,
    ext_chip: &BabyBearExt4Chip<B>,
    mut values: Vec<ExtWire<B>>,
    alphas: &[ExtWire<B>],
    x: Wire<B>,
) -> ExtWire<B> {
    let base_chip = ext_chip.base();
    let n = values.len();
    assert_eq!(n, 1usize << alphas.len());
    if alphas.is_empty() {
        return values[0];
    }

    let k = alphas.len();
    let omega_k = RootF::two_adic_generator(k);
    let omega_k_inv = omega_k.inverse();
    let tw: Vec<RootF> = omega_k.powers().take(1usize << (k - 1)).collect();
    let half = RootF::ONE.halve();
    let inv_tw_half: Vec<RootF> =
        omega_k_inv.powers().take(1usize << (k - 1)).map(|p| p * half).collect();

    let mut x_pow = base_chip.reduce_max_bits(ctx, x);
    let x_inv = invert_base_assigned(ctx, base_chip, x);
    let mut x_inv_pow = base_chip.reduce_max_bits(ctx, x_inv);

    for (j, alpha) in alphas.iter().enumerate() {
        let m = n >> (j + 1);
        for i in 0..m {
            let t = base_chip.mul_const(ctx, x_pow, tw[i << j]);
            let t_inv_half = base_chip.mul_const(ctx, x_inv_pow, inv_tw_half[i << j]);

            let lo = values[i];
            let hi = values[i + m];
            let lo_minus_hi = ext_chip.sub(ctx, lo, hi);
            let mut alpha_minus_t = *alpha;
            alpha_minus_t.0[0] = base_chip.sub(ctx, alpha_minus_t.0[0], t);
            let fold = ext_chip.mul(ctx, alpha_minus_t, lo_minus_hi);
            values[i] = ext_chip.scalar_mul_add(ctx, fold, t_inv_half, lo);
        }
        x_pow = base_chip.square(ctx, x_pow);
        x_pow = base_chip.reduce_max_bits(ctx, x_pow);
        x_inv_pow = base_chip.square(ctx, x_inv_pow);
        x_inv_pow = base_chip.reduce_max_bits(ctx, x_inv_pow);
    }
    values[0]
}

fn tree_compress_assigned_digests<B: BabyBearExt4Inst>(
    ctx: &mut B::Ctx,
    digests: Vec<B::V>,
) -> B::V {
    assert!(digests.len().is_power_of_two());
    let mut level = digests;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(compress_bn254_digests::<B>(ctx, pair[0], pair[1]));
        }
        level = next;
    }
    level.pop().unwrap()
}

fn constrain_merkle_path<B: BabyBearExt4Inst>(
    ctx: &mut B::Ctx,
    ext_chip: &BabyBearExt4Chip<B>,
    query_bits: &[B::V],
    merkle_path: &MerklePathWire<B>,
    _root_digest: B::V,
) {
    assert!(merkle_path.leaf_values.len().is_power_of_two());
    let gate = ext_chip.range().gate();
    assert_eq!(merkle_path.siblings.len(), query_bits.len());
    let leaf_hashes = merkle_path
        .leaf_values
        .iter()
        .map(|leaf| hash_babybear_slice_to_digest::<B>(ctx, leaf))
        .collect::<Vec<_>>();
    let mut cur = tree_compress_assigned_digests::<B>(ctx, leaf_hashes);
    for (bit, &sibling) in query_bits.iter().zip(merkle_path.siblings.iter()) {
        let left = gate.select(ctx, sibling, cur, *bit);
        let right = gate.select(ctx, cur, sibling, *bit);
        cur = compress_bn254_digests::<B>(ctx, left, right);
    }
    // constrain_equal(cur, root_digest) — no-op in arithonly.
    let _ = cur;
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn constrain_whir_verification<B: BabyBearExt4Inst>(
    ctx: &mut B::Ctx,
    ext_chip: &BabyBearExt4Chip<B>,
    transcript: &mut TranscriptChip<B>,
    mvk0: &MultiStarkVerifyingKey0<RootConfig>,
    whir_wire: &WhirProofWire<B>,
    stacking_openings: &[Vec<ReducedExtWire<B>>],
    initial_commitment_roots: &[B::V],
    u_cube: &[ExtWire<B>],
) where
    B: Clone,
{
    let gate = ext_chip.range().gate();
    let params = &mvk0.params;
    let k_whir = params.k_whir();
    let num_whir_rounds = params.num_whir_rounds();

    let mu_pow_witness = whir_wire.mu_pow_witness;
    transcript.check_witness(ctx, params.whir.mu_pow_bits, &mu_pow_witness);
    let mu_challenge = transcript.sample_ext(ctx);

    let folding_pow_witnesses = &whir_wire.folding_pow_witnesses;
    let query_phase_pow_witnesses = &whir_wire.query_phase_pow_witnesses;
    let whir_sumcheck_polys = &whir_wire.whir_sumcheck_polys;
    let ood_values = &whir_wire.ood_values;
    let final_poly_reduced = &whir_wire.final_poly;
    let final_poly = final_poly_reduced.iter().map(ExtWire::<B>::from).collect::<Vec<_>>();
    let codeword_commitment_roots = &whir_wire.codeword_commitment_roots;
    let codeword_commitment_digests =
        codeword_commitment_roots.iter().copied().map(digest_wire_from_root).collect::<Vec<_>>();

    let total_width = stacking_openings.iter().map(Vec::len).sum::<usize>();
    let one = ext_chip.from_base_const(ctx, RootF::ONE);
    let mut mu_pows = Vec::with_capacity(total_width);
    let mut mu_pow = one;
    for _ in 0..total_width {
        mu_pows.push(mu_pow);
        mu_pow = ext_chip.mul(ctx, mu_pow, mu_challenge);
        mu_pow = ext_chip.reduce_max_bits(ctx, mu_pow);
    }

    let mut final_claim = ext_chip.zero(ctx);
    let mut mu_idx = 0usize;
    for commit_openings in stacking_openings {
        for opening in commit_openings {
            let weighted = if mu_idx == 0 {
                opening.into()
            } else {
                ext_chip.mul(ctx, opening.into(), mu_pows[mu_idx])
            };
            final_claim = ext_chip.add(ctx, final_claim, weighted);
            mu_idx += 1;
        }
    }

    let mut folding_alphas = Vec::new();
    let mut z0_challenges = Vec::new();
    let mut gammas = Vec::with_capacity(num_whir_rounds);
    let mut query_indices = Vec::new();
    let mut folding_counts_per_round = Vec::with_capacity(num_whir_rounds);
    let mut query_counts_per_round = Vec::with_capacity(num_whir_rounds);
    let mut query_index_bits: Vec<usize> = Vec::new();
    let mut zs_per_round = Vec::with_capacity(num_whir_rounds);

    let mut sumcheck_cursor = 0usize;
    let mut folding_pow_cursor = 0usize;
    let mut log_rs_domain_size = params.l_skip + params.n_stack + params.log_blowup;

    for (round_idx, round_params) in params.whir.rounds.iter().enumerate() {
        let is_initial_round = round_idx == 0;
        let is_final_round = round_idx + 1 == num_whir_rounds;
        let mut alphas_round = Vec::new();

        for _ in 0..k_whir {
            if let Some(evals) = whir_sumcheck_polys.get(sumcheck_cursor) {
                let ev1 = evals[0];
                let ev2 = evals[1];
                transcript.observe_ext(ctx, &ev1);
                transcript.observe_ext(ctx, &ev2);
                let pow_witness = folding_pow_witnesses[folding_pow_cursor];
                folding_pow_cursor += 1;
                transcript.check_witness(ctx, params.whir.folding_pow_bits, &pow_witness);
                let alpha = transcript.sample_ext(ctx);
                alphas_round.push(alpha);
                folding_alphas.push(alpha);

                let ev1: ExtWire<B> = (&ev1).into();
                let ev2: ExtWire<B> = (&ev2).into();
                let ev0 = ext_chip.sub(ctx, final_claim, ev1);
                final_claim = interpolate_quadratic_at_012_assigned(
                    ctx,
                    ext_chip,
                    [&ev0, &ev1, &ev2],
                    &alpha,
                );
                sumcheck_cursor += 1;
            }
        }
        folding_counts_per_round.push(alphas_round.len());

        let y0 = if is_final_round {
            for coeff in final_poly_reduced {
                transcript.observe_ext(ctx, coeff);
            }
            None
        } else {
            transcript.observe_commit(ctx, &codeword_commitment_digests[round_idx]);
            let z0 = transcript.sample_ext(ctx);
            z0_challenges.push(z0);
            let y0 = ood_values[round_idx];
            transcript.observe_ext(ctx, &y0);
            Some(y0)
        };

        transcript.check_witness(
            ctx,
            params.whir.query_phase_pow_bits,
            &query_phase_pow_witnesses[round_idx],
        );

        let query_bits_count = log_rs_domain_size - k_whir;
        let num_queries = round_params.num_queries;
        query_counts_per_round.push(num_queries);

        let mut ys_round = Vec::with_capacity(num_queries);
        let mut zs_round = Vec::with_capacity(num_queries);

        for query_idx in 0..num_queries {
            let query_index = transcript.sample_bits(ctx, query_bits_count);
            query_index_bits.push(query_bits_count);
            query_indices.push(query_index);
            let query_bits_vec = if query_bits_count == 0 {
                Vec::new()
            } else {
                gate.num_to_bits(ctx, query_index, query_bits_count)
            };
            let zi_root = query_root_from_bits_assigned(
                ctx,
                ext_chip.base(),
                &query_bits_vec,
                log_rs_domain_size,
            );
            let zi = ext_chip.base().pow_power_of_two(ctx, zi_root, k_whir);

            let yi = if is_initial_round {
                let mut codeword_vals: Vec<Option<ExtWire<B>>> = vec![None; 1usize << k_whir];
                let mut mu_power_idx = 0usize;
                for (commit_idx, commit_openings) in stacking_openings.iter().enumerate() {
                    let merkle_path = &whir_wire.initial_round_merkle_paths[commit_idx][query_idx];
                    constrain_merkle_path(
                        ctx,
                        ext_chip,
                        &query_bits_vec,
                        merkle_path,
                        initial_commitment_roots[commit_idx],
                    );
                    for col_idx in 0..commit_openings.len() {
                        let mu_pow = mu_pows[mu_power_idx];
                        let is_first_mu = mu_power_idx == 0;
                        for (row_idx, row) in merkle_path.leaf_values.iter().enumerate() {
                            let opened_base: Wire<B> = row[col_idx].into();
                            codeword_vals[row_idx] = if let Some(prev) = codeword_vals[row_idx] {
                                Some(ext_chip.scalar_mul_add(ctx, mu_pow, opened_base, prev))
                            } else if is_first_mu {
                                Some(ext_chip.from_base_var(ctx, opened_base))
                            } else {
                                Some(ext_chip.scalar_mul(ctx, mu_pow, opened_base))
                            };
                        }
                        mu_power_idx += 1;
                    }
                }
                let codeword_vals = codeword_vals.into_iter().flatten().collect::<Vec<_>>();
                binary_k_fold_assigned(ctx, ext_chip, codeword_vals, &alphas_round, zi_root)
            } else {
                let merkle_path = &whir_wire.codeword_merkle_paths[round_idx - 1][query_idx];
                constrain_merkle_path(
                    ctx,
                    ext_chip,
                    &query_bits_vec,
                    merkle_path,
                    codeword_commitment_roots[round_idx - 1],
                );
                let opened_values = merkle_path
                    .leaf_values
                    .iter()
                    .map(|row| ExtWire::<B>(core::array::from_fn(|idx| row[idx].into())))
                    .collect::<Vec<_>>();
                binary_k_fold_assigned(ctx, ext_chip, opened_values, &alphas_round, zi_root)
            };

            zs_round.push(zi);
            ys_round.push(yi);
        }

        let gamma = transcript.sample_ext(ctx);
        if let Some(y0) = y0 {
            let y0_term = ext_chip.mul(ctx, y0.into(), gamma);
            final_claim = ext_chip.add(ctx, final_claim, y0_term);
        }
        let mut gamma_pow = ext_chip.mul(ctx, gamma, gamma);
        for yi in &ys_round {
            let term = ext_chip.mul(ctx, *yi, gamma_pow);
            final_claim = ext_chip.add(ctx, final_claim, term);
            gamma_pow = ext_chip.mul(ctx, gamma_pow, gamma);
        }
        gammas.push(gamma);
        zs_per_round.push(zs_round);
        log_rs_domain_size = log_rs_domain_size.saturating_sub(1);
    }

    let rounds = query_counts_per_round.len();
    let t = k_whir * rounds;

    let prefix = eval_mobius_eq_mle_assigned(ctx, ext_chip, &u_cube[..t], &folding_alphas[..t]);
    let suffix = eval_mle_evals_at_point_assigned(ctx, ext_chip, &final_poly, &u_cube[t..]);
    let mut final_acc = ext_chip.mul(ctx, prefix, suffix);

    let mut alpha_offset = k_whir;
    for round_idx in 0..rounds {
        let gamma = &gammas[round_idx];
        let alpha_slc = &folding_alphas[alpha_offset..t];
        let slc_len = (t - alpha_offset) + 1;

        if round_idx + 1 != rounds {
            let z0 = &z0_challenges[round_idx];
            let mut z0_pows = Vec::with_capacity(slc_len);
            z0_pows.push(*z0);
            for _ in 1..slc_len {
                let prev = z0_pows.last().unwrap();
                let next = ext_chip.square(ctx, *prev);
                z0_pows.push(next);
            }
            let z0_max = *z0_pows.last().unwrap();
            let z0_pows_reduced: Vec<_> =
                z0_pows.iter().map(|p| ext_chip.reduce_max_bits(ctx, *p)).collect();
            let eq = eval_eq_mle_assigned(
                ctx,
                ext_chip,
                alpha_slc,
                &z0_pows_reduced[..z0_pows_reduced.len().saturating_sub(1)],
            );
            let poly_eval = horner_eval_ext_poly_assigned(ctx, ext_chip, &final_poly, &z0_max);
            let term = ext_chip.mul(ctx, *gamma, eq);
            let term = ext_chip.mul(ctx, term, poly_eval);
            final_acc = ext_chip.add(ctx, final_acc, term);
        }

        let mut gamma_pow = ext_chip.mul(ctx, *gamma, *gamma);
        for zi in zs_per_round[round_idx].iter() {
            let mut zi_pows = Vec::with_capacity(slc_len);
            zi_pows.push(*zi);
            for _ in 1..slc_len {
                let prev = zi_pows.last().unwrap();
                let next = ext_chip.base().square(ctx, *prev);
                zi_pows.push(next);
            }
            let zi_pows_reduced: Vec<_> =
                zi_pows.iter().map(|p| ext_chip.base().reduce_max_bits(ctx, *p)).collect();
            let eq = eval_eq_mle_ef_f_assigned(
                ctx,
                ext_chip,
                alpha_slc,
                &zi_pows_reduced[..zi_pows_reduced.len().saturating_sub(1)],
            );
            let poly_eval = horner_eval_ext_poly_f_assigned(
                ctx,
                ext_chip,
                &final_poly,
                zi_pows_reduced.last().unwrap(),
            );
            let term = ext_chip.mul(ctx, gamma_pow, eq);
            let term = ext_chip.mul(ctx, term, poly_eval);
            final_acc = ext_chip.add(ctx, final_acc, term);
            gamma_pow = ext_chip.mul(ctx, gamma_pow, *gamma);
        }
        alpha_offset += k_whir;
    }
    ext_chip.assert_equal(ctx, final_acc, final_claim);
}
