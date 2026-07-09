//! Arithmetic-only port of `stages/full_pipeline/mod.rs`.

use halo2_base::{halo2_proofs::halo2curves::bn256::Fr, utils::biguint_to_fe};
use openvm_stark_sdk::{
    config::baby_bear_bn254_poseidon2::{
        BabyBearBn254Poseidon2Config as RootConfig, Bn254Scalar,
    },
    openvm_stark_backend::{
        keygen::types::{MultiStarkVerifyingKey, MultiStarkVerifyingKey0},
        p3_field::{PrimeCharacteristicRing, PrimeField},
        proof::Proof,
        prover::stacked_pcs::StackedLayout,
    },
    p3_baby_bear::BabyBear,
};

use crate::chip::{BabyBearExt, BabyBearExtInst};
use crate::proof_wire::ProofWire;
use crate::transcript::{digest_wire_from_root, DigestWire, TranscriptChip};
use crate::verify::batch_constraints::{
    constrain_batch_constraints_verification, load_batch_constraint_proof_wire,
    load_gkr_proof_wire,
};
use crate::verify::stacked_reduction::{constrain_stacked_reduction, load_stacking_proof_wire};
use crate::verify::whir::{constrain_whir_verification, load_whir_proof_wire};
use crate::wire::ReducedWire;

pub(crate) fn digest_scalar_to_fr(value: Bn254Scalar) -> Fr {
    biguint_to_fe(&value.as_canonical_biguint())
}

pub fn log_heights_per_air_from_proof(proof: &Proof<RootConfig>) -> Vec<usize> {
    proof
        .trace_vdata
        .iter()
        .enumerate()
        .map(|(air_id, tv)| {
            tv.as_ref()
                .unwrap_or_else(|| panic!("missing trace_vdata for air_id {air_id}"))
                .log_height
        })
        .collect()
}

pub fn load_proof_wire(
    ext_chip: &impl BabyBearExtInst,
    proof: &Proof<RootConfig>,
    log_heights_per_air: &[usize],
) -> ProofWire {
    let from_proof = log_heights_per_air_from_proof(proof);
    assert_eq!(
        from_proof.as_slice(),
        log_heights_per_air,
        "per-AIR log heights from proof must match static config"
    );

    let base_chip = ext_chip.base();

    let common_main_commit_root = digest_scalar_to_fr(proof.common_main_commit[0]);

    let public_values = proof
        .public_values
        .iter()
        .map(|values| {
            values
                .iter()
                .map(|&value| base_chip.load_reduced_witness(value))
                .collect::<Vec<ReducedWire>>()
        })
        .collect::<Vec<_>>();

    let cached_commitment_roots = proof
        .trace_vdata
        .iter()
        .map(|vdata| {
            if let Some(vdata) = vdata {
                vdata
                    .cached_commitments
                    .iter()
                    .map(|commit| digest_scalar_to_fr(commit[0]))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        })
        .collect::<Vec<_>>();

    let gkr = load_gkr_proof_wire(ext_chip, &proof.gkr_proof);
    let batch = load_batch_constraint_proof_wire(ext_chip, &proof.batch_constraint_proof);
    let stacking = load_stacking_proof_wire(ext_chip, &proof.stacking_proof);
    let whir = load_whir_proof_wire(ext_chip, &proof.whir_proof);

    ProofWire {
        common_main_commit_root,
        public_values,
        cached_commitment_roots,
        gkr,
        batch,
        stacking,
        whir,
    }
}

#[allow(clippy::too_many_arguments)]
fn observe_preamble<B: crate::chip::BabyBearExt + Clone>(
    transcript: &mut TranscriptChip<B>,
    mvk: &MultiStarkVerifyingKey<RootConfig>,
    log_heights_per_air: &[usize],
    public_values: &[Vec<ReducedWire>],
    cached_commitment_roots: &[Vec<Fr>],
    vk_pre_hash: DigestWire,
    common_main_commit: DigestWire,
) {
    transcript.observe_commit(&vk_pre_hash);
    transcript.observe_commit(&common_main_commit);

    for air_idx in 0..mvk.inner.per_air.len() {
        if !mvk.inner.per_air[air_idx].is_required {
            let presence_flag = transcript
                .baby_bear()
                .load_reduced_constant(BabyBear::ONE);
            transcript.observe(&presence_flag);
        }

        if let Some(preprocessed) = mvk.inner.per_air[air_idx].preprocessed_data.as_ref() {
            let preprocessed_root = digest_scalar_to_fr(preprocessed.commit[0]);
            transcript.observe_commit(&digest_wire_from_root(preprocessed_root));
        } else {
            let lh = u32::try_from(log_heights_per_air[air_idx])
                .expect("log_height must fit u32");
            let log_height = transcript
                .baby_bear()
                .load_reduced_constant(BabyBear::from_u32(lh));
            transcript.observe(&log_height);
        }

        for root in &cached_commitment_roots[air_idx] {
            transcript.observe_commit(&digest_wire_from_root(*root));
        }

        for value in &public_values[air_idx] {
            transcript.observe(value);
        }
    }
}

pub fn constrained_verify<E: BabyBearExtInst>(
    ext_chip: &E,
    root_vk: &MultiStarkVerifyingKey<RootConfig>,
    proof_wire: &ProofWire,
    trace_id_to_air_id: &[usize],
    log_heights_per_air: &[usize],
    stacked_layouts: &[StackedLayout],
) where
    E::Base: Clone,
{
    assert_eq!(log_heights_per_air.len(), root_vk.inner.per_air.len());
    let l_skip = root_vk.inner.params.l_skip;
    let n_per_trace: Vec<isize> = trace_id_to_air_id
        .iter()
        .map(|&air_id| log_heights_per_air[air_id] as isize - l_skip as isize)
        .collect();

    let mvk_pre_hash_root = digest_scalar_to_fr(root_vk.pre_hash[0]);
    let mut transcript = TranscriptChip::new(ext_chip.base().clone());

    observe_preamble(
        &mut transcript,
        root_vk,
        log_heights_per_air,
        &proof_wire.public_values,
        &proof_wire.cached_commitment_roots,
        digest_wire_from_root(mvk_pre_hash_root),
        digest_wire_from_root(proof_wire.common_main_commit_root),
    );

    let batch = constrain_batch_constraints_verification(
        ext_chip,
        &mut transcript,
        &root_vk.inner,
        &proof_wire.gkr,
        &proof_wire.batch,
        &n_per_trace,
        trace_id_to_air_id,
        proof_wire.public_values.clone(),
    );

    let need_rot_per_commit = get_need_rot_per_commit(&root_vk.inner, trace_id_to_air_id);

    let batch_r = batch.r.clone();
    let stacked_reduction = constrain_stacked_reduction(
        ext_chip,
        &mut transcript,
        &proof_wire.stacking,
        stacked_layouts,
        &need_rot_per_commit,
        l_skip,
        root_vk.inner.params.n_stack,
        &batch.column_openings,
        &batch_r,
    );

    let u_cube = {
        let u = &stacked_reduction.u;
        assert!(!u.is_empty());
        let mut u_cube = Vec::with_capacity(l_skip + u.len().saturating_sub(1));
        let mut power = *u.first().unwrap();
        for _ in 0..l_skip {
            u_cube.push(power);
            power = ext_chip.square(power);
            power = ext_chip.reduce_max_bits(power);
        }
        u_cube.extend(u.iter().skip(1).copied());
        u_cube
    };

    let initial_commitment_roots = {
        let common_main_root = proof_wire.common_main_commit_root;
        let mut commits = vec![common_main_root];
        for &air_id in trace_id_to_air_id {
            if let Some(preprocessed) = &root_vk.inner.per_air[air_id].preprocessed_data {
                commits.push(digest_scalar_to_fr(preprocessed.commit[0]));
            }
            commits.extend(proof_wire.cached_commitment_roots[air_id].iter().copied());
        }
        commits
    };

    constrain_whir_verification(
        ext_chip,
        &mut transcript,
        &root_vk.inner,
        &proof_wire.whir,
        &stacked_reduction.stacking_openings,
        &initial_commitment_roots,
        &u_cube,
    );
}

fn get_need_rot_per_commit(
    mvk0: &MultiStarkVerifyingKey0<RootConfig>,
    trace_id_to_air_id: &[usize],
) -> Vec<Vec<bool>> {
    let mut need_rot_per_commit = vec![trace_id_to_air_id
        .iter()
        .map(|&air_id| mvk0.per_air[air_id].params.need_rot)
        .collect::<Vec<_>>()];
    for &air_id in trace_id_to_air_id {
        let need_rot = mvk0.per_air[air_id].params.need_rot;
        if mvk0.per_air[air_id].preprocessed_data.is_some() {
            need_rot_per_commit.push(vec![need_rot]);
        }
        let cached_len = mvk0.per_air[air_id].params.width.cached_mains.len();
        for _ in 0..cached_len {
            need_rot_per_commit.push(vec![need_rot]);
        }
    }
    need_rot_per_commit
}
