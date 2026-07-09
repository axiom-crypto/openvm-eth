//! Arithmetic-only counterparts of the ProofWire types.
//!
//! Same shape as `openvm/crates/static-verifier/src/stages/{full_pipeline,
//! batch_constraints, stacked_reduction, whir}/mod.rs`, but with
//! `AssignedValue<Fr>` → `Fr` and `BabyBearWire` → `Wire`.

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

use crate::wire::{ExtWire, ReducedExtWire, ReducedWire};

#[derive(Clone, Debug)]
pub struct GkrProofWire {
    pub logup_pow_witness: ReducedWire,
    pub q0_claim: ReducedExtWire,
    pub claims_per_layer: Vec<[ReducedExtWire; 4]>,
    pub sumcheck_polys: Vec<Vec<[ReducedExtWire; 3]>>,
}

#[derive(Clone, Debug)]
pub struct BatchConstraintProofWire {
    pub numerator_term_per_air: Vec<ReducedExtWire>,
    pub denominator_term_per_air: Vec<ReducedExtWire>,
    pub univariate_round_coeffs: Vec<ReducedExtWire>,
    pub sumcheck_round_polys: Vec<Vec<ReducedExtWire>>,
    pub column_openings: Vec<Vec<Vec<ReducedExtWire>>>,
}

#[derive(Clone, Debug)]
pub struct StackingProofWire {
    pub univariate_round_coeffs: Vec<ReducedExtWire>,
    pub sumcheck_round_polys: Vec<Vec<ReducedExtWire>>,
    pub stacking_openings: Vec<Vec<ReducedExtWire>>,
}

#[derive(Clone, Debug)]
pub struct MerklePathWire {
    pub leaf_values: Vec<Vec<ReducedWire>>,
    pub siblings: Vec<Fr>,
}

#[derive(Clone, Debug)]
pub struct WhirProofWire {
    pub mu_pow_witness: ReducedWire,
    pub folding_pow_witnesses: Vec<ReducedWire>,
    pub query_phase_pow_witnesses: Vec<ReducedWire>,
    pub whir_sumcheck_polys: Vec<[ReducedExtWire; 2]>,
    pub ood_values: Vec<ReducedExtWire>,
    pub final_poly: Vec<ReducedExtWire>,
    pub codeword_commitment_roots: Vec<Fr>,
    pub initial_round_merkle_paths: Vec<Vec<MerklePathWire>>,
    pub codeword_merkle_paths: Vec<Vec<MerklePathWire>>,
}

#[derive(Clone, Debug)]
pub struct ProofWire {
    pub common_main_commit_root: Fr,
    pub public_values: Vec<Vec<ReducedWire>>,
    pub cached_commitment_roots: Vec<Vec<Fr>>,
    pub gkr: GkrProofWire,
    pub batch: BatchConstraintProofWire,
    pub stacking: StackingProofWire,
    pub whir: WhirProofWire,
}

#[derive(Clone, Debug)]
pub struct BatchConstraintIntermediatesWire {
    pub column_openings: Vec<Vec<Vec<ReducedExtWire>>>,
    pub r: Vec<ExtWire>,
}

#[derive(Clone, Debug)]
pub struct StackedReductionIntermediatesWire {
    pub stacking_openings: Vec<Vec<ReducedExtWire>>,
    pub u: Vec<ExtWire>,
}
