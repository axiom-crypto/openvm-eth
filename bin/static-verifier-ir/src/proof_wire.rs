//! Backend-generic ProofWire types.
//!
//! Proof digests (commitment roots, merkle siblings) are proof-derived, so
//! they are loaded as backend inputs (`B::V`), not host `Fr`.

use crate::{
    backend::Backend,
    wire::{ExtWire, ReducedExtWire, ReducedWire},
};

#[derive(Clone, Debug)]
pub struct GkrProofWire<B: Backend> {
    pub logup_pow_witness: ReducedWire<B>,
    pub q0_claim: ReducedExtWire<B>,
    pub claims_per_layer: Vec<[ReducedExtWire<B>; 4]>,
    pub sumcheck_polys: Vec<Vec<[ReducedExtWire<B>; 3]>>,
}

#[derive(Clone, Debug)]
pub struct BatchConstraintProofWire<B: Backend> {
    pub numerator_term_per_air: Vec<ReducedExtWire<B>>,
    pub denominator_term_per_air: Vec<ReducedExtWire<B>>,
    pub univariate_round_coeffs: Vec<ReducedExtWire<B>>,
    pub sumcheck_round_polys: Vec<Vec<ReducedExtWire<B>>>,
    pub column_openings: Vec<Vec<Vec<ReducedExtWire<B>>>>,
}

#[derive(Clone, Debug)]
pub struct StackingProofWire<B: Backend> {
    pub univariate_round_coeffs: Vec<ReducedExtWire<B>>,
    pub sumcheck_round_polys: Vec<Vec<ReducedExtWire<B>>>,
    pub stacking_openings: Vec<Vec<ReducedExtWire<B>>>,
}

#[derive(Clone, Debug)]
pub struct MerklePathWire<B: Backend> {
    pub leaf_values: Vec<Vec<ReducedWire<B>>>,
    pub siblings: Vec<B::V>,
}

#[derive(Clone, Debug)]
pub struct WhirProofWire<B: Backend> {
    pub mu_pow_witness: ReducedWire<B>,
    pub folding_pow_witnesses: Vec<ReducedWire<B>>,
    pub query_phase_pow_witnesses: Vec<ReducedWire<B>>,
    pub whir_sumcheck_polys: Vec<[ReducedExtWire<B>; 2]>,
    pub ood_values: Vec<ReducedExtWire<B>>,
    pub final_poly: Vec<ReducedExtWire<B>>,
    pub codeword_commitment_roots: Vec<B::V>,
    pub initial_round_merkle_paths: Vec<Vec<MerklePathWire<B>>>,
    pub codeword_merkle_paths: Vec<Vec<MerklePathWire<B>>>,
}

#[derive(Clone, Debug)]
pub struct ProofWire<B: Backend> {
    pub common_main_commit_root: B::V,
    pub public_values: Vec<Vec<ReducedWire<B>>>,
    pub cached_commitment_roots: Vec<Vec<B::V>>,
    pub gkr: GkrProofWire<B>,
    pub batch: BatchConstraintProofWire<B>,
    pub stacking: StackingProofWire<B>,
    pub whir: WhirProofWire<B>,
}

#[derive(Clone, Debug)]
pub struct BatchConstraintIntermediatesWire<B: Backend> {
    pub column_openings: Vec<Vec<Vec<ReducedExtWire<B>>>>,
    pub r: Vec<ExtWire<B>>,
}

#[derive(Clone, Debug)]
pub struct StackedReductionIntermediatesWire<B: Backend> {
    pub stacking_openings: Vec<Vec<ReducedExtWire<B>>>,
    pub u: Vec<ExtWire<B>>,
}
