//! Repr-generic ProofWire types.

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

use crate::repr::FieldRepr;
use crate::wire::{ExtWire, ReducedExtWire, ReducedWire};

#[derive(Clone, Debug)]
pub struct GkrProofWire<R: FieldRepr> {
    pub logup_pow_witness: ReducedWire<R>,
    pub q0_claim: ReducedExtWire<R>,
    pub claims_per_layer: Vec<[ReducedExtWire<R>; 4]>,
    pub sumcheck_polys: Vec<Vec<[ReducedExtWire<R>; 3]>>,
}

#[derive(Clone, Debug)]
pub struct BatchConstraintProofWire<R: FieldRepr> {
    pub numerator_term_per_air: Vec<ReducedExtWire<R>>,
    pub denominator_term_per_air: Vec<ReducedExtWire<R>>,
    pub univariate_round_coeffs: Vec<ReducedExtWire<R>>,
    pub sumcheck_round_polys: Vec<Vec<ReducedExtWire<R>>>,
    pub column_openings: Vec<Vec<Vec<ReducedExtWire<R>>>>,
}

#[derive(Clone, Debug)]
pub struct StackingProofWire<R: FieldRepr> {
    pub univariate_round_coeffs: Vec<ReducedExtWire<R>>,
    pub sumcheck_round_polys: Vec<Vec<ReducedExtWire<R>>>,
    pub stacking_openings: Vec<Vec<ReducedExtWire<R>>>,
}

#[derive(Clone, Debug)]
pub struct MerklePathWire<R: FieldRepr> {
    pub leaf_values: Vec<Vec<ReducedWire<R>>>,
    pub siblings: Vec<Fr>,
}

#[derive(Clone, Debug)]
pub struct WhirProofWire<R: FieldRepr> {
    pub mu_pow_witness: ReducedWire<R>,
    pub folding_pow_witnesses: Vec<ReducedWire<R>>,
    pub query_phase_pow_witnesses: Vec<ReducedWire<R>>,
    pub whir_sumcheck_polys: Vec<[ReducedExtWire<R>; 2]>,
    pub ood_values: Vec<ReducedExtWire<R>>,
    pub final_poly: Vec<ReducedExtWire<R>>,
    pub codeword_commitment_roots: Vec<Fr>,
    pub initial_round_merkle_paths: Vec<Vec<MerklePathWire<R>>>,
    pub codeword_merkle_paths: Vec<Vec<MerklePathWire<R>>>,
}

#[derive(Clone, Debug)]
pub struct ProofWire<R: FieldRepr> {
    pub common_main_commit_root: Fr,
    pub public_values: Vec<Vec<ReducedWire<R>>>,
    pub cached_commitment_roots: Vec<Vec<Fr>>,
    pub gkr: GkrProofWire<R>,
    pub batch: BatchConstraintProofWire<R>,
    pub stacking: StackingProofWire<R>,
    pub whir: WhirProofWire<R>,
}

#[derive(Clone, Debug)]
pub struct BatchConstraintIntermediatesWire<R: FieldRepr> {
    pub column_openings: Vec<Vec<Vec<ReducedExtWire<R>>>>,
    pub r: Vec<ExtWire<R>>,
}

#[derive(Clone, Debug)]
pub struct StackedReductionIntermediatesWire<R: FieldRepr> {
    pub stacking_openings: Vec<Vec<ReducedExtWire<R>>>,
    pub u: Vec<ExtWire<R>>,
}
