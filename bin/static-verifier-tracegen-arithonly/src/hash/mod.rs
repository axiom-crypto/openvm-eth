//! BN254 Poseidon2 for the arithonly transcript. Same round schedule + round
//! constants as the halo2 gadget in
//! `openvm/crates/static-verifier/src/hash/{mod,poseidon2}.rs`, but every Fr op
//! is a raw multiplication/addition — no advice cell writes.

use core::array;
use std::sync::LazyLock;

use halo2_base::{halo2_proofs::halo2curves::bn256::Fr, utils::biguint_to_fe};
pub(crate) use openvm_stark_sdk::config::baby_bear_bn254_poseidon2::SPONGE_WIDTH as POSEIDON2_WIDTH;
use openvm_stark_sdk::{
    config::bn254_poseidon2::{
        default_bn254_poseidon2_width2_constants, default_bn254_poseidon2_width3_constants,
        Poseidon2Bn254Constants,
    },
    openvm_stark_backend::p3_field::PrimeField,
};

pub mod poseidon2;

pub(crate) const COMPRESS_WIDTH: usize = 2;

#[derive(Debug, Clone)]
pub struct Poseidon2Params<const T: usize> {
    pub rounds_f: usize,
    pub rounds_p: usize,
    pub mat_internal_diag_m_1: [Fr; T],
    pub external_rc: Vec<[Fr; T]>,
    pub internal_rc: Vec<Fr>,
}

fn bn254_constants_to_params<const T: usize>(
    constants: &Poseidon2Bn254Constants<T>,
) -> Poseidon2Params<T> {
    use openvm_stark_sdk::config::baby_bear_bn254_poseidon2::Bn254Scalar;
    let bn254_to_fr = |elem: &Bn254Scalar| -> Fr { biguint_to_fe(&elem.as_canonical_biguint()) };

    let initial_ext: Vec<[Fr; T]> = constants
        .initial_external_rc()
        .iter()
        .map(|rc| array::from_fn(|i| bn254_to_fr(&rc[i])))
        .collect();
    let terminal_ext: Vec<[Fr; T]> = constants
        .terminal_external_rc()
        .iter()
        .map(|rc| array::from_fn(|i| bn254_to_fr(&rc[i])))
        .collect();
    let internal_rc: Vec<Fr> = constants.internal_rc().iter().map(bn254_to_fr).collect();
    let mat_internal_diag_m_1 =
        array::from_fn(|i| bn254_to_fr(&constants.mat_internal_diag_m_1()[i]));

    let mut external_rc = initial_ext;
    external_rc.extend(terminal_ext);

    Poseidon2Params {
        rounds_f: external_rc.len(),
        rounds_p: internal_rc.len(),
        mat_internal_diag_m_1,
        external_rc,
        internal_rc,
    }
}

pub(crate) static POSEIDON2_PARAMS: LazyLock<Poseidon2Params<POSEIDON2_WIDTH>> =
    LazyLock::new(|| bn254_constants_to_params(default_bn254_poseidon2_width3_constants()));

pub(crate) static POSEIDON2_COMPRESS_PARAMS: LazyLock<Poseidon2Params<COMPRESS_WIDTH>> =
    LazyLock::new(|| bn254_constants_to_params(default_bn254_poseidon2_width2_constants()));
