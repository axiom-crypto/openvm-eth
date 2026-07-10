//! Repr-generic Poseidon2 permutation.

pub(crate) use openvm_stark_sdk::config::baby_bear_bn254_poseidon2::{
    BABY_BEAR_RATE as MULTI_FIELD32_RATE, BN254_RATE as POSEIDON2_RATE, DIGEST_WIDTH,
};

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

use super::{Poseidon2Params, COMPRESS_WIDTH};
use crate::chip::GateChip;
use crate::repr::FieldRepr;
use crate::wire::ReducedWire;

const MULTI_FIELD32_NUM_F_ELMS: usize = MULTI_FIELD32_RATE / POSEIDON2_RATE;

#[derive(Clone, Debug)]
pub struct Poseidon2State<R: FieldRepr, const T: usize> {
    pub s: [R; T],
}

impl<R: FieldRepr, const T: usize> Poseidon2State<R, T> {
    #[inline]
    pub fn new(state: [R; T]) -> Self {
        Self { s: state }
    }

    pub fn permutation(&mut self, params: &Poseidon2Params<T>) {
        let rounds_f_beginning = params.rounds_f / 2;
        self.matmul_external();

        for r in 0..rounds_f_beginning {
            self.add_rc(&params.external_rc[r]);
            self.sbox();
            self.matmul_external();
        }
        for r in 0..params.rounds_p {
            self.s[0] = R::add(self.s[0], R::from_fr(params.internal_rc[r]));
            self.s[0] = Self::x_power5(self.s[0]);
            self.matmul_internal(&params.mat_internal_diag_m_1);
        }
        for r in rounds_f_beginning..params.rounds_f {
            self.add_rc(&params.external_rc[r]);
            self.sbox();
            self.matmul_external();
        }
    }

    #[inline]
    fn x_power5(x: R) -> R {
        let x2 = R::mul(x, x);
        let x4 = R::mul(x2, x2);
        R::mul(x, x4)
    }

    fn sbox(&mut self) {
        for x in self.s.iter_mut() {
            *x = Self::x_power5(*x);
        }
    }

    fn add_rc(&mut self, rc: &[Fr; T]) {
        for (x, r) in self.s.iter_mut().zip(rc.iter()) {
            *x = R::add(*x, R::from_fr(*r));
        }
    }

    fn matmul_external(&mut self) {
        assert!(T == 2 || T == 3);
        let mut sum = R::zero();
        for x in self.s.iter() {
            sum = R::add(sum, *x);
        }
        for x in self.s.iter_mut() {
            *x = R::add(*x, sum);
        }
    }

    fn matmul_internal(&mut self, diag: &[Fr; T]) {
        assert!(T == 2 || T == 3);
        let mut sum = R::zero();
        for x in self.s.iter() {
            sum = R::add(sum, *x);
        }
        for i in 0..T {
            self.s[i] = R::add(R::mul(self.s[i], R::from_fr(diag[i])), sum);
        }
    }
}

pub(crate) fn pack_base_2_31_cells<R: FieldRepr>(
    _gate: &GateChip<R>,
    values: &[ReducedWire<R>],
) -> R {
    assert!(values.len() <= MULTI_FIELD32_NUM_F_ELMS);
    let base = Fr::from(1u64 << 31);
    let mut acc = R::zero();
    let mut pow = Fr::from(1u64);
    for v in values {
        acc = R::add(acc, R::mul(v.value(), R::from_fr(pow)));
        pow *= base;
    }
    acc
}

pub(crate) fn hash_babybear_slice_to_digest<R: FieldRepr>(
    gate: &GateChip<R>,
    values: &[ReducedWire<R>],
) -> R {
    let params = &*super::POSEIDON2_PARAMS;
    let mut state = Poseidon2State::<R, { super::POSEIDON2_WIDTH }>::new([R::zero(); super::POSEIDON2_WIDTH]);
    for block_chunk in values.chunks(MULTI_FIELD32_RATE) {
        for (chunk_id, chunk) in block_chunk.chunks(MULTI_FIELD32_NUM_F_ELMS).enumerate() {
            state.s[chunk_id] = pack_base_2_31_cells(gate, chunk);
        }
        state.permutation(params);
    }
    state.s[0]
}

pub(crate) fn compress_bn254_digests<R: FieldRepr>(left: R, right: R) -> R {
    let params = &*super::POSEIDON2_COMPRESS_PARAMS;
    let mut state = Poseidon2State::<R, COMPRESS_WIDTH>::new([left, right]);
    state.permutation(params);
    state.s[0]
}
