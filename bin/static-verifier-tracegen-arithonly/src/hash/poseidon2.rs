//! Native-Fr Poseidon2 permutation. Same schedule / constants as
//! `openvm/crates/static-verifier/src/hash/poseidon2.rs` but without gate rows.

use halo2_base::halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};

pub(crate) use openvm_stark_sdk::config::baby_bear_bn254_poseidon2::{
    BABY_BEAR_RATE as MULTI_FIELD32_RATE, BN254_RATE as POSEIDON2_RATE, DIGEST_WIDTH,
};

use super::{Poseidon2Params, COMPRESS_WIDTH};
use crate::chip::GateChip;
use crate::wire::ReducedWire;

const MULTI_FIELD32_NUM_F_ELMS: usize = MULTI_FIELD32_RATE / POSEIDON2_RATE;

#[derive(Clone, Debug)]
pub struct Poseidon2State<const T: usize> {
    pub s: [Fr; T],
}

impl<const T: usize> Poseidon2State<T> {
    #[inline]
    pub fn new(state: [Fr; T]) -> Self {
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
            self.s[0] += params.internal_rc[r];
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
    fn x_power5(x: Fr) -> Fr {
        let x2 = x * x;
        let x4 = x2 * x2;
        x * x4
    }

    fn sbox(&mut self) {
        for x in self.s.iter_mut() {
            *x = Self::x_power5(*x);
        }
    }

    fn add_rc(&mut self, rc: &[Fr; T]) {
        for (x, r) in self.s.iter_mut().zip(rc.iter()) {
            *x += r;
        }
    }

    fn matmul_external(&mut self) {
        // T=3: circulant matrix (2,1,1). Equivalent to `s[i] += sum(s)`.
        // T=2: circ(2,1) = [[2,1],[1,2]]. Same identity.
        assert!(T == 2 || T == 3);
        let mut sum = Fr::ZERO;
        for x in self.s.iter() {
            sum += x;
        }
        for x in self.s.iter_mut() {
            *x += sum;
        }
    }

    fn matmul_internal(&mut self, diag: &[Fr; T]) {
        assert!(T == 2 || T == 3);
        let mut sum = Fr::ZERO;
        for x in self.s.iter() {
            sum += x;
        }
        for i in 0..T {
            self.s[i] = self.s[i] * diag[i] + sum;
        }
    }
}

pub(crate) fn pack_base_2_31_cells(_gate: &GateChip, values: &[ReducedWire]) -> Fr {
    assert!(values.len() <= MULTI_FIELD32_NUM_F_ELMS);
    let base = Fr::from(1u64 << 31);
    let mut acc = Fr::ZERO;
    let mut pow = Fr::ONE;
    for v in values {
        acc += v.value() * pow;
        pow *= base;
    }
    acc
}

pub(crate) fn hash_babybear_slice_to_digest(gate: &GateChip, values: &[ReducedWire]) -> Fr {
    let params = &*super::POSEIDON2_PARAMS;
    let mut state = Poseidon2State::new([Fr::ZERO; super::POSEIDON2_WIDTH]);
    for block_chunk in values.chunks(MULTI_FIELD32_RATE) {
        for (chunk_id, chunk) in block_chunk.chunks(MULTI_FIELD32_NUM_F_ELMS).enumerate() {
            state.s[chunk_id] = pack_base_2_31_cells(gate, chunk);
        }
        state.permutation(params);
    }
    state.s[0]
}

pub(crate) fn compress_bn254_digests(left: Fr, right: Fr) -> Fr {
    let params = &*super::POSEIDON2_COMPRESS_PARAMS;
    let mut state = Poseidon2State::<COMPRESS_WIDTH>::new([left, right]);
    state.permutation(params);
    state.s[0]
}
