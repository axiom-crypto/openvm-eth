//! Arithmetic-only Poseidon2 transcript.
//!
//! Port of `openvm/crates/static-verifier/src/transcript/mod.rs`.

use core::{array, iter};
use std::sync::OnceLock;

use halo2_base::{
    halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr},
    utils::{biguint_to_fe, fe_to_biguint},
};
use num_bigint::BigUint;
use openvm_stark_sdk::{
    config::baby_bear_bn254_poseidon2::{Bn254Scalar, Digest as RootDigest},
    openvm_stark_backend::p3_field::{Field as P3Field, PrimeField},
};

use crate::chip::baby_bear::{BABYBEAR_MAX_BITS, BABY_BEAR_MODULUS_U64};
use crate::chip::{BabyBearExt, RangeExt};
use crate::hash::poseidon2::{pack_base_2_31_cells, Poseidon2State, DIGEST_WIDTH, POSEIDON2_RATE};
use crate::hash::{POSEIDON2_PARAMS, POSEIDON2_WIDTH};
use crate::wire::{ExtWire, ReducedExtWire, ReducedWire, Wire};

const NUM_OBS_PER_WORD: usize = 8;
const NUM_SAMPLES_PER_WORD: usize = 5;

struct BaseBabyBearDecompBounds {
    top_quotient_max_fe: Fr,
    top_quotient_max_plus_one: BigUint,
    lower_max_plus_one: BigUint,
    pow_k: BigUint,
}

fn base_baby_bear_decomp_bounds() -> &'static BaseBabyBearDecompBounds {
    static BOUNDS: OnceLock<BaseBabyBearDecompBounds> = OnceLock::new();
    BOUNDS.get_or_init(|| {
        let p = BigUint::from(BABY_BEAR_MODULUS_U64);
        let one = BigUint::from(1u64);
        let modulus = <Bn254Scalar as P3Field>::order();
        let modulus_minus_one = &modulus - &one;
        let pow_k = p.pow(NUM_SAMPLES_PER_WORD as u32);
        let q_k_max = &modulus_minus_one / &pow_k;
        let lower_max = modulus_minus_one - &q_k_max * &pow_k;
        BaseBabyBearDecompBounds {
            top_quotient_max_fe: biguint_to_fe(&q_k_max),
            top_quotient_max_plus_one: &q_k_max + &one,
            lower_max_plus_one: lower_max + one,
            pow_k,
        }
    })
}

fn load_base_baby_bear_decomposition_witness(
    packed: Fr,
) -> ([Fr; NUM_SAMPLES_PER_WORD], Fr) {
    let p = BigUint::from(BABY_BEAR_MODULUS_U64);
    let mut value = fe_to_biguint(&packed);
    let digit_witnesses_big: [BigUint; NUM_SAMPLES_PER_WORD] = array::from_fn(|_| {
        let digit = &value % &p;
        value /= &p;
        digit
    });
    let top_quotient_big = value;
    let digit_witnesses: [Fr; NUM_SAMPLES_PER_WORD] =
        array::from_fn(|idx| biguint_to_fe(&digit_witnesses_big[idx]));
    let top_quotient: Fr = biguint_to_fe(&top_quotient_big);
    (digit_witnesses, top_quotient)
}

fn constrain_base_baby_bear_decomposition<B: BabyBearExt>(
    base: &B,
    packed: Fr,
    digit_witnesses: [Fr; NUM_SAMPLES_PER_WORD],
    top_quotient: Fr,
    bounds: &BaseBabyBearDecompBounds,
) -> [Wire; NUM_SAMPLES_PER_WORD] {
    let range = base.range();
    let gate = range.gate();
    let p = BigUint::from(BABY_BEAR_MODULUS_U64);
    let one_big = BigUint::from(1u64);
    let _ = one_big;

    for &digit in &digit_witnesses {
        range.check_less_than_safe(digit, BABY_BEAR_MODULUS_U64);
    }
    let top_quotient_valid =
        range.is_big_less_than_safe(top_quotient, bounds.top_quotient_max_plus_one.clone());
    gate.assert_is_const(top_quotient_valid, &Fr::ONE);

    // lower = Σ digit_i * p^i
    let lower = {
        let powers: Vec<Fr> = iter::successors(Some(Fr::ONE), |power| {
            Some(*power * biguint_to_fe::<Fr>(&p))
        })
        .take(NUM_SAMPLES_PER_WORD)
        .collect();
        gate.inner_product(digit_witnesses, powers)
    };

    // packed == top_quotient * p^k + lower
    let _recomposed = gate.mul_add(top_quotient, biguint_to_fe(&bounds.pow_k), lower);

    let at_top_boundary = gate.is_equal(top_quotient, bounds.top_quotient_max_fe);
    let lower_range_bits =
        (bounds.pow_k.bits() as usize).div_ceil(range.lookup_bits()) * range.lookup_bits();
    range.range_check(lower, lower_range_bits);
    let lower_is_valid =
        range.is_less_than(lower, biguint_to_fe(&bounds.lower_max_plus_one), lower_range_bits);
    let lower_is_invalid = gate.not(lower_is_valid);
    let lower_violation = gate.mul(at_top_boundary, lower_is_invalid);
    gate.assert_is_const(lower_violation, &Fr::ZERO);

    digit_witnesses.map(|value| Wire::new(value, BABYBEAR_MAX_BITS))
}

fn decompose_bn254_to_base_baby_bear_digits<B: BabyBearExt>(
    baby_bear: &B,
    packed: Fr,
) -> [Wire; NUM_SAMPLES_PER_WORD] {
    let bounds = base_baby_bear_decomp_bounds();
    let (digit_witnesses, top_quotient) = load_base_baby_bear_decomposition_witness(packed);
    constrain_base_baby_bear_decomposition(baby_bear, packed, digit_witnesses, top_quotient, bounds)
}

#[derive(Clone, Debug)]
pub struct DigestWire {
    pub elems: [Fr; DIGEST_WIDTH],
}

pub fn digest_wire_from_root(root: Fr) -> DigestWire {
    DigestWire {
        elems: array::from_fn(|_| root),
    }
}

fn bn254_to_halo2(value: Bn254Scalar) -> Fr {
    biguint_to_fe(&value.as_canonical_biguint())
}

pub fn load_digest_witness(digest: RootDigest) -> DigestWire {
    DigestWire {
        elems: array::from_fn(|i| bn254_to_halo2(digest[i])),
    }
}

#[derive(Clone, Debug)]
pub struct TranscriptChip<B: BabyBearExt + Clone> {
    baby_bear: B,
    sponge_state: [Fr; POSEIDON2_WIDTH],
    absorb_idx: usize,
    sample_idx: usize,
    observe_buf: Vec<ReducedWire>,
    sample_buf: Vec<Wire>,
}

impl<B: BabyBearExt + Clone> TranscriptChip<B> {
    pub fn baby_bear(&self) -> &B {
        &self.baby_bear
    }

    pub fn new(baby_bear: B) -> Self {
        Self {
            baby_bear,
            sponge_state: [Fr::ZERO; POSEIDON2_WIDTH],
            absorb_idx: 0,
            sample_idx: 0,
            observe_buf: Vec::with_capacity(NUM_OBS_PER_WORD),
            sample_buf: Vec::with_capacity(NUM_SAMPLES_PER_WORD),
        }
    }

    fn sponge_absorb(&mut self, value: Fr) {
        self.sponge_state[self.absorb_idx] = value;
        self.absorb_idx += 1;
        if self.absorb_idx == POSEIDON2_RATE {
            self.permute_state();
            self.absorb_idx = 0;
            self.sample_idx = POSEIDON2_RATE;
        }
    }

    fn sponge_squeeze(&mut self) -> Fr {
        if self.absorb_idx != 0 || self.sample_idx == 0 {
            self.permute_state();
            self.absorb_idx = 0;
            self.sample_idx = POSEIDON2_RATE;
        }
        self.sample_idx -= 1;
        self.sponge_state[self.sample_idx]
    }

    fn permute_state(&mut self) {
        let mut state = Poseidon2State::new(self.sponge_state);
        state.permutation(&POSEIDON2_PARAMS);
        self.sponge_state = state.s;
    }

    fn invalidate_samples(&mut self) {
        self.sample_buf.clear();
    }

    fn flush_observe_buf(&mut self) {
        if !self.observe_buf.is_empty() {
            let gate = self.baby_bear.gate();
            let packed = pack_base_2_31_cells(gate, &self.observe_buf);
            self.sponge_absorb(packed);
            self.observe_buf.clear();
        }
    }

    fn absorb_digest(&mut self, digest: &DigestWire) {
        self.invalidate_samples();
        self.flush_observe_buf();
        for &elem in &digest.elems {
            self.sponge_absorb(elem);
        }
    }

    pub fn observe(&mut self, value: &ReducedWire) {
        self.invalidate_samples();
        self.observe_buf.push(*value);
        if self.observe_buf.len() == NUM_OBS_PER_WORD {
            self.flush_observe_buf();
        }
    }

    pub fn observe_ext(&mut self, value: &ReducedExtWire) {
        for coeff in value.coeffs() {
            self.observe(coeff);
        }
    }

    pub fn observe_commit(&mut self, digest: &DigestWire) {
        self.absorb_digest(digest);
    }

    pub fn sample(&mut self) -> Wire {
        if let Some(val) = self.sample_buf.pop() {
            return val;
        }
        self.flush_observe_buf();
        let squeezed = self.sponge_squeeze();
        let mut digits: Vec<Wire> =
            decompose_bn254_to_base_baby_bear_digits(&self.baby_bear, squeezed).to_vec();
        digits.reverse();
        self.sample_buf = digits;
        self.sample_buf.pop().expect("sample_buf non-empty")
    }

    pub fn sample_ext(&mut self) -> ExtWire {
        ExtWire(array::from_fn(|_| self.sample()))
    }

    pub fn sample_bits(&mut self, bits: usize) -> Fr {
        assert!(bits < (u32::BITS as usize));
        assert!((1u64 << bits) < BABY_BEAR_MODULUS_U64);
        let sampled = self.sample();
        if bits == 0 {
            return Fr::ZERO;
        }
        let range = self.baby_bear.range();
        let divisor = BigUint::from(1u64) << bits;
        let (_, rem) = range.div_mod(sampled.value, divisor, BABYBEAR_MAX_BITS as usize);
        rem
    }

    pub fn check_witness(&mut self, bits: usize, witness: &ReducedWire) {
        if bits == 0 {
            return;
        }
        self.observe(witness);
        let sampled_bits = self.sample_bits(bits);
        self.baby_bear
            .gate()
            .assert_is_const(sampled_bits, &Fr::ZERO);
    }
}
