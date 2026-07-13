//! Backend-generic Poseidon2 transcript.

use core::{array, iter};
use std::sync::OnceLock;

use halo2_base::{
    halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr},
    utils::biguint_to_fe,
};
use num_bigint::BigUint;
use openvm_stark_sdk::{
    config::baby_bear_bn254_poseidon2::Bn254Scalar,
    openvm_stark_backend::p3_field::Field as P3Field,
};

use crate::{
    backend::Backend,
    chip::baby_bear::{BabyBearChip, BABYBEAR_MAX_BITS, BABY_BEAR_MODULUS_U64},
    hash::{
        poseidon2::{pack_base_2_31_cells, DIGEST_WIDTH, POSEIDON2_RATE},
        POSEIDON2_WIDTH,
    },
    wire::{ExtWire, ReducedExtWire, ReducedWire, Wire},
};

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

fn decompose_bn254_to_base_baby_bear_digits<B: Backend>(
    ctx: &mut B::Ctx,
    baby_bear: &BabyBearChip<B>,
    packed: B::V,
) -> [Wire<B>; NUM_SAMPLES_PER_WORD] {
    let bounds = base_baby_bear_decomp_bounds();
    let (digit_witnesses, top_quotient) = B::bn_to_bb_digits(ctx, packed);

    let range = baby_bear.range();
    let gate = range.gate();
    let p = BigUint::from(BABY_BEAR_MODULUS_U64);

    for &digit in &digit_witnesses {
        range.check_less_than_safe(ctx, digit, BABY_BEAR_MODULUS_U64);
    }
    let top_quotient_valid =
        range.is_big_less_than_safe(ctx, top_quotient, bounds.top_quotient_max_plus_one.clone());
    gate.assert_is_const(ctx, top_quotient_valid, &Fr::ONE);

    let lower = {
        let powers: Vec<B::V> =
            iter::successors(Some(Fr::ONE), |power| Some(*power * biguint_to_fe::<Fr>(&p)))
                .take(NUM_SAMPLES_PER_WORD)
                .map(|power| B::constant(ctx, power))
                .collect();
        gate.inner_product(ctx, digit_witnesses, powers)
    };

    let pow_k_val = B::constant(ctx, biguint_to_fe(&bounds.pow_k));
    let _recomposed = gate.mul_add(ctx, top_quotient, pow_k_val, lower);

    let top_max = B::constant(ctx, bounds.top_quotient_max_fe);
    let at_top_boundary = gate.is_equal(ctx, top_quotient, top_max);
    let lower_range_bits =
        (bounds.pow_k.bits() as usize).div_ceil(range.lookup_bits()) * range.lookup_bits();
    range.range_check(ctx, lower, lower_range_bits);
    let lower_max = B::constant(ctx, biguint_to_fe(&bounds.lower_max_plus_one));
    let lower_is_valid = range.is_less_than(ctx, lower, lower_max, lower_range_bits);
    let lower_is_invalid = gate.not(ctx, lower_is_valid);
    let lower_violation = gate.mul(ctx, at_top_boundary, lower_is_invalid);
    gate.assert_is_const(ctx, lower_violation, &Fr::ZERO);

    digit_witnesses.map(|value| Wire::new(value, BABYBEAR_MAX_BITS))
}

#[derive(Clone, Debug)]
pub struct DigestWire<B: Backend> {
    pub elems: [B::V; DIGEST_WIDTH],
}

pub fn digest_wire_from_root<B: Backend>(root: B::V) -> DigestWire<B> {
    DigestWire { elems: array::from_fn(|_| root) }
}

#[derive(Clone, Debug)]
pub struct TranscriptChip<B: Backend> {
    baby_bear: BabyBearChip<B>,
    sponge_state: [B::V; POSEIDON2_WIDTH],
    absorb_idx: usize,
    sample_idx: usize,
    observe_buf: Vec<ReducedWire<B>>,
    sample_buf: Vec<Wire<B>>,
}

impl<B: Backend> TranscriptChip<B> {
    pub fn baby_bear(&self) -> &BabyBearChip<B> {
        &self.baby_bear
    }

    pub fn new(ctx: &mut B::Ctx, baby_bear: BabyBearChip<B>) -> Self {
        let zero = B::constant(ctx, Fr::ZERO);
        Self {
            baby_bear,
            sponge_state: [zero; POSEIDON2_WIDTH],
            absorb_idx: 0,
            sample_idx: 0,
            observe_buf: Vec::with_capacity(NUM_OBS_PER_WORD),
            sample_buf: Vec::with_capacity(NUM_SAMPLES_PER_WORD),
        }
    }

    fn sponge_absorb(&mut self, ctx: &mut B::Ctx, value: B::V) {
        self.sponge_state[self.absorb_idx] = value;
        self.absorb_idx += 1;
        if self.absorb_idx == POSEIDON2_RATE {
            self.permute_state(ctx);
            self.absorb_idx = 0;
            self.sample_idx = POSEIDON2_RATE;
        }
    }

    fn sponge_squeeze(&mut self, ctx: &mut B::Ctx) -> B::V {
        if self.absorb_idx != 0 || self.sample_idx == 0 {
            self.permute_state(ctx);
            self.absorb_idx = 0;
            self.sample_idx = POSEIDON2_RATE;
        }
        self.sample_idx -= 1;
        self.sponge_state[self.sample_idx]
    }

    fn permute_state(&mut self, ctx: &mut B::Ctx) {
        self.sponge_state = B::poseidon2_t3(ctx, self.sponge_state);
    }

    fn invalidate_samples(&mut self) {
        self.sample_buf.clear();
    }

    fn flush_observe_buf(&mut self, ctx: &mut B::Ctx) {
        if !self.observe_buf.is_empty() {
            let packed = pack_base_2_31_cells::<B>(ctx, &self.observe_buf);
            self.sponge_absorb(ctx, packed);
            self.observe_buf.clear();
        }
    }

    fn absorb_digest(&mut self, ctx: &mut B::Ctx, digest: &DigestWire<B>) {
        self.invalidate_samples();
        self.flush_observe_buf(ctx);
        for &elem in &digest.elems {
            self.sponge_absorb(ctx, elem);
        }
    }

    pub fn observe(&mut self, ctx: &mut B::Ctx, value: &ReducedWire<B>) {
        self.invalidate_samples();
        self.observe_buf.push(*value);
        if self.observe_buf.len() == NUM_OBS_PER_WORD {
            self.flush_observe_buf(ctx);
        }
    }

    pub fn observe_ext(&mut self, ctx: &mut B::Ctx, value: &ReducedExtWire<B>) {
        for coeff in value.coeffs() {
            self.observe(ctx, coeff);
        }
    }

    pub fn observe_commit(&mut self, ctx: &mut B::Ctx, digest: &DigestWire<B>) {
        self.absorb_digest(ctx, digest);
    }

    pub fn sample(&mut self, ctx: &mut B::Ctx) -> Wire<B> {
        if let Some(val) = self.sample_buf.pop() {
            return val;
        }
        self.flush_observe_buf(ctx);
        let squeezed = self.sponge_squeeze(ctx);
        let mut digits: Vec<Wire<B>> =
            decompose_bn254_to_base_baby_bear_digits(ctx, &self.baby_bear, squeezed).to_vec();
        digits.reverse();
        self.sample_buf = digits;
        self.sample_buf.pop().expect("sample_buf non-empty")
    }

    pub fn sample_ext(&mut self, ctx: &mut B::Ctx) -> ExtWire<B> {
        ExtWire(array::from_fn(|_| self.sample(ctx)))
    }

    pub fn sample_bits(&mut self, ctx: &mut B::Ctx, bits: usize) -> B::V {
        assert!(bits < (u32::BITS as usize));
        assert!((1u64 << bits) < BABY_BEAR_MODULUS_U64);
        let sampled = self.sample(ctx);
        if bits == 0 {
            return B::constant(ctx, Fr::ZERO);
        }
        let range = self.baby_bear.range();
        let divisor = BigUint::from(1u64) << bits;
        let (_, rem) = range.div_mod(ctx, sampled.value, divisor, BABYBEAR_MAX_BITS as usize);
        rem
    }

    pub fn check_witness(&mut self, ctx: &mut B::Ctx, bits: usize, witness: &ReducedWire<B>) {
        if bits == 0 {
            return;
        }
        self.observe(ctx, witness);
        let sampled_bits = self.sample_bits(ctx, bits);
        self.baby_bear.gate().assert_is_const(ctx, sampled_bits, &Fr::ZERO);
    }
}
