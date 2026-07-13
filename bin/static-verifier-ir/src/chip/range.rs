//! Backend-generic `RangeChip<B>`.

use std::cmp::Ordering;

use halo2_base::{halo2_proofs::halo2curves::bn256::Fr, utils::biguint_to_fe};
use num_bigint::BigUint;

use super::gate::GateChip;
use crate::backend::Backend;

fn bit_length(x: u64) -> usize {
    if x == 0 {
        0
    } else {
        64 - x.leading_zeros() as usize
    }
}

#[derive(Clone, Debug)]
pub struct RangeChip<B: Backend> {
    pub gate: GateChip<B>,
    pub lookup_bits: usize,
    /// `[1, 2^lookup_bits, 2^{2*lookup_bits}, ...]` — Fr constants.
    pub limb_bases: Vec<Fr>,
}

impl<B: Backend> RangeChip<B> {
    pub fn new(lookup_bits: usize) -> Self {
        let gate = GateChip::new();
        let limb_base = Fr::from(1u64 << lookup_bits);
        let capacity = 253usize;
        let num_bases = capacity / lookup_bits;
        let mut running = limb_base;
        let mut limb_bases = Vec::with_capacity(num_bases + 1);
        limb_bases.push(Fr::from(1u64));
        limb_bases.push(running);
        for _ in 2..=num_bases {
            running *= limb_base;
            limb_bases.push(running);
        }
        Self { gate, lookup_bits, limb_bases }
    }

    #[inline]
    pub fn gate(&self) -> &GateChip<B> {
        &self.gate
    }

    #[inline]
    pub fn lookup_bits(&self) -> usize {
        self.lookup_bits
    }

    /// Limb decomposition + inner-product reconstruction, mirroring the
    /// halo2-lib RangeChip. Returns the last limb.
    fn _range_check(&self, ctx: &mut B::Ctx, a: B::V, range_bits: usize) -> B::V {
        if range_bits == 0 {
            return a;
        }
        let num_limbs = range_bits.div_ceil(self.lookup_bits);
        let rem_bits = range_bits % self.lookup_bits;

        let last_limb;
        if num_limbs == 1 {
            last_limb = a;
        } else {
            let limbs = B::decompose(ctx, a, num_limbs as u32, self.lookup_bits as u32);
            let mut acc = limbs[0];
            for i in 1..num_limbs {
                let base = B::constant(ctx, self.limb_bases[i]);
                let term = B::mul(ctx, limbs[i], base);
                acc = B::add(ctx, acc, term);
            }
            let _ = acc;
            last_limb = limbs[num_limbs - 1];
        }

        match rem_bits.cmp(&1) {
            Ordering::Equal => {}
            Ordering::Greater => {
                let mult = B::constant(ctx, self.gate.pow_of_two[self.lookup_bits - rem_bits]);
                let _check = B::mul(ctx, last_limb, mult);
            }
            Ordering::Less => {}
        }
        last_limb
    }

    pub fn range_check(&self, ctx: &mut B::Ctx, a: B::V, range_bits: usize) {
        self._range_check(ctx, a, range_bits);
    }

    pub fn check_less_than(&self, ctx: &mut B::Ctx, a: B::V, b: B::V, num_bits: usize) {
        assert!(num_bits < 253);
        let pow_of_two = B::constant(ctx, self.gate.pow_of_two[num_bits]);
        let shift_a_val = B::add(ctx, pow_of_two, a);
        let diff_val = B::sub(ctx, shift_a_val, b);
        self._range_check(ctx, diff_val, num_bits);
    }

    pub fn check_less_than_safe(&self, ctx: &mut B::Ctx, a: B::V, b: u64) {
        let range_bits = bit_length(b).div_ceil(self.lookup_bits) * self.lookup_bits;
        self._range_check(ctx, a, range_bits);
        let b_val = B::constant(ctx, Fr::from(b));
        self.check_less_than(ctx, a, b_val, range_bits);
    }

    pub fn check_big_less_than_safe(&self, ctx: &mut B::Ctx, a: B::V, b: BigUint) {
        let range_bits = (b.bits() as usize).div_ceil(self.lookup_bits) * self.lookup_bits;
        self._range_check(ctx, a, range_bits);
        let b_val = B::constant(ctx, biguint_to_fe(&b));
        self.check_less_than(ctx, a, b_val, range_bits);
    }

    pub fn is_less_than(&self, ctx: &mut B::Ctx, a: B::V, b: B::V, num_bits: usize) -> B::V {
        let k = num_bits.div_ceil(self.lookup_bits);
        let padded_bits = k * self.lookup_bits;
        assert!(padded_bits + self.lookup_bits <= 253);
        let pow_padded = B::constant(ctx, self.gate.pow_of_two[padded_bits]);
        let shift_a_val = B::add(ctx, pow_padded, a);
        let shifted_val = B::sub(ctx, shift_a_val, b);
        let last_limb = self._range_check(ctx, shifted_val, padded_bits + self.lookup_bits);
        self.gate.is_zero(ctx, last_limb)
    }

    pub fn is_less_than_safe(&self, ctx: &mut B::Ctx, a: B::V, b: u64) -> B::V {
        let range_bits = bit_length(b).div_ceil(self.lookup_bits) * self.lookup_bits;
        self._range_check(ctx, a, range_bits);
        let b_val = B::constant(ctx, Fr::from(b));
        self.is_less_than(ctx, a, b_val, range_bits)
    }

    pub fn is_big_less_than_safe(&self, ctx: &mut B::Ctx, a: B::V, b: BigUint) -> B::V {
        let range_bits = (b.bits() as usize).div_ceil(self.lookup_bits) * self.lookup_bits;
        self._range_check(ctx, a, range_bits);
        let b_val = B::constant(ctx, biguint_to_fe(&b));
        self.is_less_than(ctx, a, b_val, range_bits)
    }

    pub fn div_mod(
        &self,
        ctx: &mut B::Ctx,
        a: B::V,
        b: BigUint,
        a_num_bits: usize,
    ) -> (B::V, B::V) {
        let divisor = u32::try_from(&b).expect("div_mod divisor must fit u32");
        let (div, rem) = B::div_mod_u32(ctx, a, divisor);
        self.check_big_less_than_safe(
            ctx,
            div,
            (BigUint::from(1u32) << a_num_bits) / &b + BigUint::from(1u32),
        );
        self.check_big_less_than_safe(ctx, rem, b);
        (div, rem)
    }
}
