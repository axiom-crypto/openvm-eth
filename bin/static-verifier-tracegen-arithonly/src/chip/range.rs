//! Arithmetic-only `RangeChip<R>`.

use std::cmp::Ordering;
use std::marker::PhantomData;

use halo2_base::{
    halo2_proofs::halo2curves::bn256::Fr,
    utils::{biguint_to_fe, decompose_fe_to_u64_limbs, fe_to_biguint},
};
use num_bigint::BigUint;
use num_integer::Integer;

use super::gate::GateChip;
use super::RangeExt;
use crate::repr::FieldRepr;

fn bit_length(x: u64) -> usize {
    if x == 0 { 0 } else { 64 - x.leading_zeros() as usize }
}

#[derive(Clone, Debug)]
pub struct RangeChip<R: FieldRepr> {
    pub gate: GateChip<R>,
    pub lookup_bits: usize,
    /// `[1, 2^lookup_bits, 2^{2*lookup_bits}, ...]` — Fr constants.
    pub limb_bases: Vec<Fr>,
    _marker: PhantomData<R>,
}

impl<R: FieldRepr> RangeChip<R> {
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
        Self {
            gate,
            lookup_bits,
            limb_bases,
            _marker: PhantomData,
        }
    }

    /// Emit the arithmetic for `range_check`. Preserves the limb-decomposition
    /// + inner-product reconstruction (per user's decision).
    fn _range_check(&self, a: R, range_bits: usize) -> R {
        if range_bits == 0 {
            return a;
        }
        let num_limbs = range_bits.div_ceil(self.lookup_bits);
        let rem_bits = range_bits % self.lookup_bits;

        // Resolve to Fr for BigUint decomposition. For FractionRepr this may
        // invert the denominator, but in the arithonly path every value passed
        // to range_check is `Trivial` (nothing here comes from `is_zero`).
        let fr = R::resolve(a);
        let last_limb_r;
        if num_limbs == 1 {
            last_limb_r = a;
        } else {
            let limbs = decompose_fe_to_u64_limbs(&fr, num_limbs, self.lookup_bits);
            // Inner-product reconstruction; preserves n muls + (n-1) adds
            // exactly like `inner_product_simple` in halo2-lib.
            let mut acc = R::from_fr(Fr::from(limbs[0]));
            for i in 1..num_limbs {
                let term = R::mul(R::from_fr(Fr::from(limbs[i])), R::from_fr(self.limb_bases[i]));
                acc = R::add(acc, term);
            }
            let _ = acc;
            last_limb_r = R::from_fr(Fr::from(limbs[num_limbs - 1]));
        }

        match rem_bits.cmp(&1) {
            Ordering::Equal => {}
            Ordering::Greater => {
                let mult = R::from_fr(self.gate.pow_of_two[self.lookup_bits - rem_bits]);
                let _check = self.gate.mul(last_limb_r, mult);
            }
            Ordering::Less => {}
        }
        last_limb_r
    }
}

impl<R: FieldRepr> RangeExt for RangeChip<R> {
    type R = R;

    fn gate(&self) -> &GateChip<R> {
        &self.gate
    }

    fn lookup_bits(&self) -> usize {
        self.lookup_bits
    }

    fn range_check(&self, a: R, range_bits: usize) {
        self._range_check(a, range_bits);
    }

    fn check_less_than(&self, a: R, b: R, num_bits: usize) {
        assert!(num_bits < 253);
        let pow_of_two = R::from_fr(self.gate.pow_of_two[num_bits]);
        let shift_a_val = R::add(pow_of_two, a);
        let diff_val = R::sub(shift_a_val, b);
        self._range_check(diff_val, num_bits);
    }

    fn check_less_than_safe(&self, a: R, b: u64) {
        let range_bits = bit_length(b).div_ceil(self.lookup_bits) * self.lookup_bits;
        self._range_check(a, range_bits);
        self.check_less_than(a, R::from_fr(Fr::from(b)), range_bits);
    }

    fn check_big_less_than_safe(&self, a: R, b: BigUint) {
        let range_bits = (b.bits() as usize).div_ceil(self.lookup_bits) * self.lookup_bits;
        self._range_check(a, range_bits);
        self.check_less_than(a, R::from_fr(biguint_to_fe(&b)), range_bits);
    }

    fn is_less_than(&self, a: R, b: R, num_bits: usize) -> R {
        let k = num_bits.div_ceil(self.lookup_bits);
        let padded_bits = k * self.lookup_bits;
        assert!(padded_bits + self.lookup_bits <= 253);
        let pow_padded = R::from_fr(self.gate.pow_of_two[padded_bits]);
        let shift_a_val = R::add(pow_padded, a);
        let shifted_val = R::sub(shift_a_val, b);
        let last_limb = self._range_check(shifted_val, padded_bits + self.lookup_bits);
        self.gate.is_zero(last_limb)
    }

    fn is_less_than_safe(&self, a: R, b: u64) -> R {
        let range_bits = bit_length(b).div_ceil(self.lookup_bits) * self.lookup_bits;
        self._range_check(a, range_bits);
        self.is_less_than(a, R::from_fr(Fr::from(b)), range_bits)
    }

    fn is_big_less_than_safe(&self, a: R, b: BigUint) -> R {
        let range_bits = (b.bits() as usize).div_ceil(self.lookup_bits) * self.lookup_bits;
        self._range_check(a, range_bits);
        self.is_less_than(a, R::from_fr(biguint_to_fe(&b)), range_bits)
    }

    fn div_mod(&self, a: R, b: BigUint, a_num_bits: usize) -> (R, R) {
        let fr = R::resolve(a);
        let a_val = fe_to_biguint(&fr);
        let (div, rem) = a_val.div_mod_floor(&b);
        let div_r: R = R::from_fr(biguint_to_fe(&div));
        let rem_r: R = R::from_fr(biguint_to_fe(&rem));
        self.check_big_less_than_safe(
            div_r,
            (BigUint::from(1u32) << a_num_bits) / &b + BigUint::from(1u32),
        );
        self.check_big_less_than_safe(rem_r, b);
        (div_r, rem_r)
    }
}
