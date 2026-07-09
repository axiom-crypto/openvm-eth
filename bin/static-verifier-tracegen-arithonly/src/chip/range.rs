//! Arithmetic-only re-implementation of `halo2_base::gates::range::RangeChip<Fr>`.
//!
//! `range_check` preserves the limb-decomposition + inner-product reconstruction
//! Fr arithmetic (per user's decision). Everything else that is pure Fr witness
//! generation (BigUint div_mod, shifted-diff constructions for less-than checks)
//! is preserved as well. What we drop is the lookup-row bookkeeping and
//! Assigned/AssignedValue plumbing.

use std::cmp::Ordering;

use halo2_base::{
    halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr},
    utils::{biguint_to_fe, decompose_fe_to_u64_limbs, fe_to_biguint},
};
use num_bigint::BigUint;
use num_integer::Integer;

use super::gate::GateChip;
use super::RangeExt;

fn bit_length(x: u64) -> usize {
    if x == 0 { 0 } else { 64 - x.leading_zeros() as usize }
}

#[derive(Clone, Debug)]
pub struct RangeChip {
    pub gate: GateChip,
    pub lookup_bits: usize,
    /// Precomputed `[1, 2^lookup_bits, 2^{2*lookup_bits}, ...]` up to the
    /// number of limbs that fit in `Fr::CAPACITY`.
    pub limb_bases: Vec<Fr>,
}

impl RangeChip {
    pub fn new(lookup_bits: usize) -> Self {
        let gate = GateChip::new();
        let limb_base = Fr::from(1u64 << lookup_bits);
        let capacity = 253usize; // Fr::CAPACITY
        let num_bases = capacity / lookup_bits;
        let mut running = limb_base;
        let mut limb_bases = Vec::with_capacity(num_bases + 1);
        limb_bases.push(Fr::ONE);
        limb_bases.push(running);
        for _ in 2..=num_bases {
            running *= limb_base;
            limb_bases.push(running);
        }
        Self {
            gate,
            lookup_bits,
            limb_bases,
        }
    }

    /// Emit the arithmetic for a `range_check`. Returns the last limb's value.
    /// Preserves the inner-product reconstruction Fr multiplications, but does
    /// not queue any lookup rows.
    fn _range_check(&self, a: Fr, range_bits: usize) -> Fr {
        if range_bits == 0 {
            return a;
        }
        let num_limbs = range_bits.div_ceil(self.lookup_bits);
        let rem_bits = range_bits % self.lookup_bits;

        let last_limb = if num_limbs == 1 {
            a
        } else {
            let limbs = decompose_fe_to_u64_limbs(&a, num_limbs, self.lookup_bits);
            // Inner product reconstruction: preserves n Fr muls + (n-1) Fr adds
            // exactly like `inner_product_simple` in halo2-lib. (The first limb
            // multiplies by 1, so no mul there; halo2-lib special-cases that,
            // and we do too.)
            let mut acc = Fr::from(limbs[0]);
            for i in 1..num_limbs {
                acc += Fr::from(limbs[i]) * self.limb_bases[i];
            }
            let _ = acc; // acc == a modulo range (arithmetic done, not used).
            Fr::from(limbs[num_limbs - 1])
        };

        match rem_bits.cmp(&1) {
            Ordering::Equal => {
                // assert_bit: constraint-only in the real chip, no Fr mul.
            }
            Ordering::Greater => {
                // The real chip does `mul(last_limb, pow_of_two[lookup_bits - rem_bits])`
                // to align the highest limb. Preserve that Fr mul.
                let mult = self.gate.pow_of_two[self.lookup_bits - rem_bits];
                let _check = self.gate.mul(last_limb, mult);
            }
            Ordering::Less => {}
        }

        last_limb
    }
}

impl RangeExt for RangeChip {
    fn gate(&self) -> &GateChip {
        &self.gate
    }

    fn lookup_bits(&self) -> usize {
        self.lookup_bits
    }

    fn range_check(&self, a: Fr, range_bits: usize) {
        self._range_check(a, range_bits);
    }

    fn check_less_than(&self, a: Fr, b: Fr, num_bits: usize) {
        assert!(num_bits < 253, "num_bits must fit Fr::CAPACITY");
        let pow_of_two = self.gate.pow_of_two[num_bits];
        let shift_a_val = pow_of_two + a;
        let diff_val = shift_a_val - b;
        self._range_check(diff_val, num_bits);
    }

    fn check_less_than_safe(&self, a: Fr, b: u64) {
        let range_bits = bit_length(b).div_ceil(self.lookup_bits) * self.lookup_bits;
        self._range_check(a, range_bits);
        self.check_less_than(a, Fr::from(b), range_bits);
    }

    fn check_big_less_than_safe(&self, a: Fr, b: BigUint) {
        let range_bits = (b.bits() as usize).div_ceil(self.lookup_bits) * self.lookup_bits;
        self._range_check(a, range_bits);
        self.check_less_than(a, biguint_to_fe(&b), range_bits);
    }

    fn is_less_than(&self, a: Fr, b: Fr, num_bits: usize) -> Fr {
        let k = num_bits.div_ceil(self.lookup_bits);
        let padded_bits = k * self.lookup_bits;
        assert!(padded_bits + self.lookup_bits <= 253);
        let pow_padded = self.gate.pow_of_two[padded_bits];
        let shift_a_val = pow_padded + a;
        let shifted_val = shift_a_val - b;
        // Range-check the (padded_bits + lookup_bits)-bit representation to
        // extract the top limb.
        let last_limb = self._range_check(shifted_val, padded_bits + self.lookup_bits);
        self.gate.is_zero(last_limb)
    }

    fn is_less_than_safe(&self, a: Fr, b: u64) -> Fr {
        let range_bits = bit_length(b).div_ceil(self.lookup_bits) * self.lookup_bits;
        self._range_check(a, range_bits);
        self.is_less_than(a, Fr::from(b), range_bits)
    }

    fn is_big_less_than_safe(&self, a: Fr, b: BigUint) -> Fr {
        let range_bits = (b.bits() as usize).div_ceil(self.lookup_bits) * self.lookup_bits;
        self._range_check(a, range_bits);
        self.is_less_than(a, biguint_to_fe(&b), range_bits)
    }

    fn div_mod(&self, a: Fr, b: BigUint, a_num_bits: usize) -> (Fr, Fr) {
        let a_val = fe_to_biguint(&a);
        let (div, rem) = a_val.div_mod_floor(&b);
        let div_fr: Fr = biguint_to_fe(&div);
        let rem_fr: Fr = biguint_to_fe(&rem);
        // Preserve the constraint-time range checks' arithmetic.
        self.check_big_less_than_safe(
            div_fr,
            (BigUint::from(1u32) << a_num_bits) / &b + BigUint::from(1u32),
        );
        self.check_big_less_than_safe(rem_fr, b);
        (div_fr, rem_fr)
    }
}
