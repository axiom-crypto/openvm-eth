//! Arithmetic-only BabyBear-in-Fr chip.
//!
//! Direct port of `openvm/crates/static-verifier/src/field/baby_bear/base.rs`
//! with `AssignedValue<Fr>` → `Fr`. Wire = (Fr, max_bits). All Fr and BigUint
//! arithmetic (including `signed_div_mod`, range-check limb decomposition,
//! BabyBear inversion for `div`) is preserved. Assertions become no-ops.

use std::{cell::RefCell, collections::HashMap, sync::Arc};

use halo2_base::{
    halo2_proofs::halo2curves::bn256::Fr,
    utils::{bigint_to_fe, biguint_to_fe, fe_to_bigint},
};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use openvm_stark_sdk::{
    openvm_stark_backend::p3_field::{Field, PrimeCharacteristicRing, PrimeField64},
    p3_baby_bear::BabyBear,
};

use super::gate::GateChip;
use super::range::RangeChip;
use super::{BabyBearExt, RangeExt};
use crate::wire::{ReducedWire, Wire};

pub(crate) const BABY_BEAR_MODULUS_U64: u64 = 0x78000001;
pub(crate) const BABYBEAR_MAX_BITS: u32 = 31;
const RESERVED_HIGH_BITS: u32 = 2;
const FR_CAPACITY: u32 = 253;

fn bit_length_u64(x: u64) -> u32 {
    if x == 0 {
        0
    } else {
        64 - x.leading_zeros()
    }
}

pub(crate) fn wire_to_baby_bear(w: Wire) -> BabyBear {
    let b_int = fe_to_bigint(&w.value);
    let m = BigInt::from(BABY_BEAR_MODULUS_U64);
    let mut r = b_int % &m;
    if r < BigInt::from(0) {
        r += &m;
    }
    BabyBear::from_u32(r.try_into().unwrap())
}

#[derive(Clone, Debug)]
pub struct BabyBearChip {
    pub range: Arc<RangeChip>,
    const_cache: RefCell<HashMap<u64, Wire>>,
}

impl BabyBearChip {
    pub fn new(range: Arc<RangeChip>) -> Self {
        Self {
            range,
            const_cache: RefCell::new(HashMap::new()),
        }
    }

    #[inline]
    pub fn gate_ref(&self) -> &GateChip {
        self.range.gate()
    }

    /// Constrains that `|a| < 2^a_num_bits`, returns `(div, rem)` such that
    /// `a = p * div + rem` (`0 <= rem < p`). Mirrors the halo2-lib
    /// `signed_div_mod` used by `BabyBearChip::reduce`.
    fn signed_div_mod(&self, a: Fr, a_num_bits: u32) -> (Fr, Fr) {
        assert!(a_num_bits <= FR_CAPACITY - RESERVED_HIGH_BITS);
        let b = BigUint::from(BABY_BEAR_MODULUS_U64);
        let b_int = BigInt::from(b.clone());
        let a_val = fe_to_bigint(&a);
        let (div, rem) = a_val.div_mod_floor(&b_int);
        let div_val: Fr = bigint_to_fe(&div);
        let rem_val: Fr = biguint_to_fe(&rem.to_biguint().unwrap());
        // Same arithmetic as the original: shifted_div = div + bound, then
        // range_check on padded length. Emit the Fr adds and the range_check
        // limb decomposition + inner product.
        let bound = ((BigUint::from(1u32) << a_num_bits) - 1u32).div_ceil(&b);
        let shifted_div = div_val + biguint_to_fe::<Fr>(&bound);
        let range_bits = ((&bound * 2u32 + 1u32).bits()) as usize;
        self.range.range_check(shifted_div, range_bits);
        self.range.check_big_less_than_safe(rem_val, b);
        (div_val, rem_val)
    }
}

impl BabyBearExt for BabyBearChip {
    type Range = RangeChip;

    fn range(&self) -> &RangeChip {
        &self.range
    }

    fn load_witness(&self, value: BabyBear) -> Wire {
        let fr_val = Fr::from(PrimeField64::as_canonical_u64(&value));
        self.range.range_check(fr_val, BABYBEAR_MAX_BITS as usize);
        Wire::new(fr_val, BABYBEAR_MAX_BITS)
    }

    fn load_reduced_witness(&self, value: BabyBear) -> ReducedWire {
        let fr_val = Fr::from(PrimeField64::as_canonical_u64(&value));
        self.range.check_less_than_safe(fr_val, BABY_BEAR_MODULUS_U64);
        ReducedWire(Wire::new(fr_val, BABYBEAR_MAX_BITS))
    }

    fn load_constant(&self, value: BabyBear) -> Wire {
        let key = value.as_canonical_u64();
        if let Some(&cached) = self.const_cache.borrow().get(&key) {
            return cached;
        }
        let max_bits = bit_length_u64(key);
        let wire = Wire::new(Fr::from(key), max_bits);
        self.const_cache.borrow_mut().insert(key, wire);
        wire
    }

    fn load_reduced_constant(&self, value: BabyBear) -> ReducedWire {
        ReducedWire(self.load_constant(value))
    }

    fn reduce(&self, a: Wire) -> Wire {
        assert!(a.max_bits <= FR_CAPACITY - RESERVED_HIGH_BITS);
        let (_, r) = self.signed_div_mod(a.value, a.max_bits);
        Wire::new(r, BABYBEAR_MAX_BITS)
    }

    fn reduce_max_bits(&self, a: Wire) -> Wire {
        if a.max_bits > BABYBEAR_MAX_BITS {
            self.reduce(a)
        } else {
            a
        }
    }

    fn add(&self, mut a: Wire, mut b: Wire) -> Wire {
        if a.max_bits + 1 > FR_CAPACITY - RESERVED_HIGH_BITS {
            a = self.reduce(a);
        }
        if b.max_bits + 1 > FR_CAPACITY - RESERVED_HIGH_BITS {
            b = self.reduce(b);
        }
        let value = self.gate_ref().add(a.value, b.value);
        let max_bits = a.max_bits.max(b.max_bits) + 1;
        Wire::new(value, max_bits)
    }

    fn neg(&self, a: Wire) -> Wire {
        Wire::new(self.gate_ref().neg(a.value), a.max_bits)
    }

    fn sub(&self, mut a: Wire, mut b: Wire) -> Wire {
        if a.max_bits + 1 > FR_CAPACITY - RESERVED_HIGH_BITS {
            a = self.reduce(a);
        }
        if b.max_bits + 1 > FR_CAPACITY - RESERVED_HIGH_BITS {
            b = self.reduce(b);
        }
        let value = self.gate_ref().sub(a.value, b.value);
        Wire::new(value, a.max_bits.max(b.max_bits) + 1)
    }

    fn mul(&self, mut a: Wire, mut b: Wire) -> Wire {
        if a.max_bits < b.max_bits {
            std::mem::swap(&mut a, &mut b);
        }
        if a.max_bits + b.max_bits > FR_CAPACITY - RESERVED_HIGH_BITS {
            a = self.reduce(a);
            if a.max_bits + b.max_bits > FR_CAPACITY - RESERVED_HIGH_BITS {
                b = self.reduce(b);
            }
        }
        let value = self.gate_ref().mul(a.value, b.value);
        Wire::new(value, a.max_bits + b.max_bits)
    }

    fn mul_add(&self, mut a: Wire, mut b: Wire, mut c: Wire) -> Wire {
        if a.max_bits < b.max_bits {
            std::mem::swap(&mut a, &mut b);
        }
        if a.max_bits + b.max_bits + 1 > FR_CAPACITY - RESERVED_HIGH_BITS {
            a = self.reduce(a);
            if a.max_bits + b.max_bits + 1 > FR_CAPACITY - RESERVED_HIGH_BITS {
                b = self.reduce(b);
            }
        }
        if c.max_bits + 1 > FR_CAPACITY - RESERVED_HIGH_BITS {
            c = self.reduce(c);
        }
        let value = self.gate_ref().mul_add(a.value, b.value, c.value);
        let max_bits = c.max_bits.max(a.max_bits + b.max_bits) + 1;
        Wire::new(value, max_bits)
    }

    fn div(&self, mut a: Wire, mut b: Wire) -> Wire {
        let b_val = wire_to_baby_bear(b);
        let b_inv_val = b_val.try_inverse().unwrap();
        let b_inv = self.load_witness(b_inv_val);
        let one = self.load_constant(BabyBear::ONE);
        let inv_prod = self.mul(b, b_inv);
        self.assert_equal(inv_prod, one);

        let mut c = self.load_witness(wire_to_baby_bear(a) * b_inv_val);
        if a.max_bits + 1 > FR_CAPACITY - RESERVED_HIGH_BITS {
            a = self.reduce(a);
        }
        if b.max_bits + c.max_bits + 1 > FR_CAPACITY - RESERVED_HIGH_BITS {
            b = self.reduce(b);
        }
        if b.max_bits + c.max_bits + 1 > FR_CAPACITY - RESERVED_HIGH_BITS {
            c = self.reduce(c);
        }
        let diff = self.gate_ref().sub_mul(a.value, b.value, c.value);
        let max_bits = a.max_bits.max(b.max_bits + c.max_bits) + 1;
        self.assert_zero(Wire::new(diff, max_bits));
        c
    }

    fn special_inner_product(&self, a: &mut [Wire], b: &mut [Wire], s: usize) -> Wire {
        assert!(a.len() == b.len());
        assert!(a.len() == 4);
        let mut max_bits: u32 = 0;
        let lb = s.saturating_sub(3);
        let ub = 4.min(s + 1);
        let range = lb..ub;
        let other_range = (s + 1 - ub)..(s + 1 - lb);
        let len = if s < 3 { s + 1 } else { 7 - s };
        for (i, (c, d)) in a[range.clone()]
            .iter_mut()
            .zip(b[other_range.clone()].iter_mut().rev())
            .enumerate()
        {
            let cap = FR_CAPACITY - RESERVED_HIGH_BITS - (len as u32) + (i as u32);
            if c.max_bits + d.max_bits > cap {
                if c.max_bits >= d.max_bits {
                    *c = self.reduce(*c);
                    if c.max_bits + d.max_bits > cap {
                        *d = self.reduce(*d);
                    }
                } else {
                    *d = self.reduce(*d);
                    if c.max_bits + d.max_bits > cap {
                        *c = self.reduce(*c);
                    }
                }
            }
            if i == 0 {
                max_bits = c.max_bits + d.max_bits;
            } else {
                max_bits = max_bits.max(c.max_bits + d.max_bits) + 1;
            }
        }
        // Compute the actual inner product Σ a[i]*b[i] over the sliced ranges.
        let mut acc = Fr::from(0u64);
        for (av, bv) in a[range].iter().zip(b[other_range].iter().rev()) {
            acc = self.gate_ref().mul_add(av.value, bv.value, acc);
        }
        Wire::new(acc, max_bits)
    }

    fn select(&self, cond: Fr, a: Wire, b: Wire) -> Wire {
        let value = self.gate_ref().select(a.value, b.value, cond);
        Wire::new(value, a.max_bits.max(b.max_bits))
    }

    fn assert_zero(&self, _a: Wire) {
        // No-op: constraint-only in arithonly.
    }

    fn assert_equal(&self, _a: Wire, _b: Wire) {
        // No-op: constraint-only in arithonly.
    }

    fn zero(&self) -> Wire {
        self.load_constant(BabyBear::ZERO)
    }

    fn one(&self) -> Wire {
        self.load_constant(BabyBear::ONE)
    }

    fn mul_const(&self, a: Wire, c: BabyBear) -> Wire {
        let c_wire = self.load_constant(c);
        self.mul(a, c_wire)
    }

    fn square(&self, a: Wire) -> Wire {
        self.mul(a, a)
    }

    fn pow_power_of_two(&self, a: Wire, n: usize) -> Wire {
        let mut r = a;
        for _ in 0..n {
            r = self.square(r);
        }
        r
    }
}
