//! Arithmetic-only BabyBear-quartic-extension-in-Fr chip.
//!
//! Direct port of `openvm/crates/static-verifier/src/field/baby_bear/extension.rs`.
//! Extension is `x^4 - W` for `W = BabyBear::W`. The mul routine reproduces the
//! 7-inner-product + 3-mul_add w-reduction scheme + per-limb reduce_max_bits.

use core::array;

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use openvm_stark_sdk::{
    openvm_stark_backend::p3_field::{
        extension::{BinomialExtensionField, BinomiallyExtendable},
        BasedVectorSpace, Field, PrimeCharacteristicRing,
    },
    p3_baby_bear::BabyBear,
};

use super::baby_bear::BabyBearChip;
use super::{BabyBearExt, BabyBearExt4, BabyBearExtInst};
use crate::wire::{ExtWire, ReducedExtWire, ReducedWire, Wire};

fn wire_to_ext(w: ExtWire) -> BabyBearExt4 {
    BabyBearExt4::from_basis_coefficients_fn(|i| super::baby_bear::wire_to_baby_bear(w.0[i]))
}

#[derive(Clone, Debug)]
pub struct BabyBearExt4Chip {
    pub base: BabyBearChip,
}

impl BabyBearExt4Chip {
    pub fn new(base: BabyBearChip) -> Self {
        Self { base }
    }
}

impl BabyBearExtInst for BabyBearExt4Chip {
    type Base = BabyBearChip;

    fn base(&self) -> &BabyBearChip {
        &self.base
    }

    fn load_witness(&self, value: BabyBearExt4) -> ExtWire {
        let coeffs = value.as_basis_coefficients_slice();
        ExtWire(array::from_fn(|i| self.base.load_witness(coeffs[i])))
    }

    fn load_reduced_witness(&self, value: BabyBearExt4) -> ReducedExtWire {
        let coeffs = value.as_basis_coefficients_slice();
        ReducedExtWire(array::from_fn(|i| self.base.load_reduced_witness(coeffs[i])))
    }

    fn load_constant(&self, value: BabyBearExt4) -> ExtWire {
        let coeffs = value.as_basis_coefficients_slice();
        ExtWire(array::from_fn(|i| self.base.load_constant(coeffs[i])))
    }

    fn load_reduced_constant(&self, value: BabyBearExt4) -> ReducedExtWire {
        let coeffs = value.as_basis_coefficients_slice();
        ReducedExtWire(array::from_fn(|i| self.base.load_reduced_constant(coeffs[i])))
    }

    fn add(&self, a: ExtWire, b: ExtWire) -> ExtWire {
        ExtWire(array::from_fn(|i| self.base.add(a.0[i], b.0[i])))
    }

    fn sub(&self, a: ExtWire, b: ExtWire) -> ExtWire {
        ExtWire(array::from_fn(|i| self.base.sub(a.0[i], b.0[i])))
    }

    fn neg(&self, a: ExtWire) -> ExtWire {
        ExtWire(array::from_fn(|i| self.base.neg(a.0[i])))
    }

    fn scalar_mul(&self, a: ExtWire, b: Wire) -> ExtWire {
        ExtWire(array::from_fn(|i| self.base.mul(a.0[i], b)))
    }

    fn scalar_mul_add(&self, a: ExtWire, b: Wire, c: ExtWire) -> ExtWire {
        ExtWire(array::from_fn(|i| self.base.mul_add(a.0[i], b, c.0[i])))
    }

    fn select(&self, cond: Fr, a: ExtWire, b: ExtWire) -> ExtWire {
        ExtWire(array::from_fn(|i| self.base.select(cond, a.0[i], b.0[i])))
    }

    fn assert_zero(&self, a: ExtWire) {
        for x in a.0.iter() {
            self.base.assert_zero(*x);
        }
    }

    fn assert_equal(&self, a: ExtWire, b: ExtWire) {
        for (x, y) in a.0.iter().zip(b.0.iter()) {
            self.base.assert_equal(*x, *y);
        }
    }

    fn mul(&self, mut a: ExtWire, mut b: ExtWire) -> ExtWire {
        let mut coeffs = Vec::with_capacity(7);
        for s in 0..7 {
            coeffs.push(self.base.special_inner_product(&mut a.0, &mut b.0, s));
        }
        let w = self
            .base
            .load_constant(<BabyBear as BinomiallyExtendable<4>>::W);
        for i in 4..7 {
            coeffs[i - 4] = self.base.mul_add(coeffs[i], w, coeffs[i - 4]);
        }
        coeffs.truncate(4);
        ExtWire(coeffs.try_into().unwrap())
    }

    fn div(&self, a: ExtWire, b: ExtWire) -> ExtWire {
        let b_val = wire_to_ext(b);
        let b_inv_val = b_val.try_inverse().unwrap();
        let b_inv = self.load_witness(b_inv_val);
        let one = self.load_constant(BinomialExtensionField::<BabyBear, 4>::ONE);
        let inv_prod = self.mul(b, b_inv);
        self.assert_equal(inv_prod, one);

        let c = self.load_witness(wire_to_ext(a) * b_inv_val);
        let prod = self.mul(b, c);
        self.assert_equal(a, prod);
        c
    }

    fn reduce_max_bits(&self, a: ExtWire) -> ExtWire {
        ExtWire(a.0.map(|x| self.base.reduce_max_bits(x)))
    }

    fn zero(&self) -> ExtWire {
        self.from_base_const(BabyBear::ZERO)
    }

    fn from_base_const(&self, value: BabyBear) -> ExtWire {
        let base_val = self.base.load_constant(value);
        let z = self.base.load_constant(BabyBear::ZERO);
        ExtWire([base_val, z, z, z])
    }

    fn from_base_var(&self, value: Wire) -> ExtWire {
        let z = self.base.load_constant(BabyBear::ZERO);
        ExtWire([value, z, z, z])
    }

    fn mul_base_const(&self, a: ExtWire, c: BabyBear) -> ExtWire {
        let c_wire = self.base.load_constant(c);
        self.scalar_mul(a, c_wire)
    }

    fn square(&self, a: ExtWire) -> ExtWire {
        self.mul(a, a)
    }

    fn pow_power_of_two(&self, a: ExtWire, n: usize) -> ExtWire {
        let mut r = a;
        for _ in 0..n {
            r = self.square(r);
        }
        r
    }
}
