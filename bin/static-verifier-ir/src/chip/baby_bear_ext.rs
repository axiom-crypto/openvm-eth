//! Backend-generic `BabyBearExt4Chip<B>`: `max_bits` bookkeeping over atomic
//! [`BabyBearExt4Inst`] ops, inserting `ext4_reduce`/`bb_reduce` on inputs
//! that would overflow the tracked capacity.

use core::array;

use openvm_stark_sdk::{
    openvm_stark_backend::p3_field::{BasedVectorSpace, PrimeCharacteristicRing},
    p3_baby_bear::BabyBear,
};

use super::{
    baby_bear::{BabyBearChip, BABYBEAR_MAX_BITS, MAX_BITS_CAP},
    range::RangeChip,
    BabyBearExt4,
};
use crate::{
    backend::BabyBearExt4Inst,
    wire::{ExtWire, ReducedExtWire, Wire},
};

/// Headroom of an `Ext4Mul` output over `a_bits + b_bits`: W-scaled terms add
/// 31 bits, accumulating the ≤7 products adds 3 more.
const EXT4_MUL_OVERHEAD: u32 = 34;

#[derive(Clone, Debug)]
pub struct BabyBearExt4Chip<B: BabyBearExt4Inst> {
    pub base: BabyBearChip<B>,
}

impl<B: BabyBearExt4Inst> BabyBearExt4Chip<B> {
    pub fn new(base: BabyBearChip<B>) -> Self {
        Self { base }
    }

    #[inline]
    pub fn base(&self) -> &BabyBearChip<B> {
        &self.base
    }

    #[inline]
    pub fn range(&self) -> &RangeChip<B> {
        self.base.range()
    }

    #[inline]
    fn vals(a: &ExtWire<B>) -> [B::V; 4] {
        array::from_fn(|i| a.0[i].value)
    }

    #[inline]
    fn max_coeff_bits(a: &ExtWire<B>) -> u32 {
        a.0.iter().map(|w| w.max_bits).max().unwrap()
    }

    pub fn load_witness(&self, ctx: &mut B::Ctx, value: BabyBearExt4) -> ExtWire<B> {
        let coeffs = value.as_basis_coefficients_slice();
        ExtWire(array::from_fn(|i| self.base.load_witness(ctx, coeffs[i])))
    }
    pub fn load_reduced_witness(&self, ctx: &mut B::Ctx, value: BabyBearExt4) -> ReducedExtWire<B> {
        let coeffs = value.as_basis_coefficients_slice();
        ReducedExtWire(array::from_fn(|i| self.base.load_reduced_witness(ctx, coeffs[i])))
    }
    pub fn load_constant(&self, ctx: &mut B::Ctx, value: BabyBearExt4) -> ExtWire<B> {
        let coeffs = value.as_basis_coefficients_slice();
        ExtWire(array::from_fn(|i| self.base.load_constant(ctx, coeffs[i])))
    }
    pub fn load_reduced_constant(
        &self,
        ctx: &mut B::Ctx,
        value: BabyBearExt4,
    ) -> ReducedExtWire<B> {
        let coeffs = value.as_basis_coefficients_slice();
        ReducedExtWire(array::from_fn(|i| self.base.load_reduced_constant(ctx, coeffs[i])))
    }

    /// Atomic coefficient-wise reduction into canonical `[0, p)`.
    pub fn reduce(&self, ctx: &mut B::Ctx, a: ExtWire<B>) -> ExtWire<B> {
        assert!(Self::max_coeff_bits(&a) <= MAX_BITS_CAP);
        let out = B::ext4_reduce(ctx, Self::vals(&a));
        ExtWire(out.map(|v| Wire::new(v, BABYBEAR_MAX_BITS)))
    }

    pub fn reduce_max_bits(&self, ctx: &mut B::Ctx, a: ExtWire<B>) -> ExtWire<B> {
        if Self::max_coeff_bits(&a) > BABYBEAR_MAX_BITS {
            self.reduce(ctx, a)
        } else {
            a
        }
    }

    pub fn add(&self, ctx: &mut B::Ctx, mut a: ExtWire<B>, mut b: ExtWire<B>) -> ExtWire<B> {
        if Self::max_coeff_bits(&a) + 1 > MAX_BITS_CAP {
            a = self.reduce(ctx, a);
        }
        if Self::max_coeff_bits(&b) + 1 > MAX_BITS_CAP {
            b = self.reduce(ctx, b);
        }
        let out = B::ext4_add(ctx, Self::vals(&a), Self::vals(&b));
        ExtWire(array::from_fn(|i| Wire::new(out[i], a.0[i].max_bits.max(b.0[i].max_bits) + 1)))
    }

    pub fn sub(&self, ctx: &mut B::Ctx, mut a: ExtWire<B>, mut b: ExtWire<B>) -> ExtWire<B> {
        if Self::max_coeff_bits(&a) + 1 > MAX_BITS_CAP {
            a = self.reduce(ctx, a);
        }
        if Self::max_coeff_bits(&b) + 1 > MAX_BITS_CAP {
            b = self.reduce(ctx, b);
        }
        let out = B::ext4_sub(ctx, Self::vals(&a), Self::vals(&b));
        ExtWire(array::from_fn(|i| Wire::new(out[i], a.0[i].max_bits.max(b.0[i].max_bits) + 1)))
    }

    pub fn neg(&self, ctx: &mut B::Ctx, a: ExtWire<B>) -> ExtWire<B> {
        let out = B::ext4_neg(ctx, Self::vals(&a));
        ExtWire(array::from_fn(|i| Wire::new(out[i], a.0[i].max_bits)))
    }

    pub fn scalar_mul(&self, ctx: &mut B::Ctx, mut a: ExtWire<B>, mut b: Wire<B>) -> ExtWire<B> {
        if Self::max_coeff_bits(&a) + b.max_bits > MAX_BITS_CAP {
            a = self.reduce(ctx, a);
            if Self::max_coeff_bits(&a) + b.max_bits > MAX_BITS_CAP {
                b = self.base.reduce(ctx, b);
            }
        }
        let out = B::ext4_scalar_mul(ctx, Self::vals(&a), b.value);
        ExtWire(array::from_fn(|i| Wire::new(out[i], a.0[i].max_bits + b.max_bits)))
    }

    pub fn scalar_mul_add(
        &self,
        ctx: &mut B::Ctx,
        mut a: ExtWire<B>,
        mut b: Wire<B>,
        mut c: ExtWire<B>,
    ) -> ExtWire<B> {
        if Self::max_coeff_bits(&a) + b.max_bits + 1 > MAX_BITS_CAP {
            a = self.reduce(ctx, a);
            if Self::max_coeff_bits(&a) + b.max_bits + 1 > MAX_BITS_CAP {
                b = self.base.reduce(ctx, b);
            }
        }
        if Self::max_coeff_bits(&c) + 1 > MAX_BITS_CAP {
            c = self.reduce(ctx, c);
        }
        let out = B::ext4_scalar_mul_add(ctx, Self::vals(&a), b.value, Self::vals(&c));
        ExtWire(array::from_fn(|i| {
            Wire::new(out[i], c.0[i].max_bits.max(a.0[i].max_bits + b.max_bits) + 1)
        }))
    }

    pub fn mul(&self, ctx: &mut B::Ctx, mut a: ExtWire<B>, mut b: ExtWire<B>) -> ExtWire<B> {
        if Self::max_coeff_bits(&a) + Self::max_coeff_bits(&b) + EXT4_MUL_OVERHEAD > MAX_BITS_CAP {
            a = self.reduce(ctx, a);
            if Self::max_coeff_bits(&a) + Self::max_coeff_bits(&b) + EXT4_MUL_OVERHEAD >
                MAX_BITS_CAP
            {
                b = self.reduce(ctx, b);
            }
        }
        let max_bits = Self::max_coeff_bits(&a) + Self::max_coeff_bits(&b) + EXT4_MUL_OVERHEAD;
        let out = B::ext4_mul(ctx, Self::vals(&a), Self::vals(&b));
        ExtWire(out.map(|v| Wire::new(v, max_bits)))
    }

    /// Atomic division; the hint reduces via signed representatives, so
    /// unreduced inputs are fine.
    pub fn div(&self, ctx: &mut B::Ctx, a: ExtWire<B>, b: ExtWire<B>) -> ExtWire<B> {
        let out = B::ext4_div(ctx, Self::vals(&a), Self::vals(&b));
        ExtWire(out.map(|v| Wire::new(v, BABYBEAR_MAX_BITS)))
    }

    pub fn select(&self, ctx: &mut B::Ctx, cond: B::V, a: ExtWire<B>, b: ExtWire<B>) -> ExtWire<B> {
        ExtWire(array::from_fn(|i| self.base.select(ctx, cond, a.0[i], b.0[i])))
    }

    pub fn assert_zero(&self, ctx: &mut B::Ctx, a: ExtWire<B>) {
        for x in a.0.iter() {
            self.base.assert_zero(ctx, *x);
        }
    }

    pub fn assert_equal(&self, ctx: &mut B::Ctx, a: ExtWire<B>, b: ExtWire<B>) {
        for (x, y) in a.0.iter().zip(b.0.iter()) {
            self.base.assert_equal(ctx, *x, *y);
        }
    }

    pub fn zero(&self, ctx: &mut B::Ctx) -> ExtWire<B> {
        self.from_base_const(ctx, BabyBear::ZERO)
    }

    pub fn from_base_const(&self, ctx: &mut B::Ctx, value: BabyBear) -> ExtWire<B> {
        let base_val = self.base.load_constant(ctx, value);
        let z = self.base.load_constant(ctx, BabyBear::ZERO);
        ExtWire([base_val, z, z, z])
    }

    pub fn from_base_var(&self, ctx: &mut B::Ctx, value: Wire<B>) -> ExtWire<B> {
        let z = self.base.load_constant(ctx, BabyBear::ZERO);
        ExtWire([value, z, z, z])
    }

    pub fn mul_base_const(&self, ctx: &mut B::Ctx, a: ExtWire<B>, c: BabyBear) -> ExtWire<B> {
        let c_wire = self.base.load_constant(ctx, c);
        self.scalar_mul(ctx, a, c_wire)
    }

    pub fn square(&self, ctx: &mut B::Ctx, a: ExtWire<B>) -> ExtWire<B> {
        self.mul(ctx, a, a)
    }

    pub fn pow_power_of_two(&self, ctx: &mut B::Ctx, a: ExtWire<B>, n: usize) -> ExtWire<B> {
        let mut r = a;
        for _ in 0..n {
            r = self.square(ctx, r);
        }
        r
    }
}
