//! Backend-generic `BabyBearChip<B>`: `max_bits` lazy-reduction bookkeeping
//! over atomic [`BabyBearInst`] ops. Any input that would overflow the
//! tracked capacity gets an explicit `bb_reduce` op first.

use std::sync::Arc;

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use openvm_stark_sdk::{
    openvm_stark_backend::p3_field::{PrimeCharacteristicRing, PrimeField64},
    p3_baby_bear::BabyBear,
};

use super::{gate::GateChip, range::RangeChip};
use crate::{
    backend::{BabyBearInst, Backend},
    wire::{ReducedWire, Wire},
};

pub(crate) const BABY_BEAR_MODULUS_U64: u64 = 0x78000001;
pub(crate) const BABYBEAR_MAX_BITS: u32 = 31;
pub(crate) const RESERVED_HIGH_BITS: u32 = 2;
pub(crate) const FR_CAPACITY: u32 = 253;
/// Largest tracked magnitude an op input/output may have.
pub(crate) const MAX_BITS_CAP: u32 = FR_CAPACITY - RESERVED_HIGH_BITS;

fn bit_length_u64(x: u64) -> u32 {
    if x == 0 {
        0
    } else {
        64 - x.leading_zeros()
    }
}

#[derive(Clone, Debug)]
pub struct BabyBearChip<B: Backend> {
    pub range: Arc<RangeChip<B>>,
}

impl<B: Backend> BabyBearChip<B> {
    pub fn new(range: Arc<RangeChip<B>>) -> Self {
        Self { range }
    }

    #[inline]
    pub fn range(&self) -> &RangeChip<B> {
        &self.range
    }

    #[inline]
    pub fn gate(&self) -> &GateChip<B> {
        self.range.gate()
    }
}

impl<B: BabyBearInst> BabyBearChip<B> {
    pub fn load_witness(&self, ctx: &mut B::Ctx, value: BabyBear) -> Wire<B> {
        let fr_val = Fr::from(PrimeField64::as_canonical_u64(&value));
        Wire::new(B::input(ctx, fr_val), BABYBEAR_MAX_BITS)
    }

    pub fn load_reduced_witness(&self, ctx: &mut B::Ctx, value: BabyBear) -> ReducedWire<B> {
        ReducedWire(self.load_witness(ctx, value))
    }

    pub fn load_constant(&self, ctx: &mut B::Ctx, value: BabyBear) -> Wire<B> {
        let key = value.as_canonical_u64();
        let max_bits = bit_length_u64(key);
        Wire::new(B::constant(ctx, Fr::from(key)), max_bits)
    }

    pub fn load_reduced_constant(&self, ctx: &mut B::Ctx, value: BabyBear) -> ReducedWire<B> {
        ReducedWire(self.load_constant(ctx, value))
    }

    pub fn reduce(&self, ctx: &mut B::Ctx, a: Wire<B>) -> Wire<B> {
        assert!(a.max_bits <= MAX_BITS_CAP);
        Wire::new(B::bb_reduce(ctx, a.value), BABYBEAR_MAX_BITS)
    }

    pub fn reduce_max_bits(&self, ctx: &mut B::Ctx, a: Wire<B>) -> Wire<B> {
        if a.max_bits > BABYBEAR_MAX_BITS {
            self.reduce(ctx, a)
        } else {
            a
        }
    }

    pub fn add(&self, ctx: &mut B::Ctx, mut a: Wire<B>, mut b: Wire<B>) -> Wire<B> {
        if a.max_bits + 1 > MAX_BITS_CAP {
            a = self.reduce(ctx, a);
        }
        if b.max_bits + 1 > MAX_BITS_CAP {
            b = self.reduce(ctx, b);
        }
        Wire::new(B::bb_add(ctx, a.value, b.value), a.max_bits.max(b.max_bits) + 1)
    }

    pub fn neg(&self, ctx: &mut B::Ctx, a: Wire<B>) -> Wire<B> {
        Wire::new(B::bb_neg(ctx, a.value), a.max_bits)
    }

    pub fn sub(&self, ctx: &mut B::Ctx, mut a: Wire<B>, mut b: Wire<B>) -> Wire<B> {
        if a.max_bits + 1 > MAX_BITS_CAP {
            a = self.reduce(ctx, a);
        }
        if b.max_bits + 1 > MAX_BITS_CAP {
            b = self.reduce(ctx, b);
        }
        Wire::new(B::bb_sub(ctx, a.value, b.value), a.max_bits.max(b.max_bits) + 1)
    }

    pub fn mul(&self, ctx: &mut B::Ctx, mut a: Wire<B>, mut b: Wire<B>) -> Wire<B> {
        if a.max_bits < b.max_bits {
            std::mem::swap(&mut a, &mut b);
        }
        if a.max_bits + b.max_bits > MAX_BITS_CAP {
            a = self.reduce(ctx, a);
            if a.max_bits + b.max_bits > MAX_BITS_CAP {
                b = self.reduce(ctx, b);
            }
        }
        Wire::new(B::bb_mul(ctx, a.value, b.value), a.max_bits + b.max_bits)
    }

    pub fn mul_add(
        &self,
        ctx: &mut B::Ctx,
        mut a: Wire<B>,
        mut b: Wire<B>,
        mut c: Wire<B>,
    ) -> Wire<B> {
        if a.max_bits < b.max_bits {
            std::mem::swap(&mut a, &mut b);
        }
        if a.max_bits + b.max_bits + 1 > MAX_BITS_CAP {
            a = self.reduce(ctx, a);
            if a.max_bits + b.max_bits + 1 > MAX_BITS_CAP {
                b = self.reduce(ctx, b);
            }
        }
        if c.max_bits + 1 > MAX_BITS_CAP {
            c = self.reduce(ctx, c);
        }
        let value = B::bb_mul_add(ctx, a.value, b.value, c.value);
        let max_bits = c.max_bits.max(a.max_bits + b.max_bits) + 1;
        Wire::new(value, max_bits)
    }

    /// Atomic division in BabyBear; the hint reduces via the signed
    /// representative, so unreduced inputs are fine.
    pub fn div(&self, ctx: &mut B::Ctx, a: Wire<B>, b: Wire<B>) -> Wire<B> {
        Wire::new(B::bb_div(ctx, a.value, b.value), BABYBEAR_MAX_BITS)
    }

    pub fn select(&self, ctx: &mut B::Ctx, cond: B::V, a: Wire<B>, b: Wire<B>) -> Wire<B> {
        let value = B::select(ctx, a.value, b.value, cond);
        Wire::new(value, a.max_bits.max(b.max_bits))
    }

    pub fn assert_zero(&self, ctx: &mut B::Ctx, a: Wire<B>) {
        B::assert_zero(ctx, a.value);
    }

    pub fn assert_equal(&self, ctx: &mut B::Ctx, a: Wire<B>, b: Wire<B>) {
        B::assert_equal(ctx, a.value, b.value);
    }

    pub fn zero(&self, ctx: &mut B::Ctx) -> Wire<B> {
        self.load_constant(ctx, BabyBear::ZERO)
    }

    pub fn one(&self, ctx: &mut B::Ctx) -> Wire<B> {
        self.load_constant(ctx, BabyBear::ONE)
    }

    pub fn mul_const(&self, ctx: &mut B::Ctx, a: Wire<B>, c: BabyBear) -> Wire<B> {
        let c_wire = self.load_constant(ctx, c);
        self.mul(ctx, a, c_wire)
    }

    pub fn square(&self, ctx: &mut B::Ctx, a: Wire<B>) -> Wire<B> {
        self.mul(ctx, a, a)
    }

    pub fn pow_power_of_two(&self, ctx: &mut B::Ctx, a: Wire<B>, n: usize) -> Wire<B> {
        let mut r = a;
        for _ in 0..n {
            r = self.square(ctx, r);
        }
        r
    }
}
