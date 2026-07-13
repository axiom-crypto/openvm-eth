//! Backend-generic `GateChip<B>`.

use std::marker::PhantomData;

use halo2_base::halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};

use crate::backend::Backend;

#[derive(Clone, Debug)]
pub struct GateChip<B: Backend> {
    /// Precomputed `2^i` for `i in 0..254`, as plain `Fr`; lifted to values via
    /// `B::constant` at use site.
    pub pow_of_two: Vec<Fr>,
    _marker: PhantomData<B>,
}

impl<B: Backend> Default for GateChip<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: Backend> GateChip<B> {
    pub fn new() -> Self {
        let num_bits = 254usize;
        let mut pow_of_two = Vec::with_capacity(num_bits);
        let two = Fr::from(2u64);
        pow_of_two.push(Fr::ONE);
        pow_of_two.push(two);
        for _ in 2..num_bits {
            let last = *pow_of_two.last().unwrap();
            pow_of_two.push(two * last);
        }
        Self { pow_of_two, _marker: PhantomData }
    }

    #[inline]
    pub fn constant(&self, ctx: &mut B::Ctx, value: Fr) -> B::V {
        B::constant(ctx, value)
    }

    #[inline]
    pub fn zero(&self, ctx: &mut B::Ctx) -> B::V {
        B::constant(ctx, Fr::ZERO)
    }

    #[inline]
    pub fn one(&self, ctx: &mut B::Ctx) -> B::V {
        B::constant(ctx, Fr::ONE)
    }

    // ---- arithmetic ----

    #[inline]
    pub fn add(&self, ctx: &mut B::Ctx, a: B::V, b: B::V) -> B::V {
        B::add(ctx, a, b)
    }

    #[inline]
    pub fn sub(&self, ctx: &mut B::Ctx, a: B::V, b: B::V) -> B::V {
        B::sub(ctx, a, b)
    }

    #[inline]
    pub fn neg(&self, ctx: &mut B::Ctx, a: B::V) -> B::V {
        B::neg(ctx, a)
    }

    #[inline]
    pub fn mul(&self, ctx: &mut B::Ctx, a: B::V, b: B::V) -> B::V {
        B::mul(ctx, a, b)
    }

    /// `a * b + c`
    #[inline]
    pub fn mul_add(&self, ctx: &mut B::Ctx, a: B::V, b: B::V, c: B::V) -> B::V {
        B::mul_add(ctx, a, b, c)
    }

    /// `a - b * c`
    #[inline]
    pub fn sub_mul(&self, ctx: &mut B::Ctx, a: B::V, b: B::V, c: B::V) -> B::V {
        B::sub_mul(ctx, a, b, c)
    }

    /// `(1 - a) * b`
    #[inline]
    pub fn mul_not(&self, ctx: &mut B::Ctx, a: B::V, b: B::V) -> B::V {
        let one = self.one(ctx);
        let not_a = B::sub(ctx, one, a);
        B::mul(ctx, not_a, b)
    }

    pub fn sum<I: IntoIterator<Item = B::V>>(&self, ctx: &mut B::Ctx, iter: I) -> B::V {
        let zero = self.zero(ctx);
        iter.into_iter().fold(zero, |acc, x| B::add(ctx, acc, x))
    }

    pub fn inner_product<I, J>(&self, ctx: &mut B::Ctx, a: I, b: J) -> B::V
    where
        I: IntoIterator<Item = B::V>,
        J: IntoIterator<Item = B::V>,
    {
        let zero = self.zero(ctx);
        a.into_iter().zip(b).fold(zero, |acc, (ai, bi)| B::mul_add(ctx, ai, bi, acc))
    }

    // ---- boolean and selection ----

    /// `1 if a == 0 else 0`. Also emits the inverse-witness slot.
    #[inline]
    pub fn is_zero(&self, ctx: &mut B::Ctx, a: B::V) -> B::V {
        B::is_zero(ctx, a).1
    }

    #[inline]
    pub fn is_equal(&self, ctx: &mut B::Ctx, a: B::V, b: B::V) -> B::V {
        let diff = B::sub(ctx, a, b);
        self.is_zero(ctx, diff)
    }

    #[inline]
    pub fn not(&self, ctx: &mut B::Ctx, a: B::V) -> B::V {
        let one = self.one(ctx);
        B::sub(ctx, one, a)
    }

    #[inline]
    pub fn and(&self, ctx: &mut B::Ctx, a: B::V, b: B::V) -> B::V {
        B::mul(ctx, a, b)
    }

    /// `sel ? a : b`
    #[inline]
    pub fn select(&self, ctx: &mut B::Ctx, a: B::V, b: B::V, sel: B::V) -> B::V {
        B::select(ctx, a, b, sel)
    }

    // ---- bits ----

    pub fn num_to_bits(&self, ctx: &mut B::Ctx, a: B::V, range_bits: usize) -> Vec<B::V> {
        debug_assert!(range_bits > 0);
        B::decompose(ctx, a, range_bits as u32, 1)
    }

    // ---- assertions ----

    #[inline]
    pub fn assert_bit(&self, _ctx: &mut B::Ctx, _x: B::V) {}

    #[inline]
    pub fn assert_is_const(&self, ctx: &mut B::Ctx, a: B::V, constant: &Fr) {
        B::assert_is_const(ctx, a, constant);
    }
}
