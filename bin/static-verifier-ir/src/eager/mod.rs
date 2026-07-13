//! Eager backend: computes concrete `Fr` values and appends every op output
//! to the witness stream. Performance baseline and equivalence golden.

use std::collections::HashMap;

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

use crate::{
    backend::{BabyBearExt4Inst, BabyBearInst, Backend},
    hints,
};

#[derive(Default)]
pub struct EagerCtx {
    pub witness: Vec<Fr>,
    const_cache: HashMap<[u8; 32], ()>,
}

impl EagerCtx {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct EagerBackend;

#[inline]
fn push(ctx: &mut EagerCtx, v: Fr) -> Fr {
    ctx.witness.push(v);
    v
}

impl Backend for EagerBackend {
    const NAME: &'static str = "eager";

    type V = Fr;
    type Ctx = EagerCtx;

    #[inline]
    fn input(ctx: &mut EagerCtx, value: Fr) -> Fr {
        push(ctx, value)
    }

    #[inline]
    fn constant(ctx: &mut EagerCtx, value: Fr) -> Fr {
        if ctx.const_cache.insert(value.to_bytes(), ()).is_none() {
            ctx.witness.push(value);
        }
        value
    }

    #[inline]
    fn add(ctx: &mut EagerCtx, a: Fr, b: Fr) -> Fr {
        push(ctx, a + b)
    }
    #[inline]
    fn sub(ctx: &mut EagerCtx, a: Fr, b: Fr) -> Fr {
        push(ctx, a - b)
    }
    #[inline]
    fn mul(ctx: &mut EagerCtx, a: Fr, b: Fr) -> Fr {
        push(ctx, a * b)
    }
    #[inline]
    fn neg(ctx: &mut EagerCtx, a: Fr) -> Fr {
        push(ctx, -a)
    }
    #[inline]
    fn mul_add(ctx: &mut EagerCtx, a: Fr, b: Fr, c: Fr) -> Fr {
        push(ctx, a * b + c)
    }
    #[inline]
    fn sub_mul(ctx: &mut EagerCtx, a: Fr, b: Fr, c: Fr) -> Fr {
        push(ctx, a - b * c)
    }
    #[inline]
    fn select(ctx: &mut EagerCtx, a: Fr, b: Fr, sel: Fr) -> Fr {
        push(ctx, (a - b) * sel + b)
    }

    fn is_zero(ctx: &mut EagerCtx, a: Fr) -> (Fr, Fr) {
        let (inv_or_zero, indicator) = hints::is_zero_hint(a);
        (push(ctx, inv_or_zero), push(ctx, indicator))
    }

    fn div_mod_u32(ctx: &mut EagerCtx, a: Fr, divisor: u32) -> (Fr, Fr) {
        let (quot, rem) = hints::div_mod_u32_hint(a, divisor);
        (push(ctx, quot), push(ctx, rem))
    }

    fn decompose(ctx: &mut EagerCtx, a: Fr, num_limbs: u32, limb_bits: u32) -> Vec<Fr> {
        let limbs = hints::decompose_hint(a, num_limbs, limb_bits);
        ctx.witness.extend_from_slice(&limbs);
        limbs
    }

    fn bn_to_bb_digits(ctx: &mut EagerCtx, packed: Fr) -> ([Fr; 5], Fr) {
        let (digits, top_quotient) = hints::bn_to_bb_digits_hint(packed);
        ctx.witness.extend_from_slice(&digits);
        (digits, push(ctx, top_quotient))
    }

    fn poseidon2_t3(ctx: &mut EagerCtx, state: [Fr; 3]) -> [Fr; 3] {
        let out = hints::poseidon2_t3_hint(state);
        ctx.witness.extend_from_slice(&out);
        out
    }

    fn poseidon2_t2(ctx: &mut EagerCtx, state: [Fr; 2]) -> [Fr; 2] {
        let out = hints::poseidon2_t2_hint(state);
        ctx.witness.extend_from_slice(&out);
        out
    }
}

#[inline]
fn push4(ctx: &mut EagerCtx, out: [Fr; 4]) -> [Fr; 4] {
    ctx.witness.extend_from_slice(&out);
    out
}

impl BabyBearInst for EagerBackend {
    #[inline]
    fn bb_add(ctx: &mut EagerCtx, a: Fr, b: Fr) -> Fr {
        push(ctx, a + b)
    }
    #[inline]
    fn bb_sub(ctx: &mut EagerCtx, a: Fr, b: Fr) -> Fr {
        push(ctx, a - b)
    }
    #[inline]
    fn bb_neg(ctx: &mut EagerCtx, a: Fr) -> Fr {
        push(ctx, -a)
    }
    #[inline]
    fn bb_mul(ctx: &mut EagerCtx, a: Fr, b: Fr) -> Fr {
        push(ctx, a * b)
    }
    #[inline]
    fn bb_mul_add(ctx: &mut EagerCtx, a: Fr, b: Fr, c: Fr) -> Fr {
        push(ctx, a * b + c)
    }
    #[inline]
    fn bb_reduce(ctx: &mut EagerCtx, a: Fr) -> Fr {
        push(ctx, hints::bb_reduce_hint(a))
    }
    #[inline]
    fn bb_div(ctx: &mut EagerCtx, a: Fr, b: Fr) -> Fr {
        push(ctx, hints::bb_div_hint(a, b))
    }
}

impl BabyBearExt4Inst for EagerBackend {
    #[inline]
    fn ext4_add(ctx: &mut EagerCtx, a: [Fr; 4], b: [Fr; 4]) -> [Fr; 4] {
        push4(ctx, core::array::from_fn(|i| a[i] + b[i]))
    }
    #[inline]
    fn ext4_sub(ctx: &mut EagerCtx, a: [Fr; 4], b: [Fr; 4]) -> [Fr; 4] {
        push4(ctx, core::array::from_fn(|i| a[i] - b[i]))
    }
    #[inline]
    fn ext4_neg(ctx: &mut EagerCtx, a: [Fr; 4]) -> [Fr; 4] {
        push4(ctx, a.map(|x| -x))
    }
    #[inline]
    fn ext4_scalar_mul(ctx: &mut EagerCtx, a: [Fr; 4], b: Fr) -> [Fr; 4] {
        push4(ctx, a.map(|x| x * b))
    }
    #[inline]
    fn ext4_scalar_mul_add(ctx: &mut EagerCtx, a: [Fr; 4], b: Fr, c: [Fr; 4]) -> [Fr; 4] {
        push4(ctx, core::array::from_fn(|i| a[i] * b + c[i]))
    }
    #[inline]
    fn ext4_mul(ctx: &mut EagerCtx, a: [Fr; 4], b: [Fr; 4]) -> [Fr; 4] {
        push4(ctx, hints::ext4_mul_fr(a, b))
    }
    #[inline]
    fn ext4_reduce(ctx: &mut EagerCtx, a: [Fr; 4]) -> [Fr; 4] {
        push4(ctx, a.map(hints::bb_reduce_hint))
    }
    #[inline]
    fn ext4_div(ctx: &mut EagerCtx, a: [Fr; 4], b: [Fr; 4]) -> [Fr; 4] {
        push4(ctx, hints::ext4_div_hint(a, b))
    }
}
