//! Op-emitter backend trait.
//!
//! Every op appends its output(s) to an implicit witness stream, one slot per
//! output, in program order. The eager backend computes concrete `Fr` values
//! and pushes them; IR backends allocate slot ids and record instructions.
//! Because all chips are shared generic code, the slot streams of every
//! backend line up index-for-index by construction.

use std::fmt::Debug;

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

/// Backends are ZSTs; all state lives in `Ctx`.
pub trait Backend: Copy + Clone + Debug + Sized + 'static {
    const NAME: &'static str;

    /// Wire value: concrete `Fr` (eager) or a `u32` witness-slot id (IR).
    type V: Copy + Debug + 'static;
    type Ctx;

    /// Proof-derived value (changes between proofs). Emits 1 slot.
    fn input(ctx: &mut Self::Ctx, value: Fr) -> Self::V;

    /// Static constant (vk digests, powers of two, round constants, ...).
    /// Deduplicated in `Ctx`; emits 1 slot on first sight, 0 afterwards.
    fn constant(ctx: &mut Self::Ctx, value: Fr) -> Self::V;

    // ---- pure Fr arithmetic (1 output slot each) ----

    fn add(ctx: &mut Self::Ctx, a: Self::V, b: Self::V) -> Self::V;
    fn sub(ctx: &mut Self::Ctx, a: Self::V, b: Self::V) -> Self::V;
    fn mul(ctx: &mut Self::Ctx, a: Self::V, b: Self::V) -> Self::V;
    fn neg(ctx: &mut Self::Ctx, a: Self::V) -> Self::V;
    /// `a * b + c`
    fn mul_add(ctx: &mut Self::Ctx, a: Self::V, b: Self::V, c: Self::V) -> Self::V;
    /// `a - b * c`
    fn sub_mul(ctx: &mut Self::Ctx, a: Self::V, b: Self::V, c: Self::V) -> Self::V;
    /// `sel ? a : b` = `(a - b) * sel + b`
    fn select(ctx: &mut Self::Ctx, a: Self::V, b: Self::V, sel: Self::V) -> Self::V;

    // ---- hint ops (multi-output; fixed slot order) ----

    /// Slots: `[inv_or_zero, indicator]`. `indicator = (a == 0)`,
    /// `inv_or_zero = a^{-1}` if `a != 0` else `0`.
    fn is_zero(ctx: &mut Self::Ctx, a: Self::V) -> (Self::V, Self::V);

    /// Floor divmod of the canonical integer of `a` by `divisor`.
    /// Slots: `[quot, rem]`.
    fn div_mod_u32(ctx: &mut Self::Ctx, a: Self::V, divisor: u32) -> (Self::V, Self::V);

    /// Little-endian base-`2^limb_bits` limbs of the canonical integer of `a`.
    /// Slots: limbs LSB-first. `limb_bits = 1` covers `num_to_bits`.
    fn decompose(ctx: &mut Self::Ctx, a: Self::V, num_limbs: u32, limb_bits: u32) -> Vec<Self::V>;

    /// Base-p digit decomposition of the canonical integer of `packed`:
    /// `packed = d0 + d1*p + ... + d4*p^4 + q*p^5`. Slots: `[d0..d4, q]`.
    fn bn_to_bb_digits(ctx: &mut Self::Ctx, packed: Self::V) -> ([Self::V; 5], Self::V);

    // ---- atomic Poseidon2 permutations (T output slots) ----

    fn poseidon2_t3(ctx: &mut Self::Ctx, state: [Self::V; 3]) -> [Self::V; 3];
    fn poseidon2_t2(ctx: &mut Self::Ctx, state: [Self::V; 2]) -> [Self::V; 2];

    // ---- assertions: no slots, default no-ops ----

    #[inline]
    fn assert_zero(_ctx: &mut Self::Ctx, _a: Self::V) {}
    #[inline]
    fn assert_equal(_ctx: &mut Self::Ctx, _a: Self::V, _b: Self::V) {}
    #[inline]
    fn assert_is_const(_ctx: &mut Self::Ctx, _a: Self::V, _c: &Fr) {}
}

/// Atomic BabyBear instructions. Values are lazily-reduced residues held in
/// `Fr` slots; the *chips* own the `max_bits` bookkeeping and call
/// [`BabyBearInst::bb_reduce`] on any input that needs reduction before
/// emitting an op.
pub trait BabyBearInst: Backend {
    fn bb_add(ctx: &mut Self::Ctx, a: Self::V, b: Self::V) -> Self::V;
    fn bb_sub(ctx: &mut Self::Ctx, a: Self::V, b: Self::V) -> Self::V;
    fn bb_neg(ctx: &mut Self::Ctx, a: Self::V) -> Self::V;
    fn bb_mul(ctx: &mut Self::Ctx, a: Self::V, b: Self::V) -> Self::V;
    /// `a * b + c`
    fn bb_mul_add(ctx: &mut Self::Ctx, a: Self::V, b: Self::V, c: Self::V) -> Self::V;
    /// Reduce the signed representative of `a` into canonical `[0, p)`.
    /// 1 slot.
    fn bb_reduce(ctx: &mut Self::Ctx, a: Self::V) -> Self::V;
    /// `(a mod p) * (b mod p)^{-1}` in BabyBear. 1 slot, canonical.
    fn bb_div(ctx: &mut Self::Ctx, a: Self::V, b: Self::V) -> Self::V;
}

/// Atomic BabyBear quartic-extension instructions. Coefficient slot order is
/// always 0..4.
pub trait BabyBearExt4Inst: BabyBearInst {
    fn ext4_add(ctx: &mut Self::Ctx, a: [Self::V; 4], b: [Self::V; 4]) -> [Self::V; 4];
    fn ext4_sub(ctx: &mut Self::Ctx, a: [Self::V; 4], b: [Self::V; 4]) -> [Self::V; 4];
    fn ext4_neg(ctx: &mut Self::Ctx, a: [Self::V; 4]) -> [Self::V; 4];
    /// Coefficient-wise `a * b` for base-field `b`.
    fn ext4_scalar_mul(ctx: &mut Self::Ctx, a: [Self::V; 4], b: Self::V) -> [Self::V; 4];
    /// Coefficient-wise `a * b + c` for base-field `b`.
    fn ext4_scalar_mul_add(
        ctx: &mut Self::Ctx,
        a: [Self::V; 4],
        b: Self::V,
        c: [Self::V; 4],
    ) -> [Self::V; 4];
    /// Binomial-extension product (x^4 = W).
    fn ext4_mul(ctx: &mut Self::Ctx, a: [Self::V; 4], b: [Self::V; 4]) -> [Self::V; 4];
    /// Coefficient-wise reduction into canonical `[0, p)`. 4 slots.
    fn ext4_reduce(ctx: &mut Self::Ctx, a: [Self::V; 4]) -> [Self::V; 4];
    /// Quartic-extension `a / b`. Slots: coeffs 0..4, canonical.
    fn ext4_div(ctx: &mut Self::Ctx, a: [Self::V; 4], b: [Self::V; 4]) -> [Self::V; 4];
}
