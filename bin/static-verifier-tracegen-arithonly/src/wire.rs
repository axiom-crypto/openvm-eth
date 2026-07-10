//! Wire representation, generic over the field-element repr `R`.

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

use crate::repr::FieldRepr;

/// A single BabyBear-domain value emulated inside BN254 Fr (or a fraction repr).
///
/// Invariant: the underlying field value is a signed integer with `|value| < 2^max_bits`.
#[derive(Copy, Clone, Debug)]
pub struct Wire<R: FieldRepr> {
    pub value: R,
    pub max_bits: u32,
}

impl<R: FieldRepr> Wire<R> {
    #[inline]
    pub const fn new(value: R, max_bits: u32) -> Self {
        Self { value, max_bits }
    }
}

/// Quartic BabyBear-extension wire — one `Wire<R>` per coefficient.
#[derive(Copy, Clone, Debug)]
pub struct ExtWire<R: FieldRepr>(pub [Wire<R>; 4]);

/// Digest node from a proof (always concrete Fr — not affected by repr).
pub type DigestWire = Fr;

/// Type-level canonicality tag.
#[derive(Copy, Clone, Debug)]
pub struct ReducedWire<R: FieldRepr>(pub Wire<R>);

impl<R: FieldRepr> From<ReducedWire<R>> for Wire<R> {
    #[inline]
    fn from(w: ReducedWire<R>) -> Self {
        w.0
    }
}

impl<R: FieldRepr> From<&ReducedWire<R>> for Wire<R> {
    #[inline]
    fn from(w: &ReducedWire<R>) -> Self {
        w.0
    }
}

impl<R: FieldRepr> ReducedWire<R> {
    #[inline]
    pub fn value(&self) -> R {
        self.0.value
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ReducedExtWire<R: FieldRepr>(pub [ReducedWire<R>; 4]);

impl<R: FieldRepr> From<ReducedExtWire<R>> for ExtWire<R> {
    #[inline]
    fn from(w: ReducedExtWire<R>) -> Self {
        ExtWire(w.0.map(Wire::from))
    }
}

impl<R: FieldRepr> From<&ReducedExtWire<R>> for ExtWire<R> {
    #[inline]
    fn from(w: &ReducedExtWire<R>) -> Self {
        ExtWire(w.0.map(Wire::from))
    }
}

impl<R: FieldRepr> ReducedExtWire<R> {
    #[inline]
    pub fn coeffs(&self) -> &[ReducedWire<R>; 4] {
        &self.0
    }
}
