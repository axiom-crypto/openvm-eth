//! Wire representation, generic over the backend `B`.

use crate::backend::Backend;

/// A single BabyBear-domain value emulated inside BN254 Fr.
///
/// Invariant: the underlying field value is a signed integer with `|value| < 2^max_bits`.
#[derive(Copy, Clone, Debug)]
pub struct Wire<B: Backend> {
    pub value: B::V,
    pub max_bits: u32,
}

impl<B: Backend> Wire<B> {
    #[inline]
    pub const fn new(value: B::V, max_bits: u32) -> Self {
        Self { value, max_bits }
    }
}

/// Quartic BabyBear-extension wire — one `Wire<B>` per coefficient.
#[derive(Copy, Clone, Debug)]
pub struct ExtWire<B: Backend>(pub [Wire<B>; 4]);

/// Type-level canonicality tag.
#[derive(Copy, Clone, Debug)]
pub struct ReducedWire<B: Backend>(pub Wire<B>);

impl<B: Backend> From<ReducedWire<B>> for Wire<B> {
    #[inline]
    fn from(w: ReducedWire<B>) -> Self {
        w.0
    }
}

impl<B: Backend> From<&ReducedWire<B>> for Wire<B> {
    #[inline]
    fn from(w: &ReducedWire<B>) -> Self {
        w.0
    }
}

impl<B: Backend> ReducedWire<B> {
    #[inline]
    pub fn value(&self) -> B::V {
        self.0.value
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ReducedExtWire<B: Backend>(pub [ReducedWire<B>; 4]);

impl<B: Backend> From<ReducedExtWire<B>> for ExtWire<B> {
    #[inline]
    fn from(w: ReducedExtWire<B>) -> Self {
        ExtWire(w.0.map(Wire::from))
    }
}

impl<B: Backend> From<&ReducedExtWire<B>> for ExtWire<B> {
    #[inline]
    fn from(w: &ReducedExtWire<B>) -> Self {
        ExtWire(w.0.map(Wire::from))
    }
}

impl<B: Backend> ReducedExtWire<B> {
    #[inline]
    pub fn coeffs(&self) -> &[ReducedWire<B>; 4] {
        &self.0
    }
}
