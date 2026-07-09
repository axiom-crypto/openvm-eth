//! Minimal wire representation for arithmetic-only tracegen.
//!
//! `Wire` replaces `BabyBearWire { value: AssignedValue<Fr>, max_bits: usize }`
//! from `openvm-static-verifier`. Since no advice buffer or context cell is
//! ever populated, we store just the raw Fr value and the max_bits tag needed
//! for lazy-reduction bookkeeping.

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

/// A single BabyBear-domain value emulated inside BN254 Fr.
///
/// Invariant: `|value| < 2^max_bits` (signed).
#[derive(Copy, Clone, Debug)]
pub struct Wire {
    pub value: Fr,
    pub max_bits: u32,
}

impl Wire {
    #[inline]
    pub const fn new(value: Fr, max_bits: u32) -> Self {
        Self { value, max_bits }
    }
}

/// A quartic BabyBear extension value, one Wire per coefficient.
#[derive(Copy, Clone, Debug)]
pub struct ExtWire(pub [Wire; 4]);

/// A BN254 digest node — same shape as `AssignedValue<Fr>` in the original,
/// but here it's just an Fr since there's nothing to assign.
pub type DigestWire = Fr;

/// Type-level canonicality tag. Zero runtime cost — same layout as `Wire`.
#[derive(Copy, Clone, Debug)]
pub struct ReducedWire(pub Wire);

impl From<ReducedWire> for Wire {
    #[inline]
    fn from(w: ReducedWire) -> Self {
        w.0
    }
}

impl From<&ReducedWire> for Wire {
    #[inline]
    fn from(w: &ReducedWire) -> Self {
        w.0
    }
}

impl ReducedWire {
    #[inline]
    pub fn value(&self) -> Fr {
        self.0.value
    }
}

/// Extension-field analogue of `ReducedWire`.
#[derive(Copy, Clone, Debug)]
pub struct ReducedExtWire(pub [ReducedWire; 4]);

impl From<ReducedExtWire> for ExtWire {
    #[inline]
    fn from(w: ReducedExtWire) -> Self {
        ExtWire(w.0.map(Wire::from))
    }
}

impl From<&ReducedExtWire> for ExtWire {
    #[inline]
    fn from(w: &ReducedExtWire) -> Self {
        ExtWire(w.0.map(Wire::from))
    }
}

impl ReducedExtWire {
    #[inline]
    pub fn coeffs(&self) -> &[ReducedWire; 4] {
        &self.0
    }
}
