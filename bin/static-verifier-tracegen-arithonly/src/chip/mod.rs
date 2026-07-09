//! Chip traits for the arithmetic-only static verifier.
//!
//! Three traits parallel the concrete `BabyBearExtChip` / `BabyBearChip` /
//! `RangeChip<Fr>` triangle in `openvm-static-verifier`, but wires are the
//! concrete `Wire` / `ExtWire` types from `crate::wire` (no `AssignedValue`).
//!
//! The tracegen entry point takes `&impl BabyBearExtInst`.

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use num_bigint::BigUint;
use openvm_stark_sdk::p3_baby_bear::BabyBear;

use crate::wire::{ExtWire, ReducedExtWire, ReducedWire, Wire};

pub mod baby_bear;
pub mod baby_bear_ext;
pub mod gate;
pub mod range;

pub use baby_bear::BabyBearChip;
pub use baby_bear_ext::BabyBearExt4Chip;
pub use gate::GateChip;
pub use range::RangeChip;

pub type BabyBearExt4 = openvm_stark_sdk::openvm_stark_backend::p3_field::extension::BinomialExtensionField<BabyBear, 4>;

/// Range-check + integer-division primitives.
pub trait RangeExt {
    fn gate(&self) -> &GateChip;
    fn lookup_bits(&self) -> usize;

    /// Emits the limb-decomposition + inner-product reconstruction arithmetic
    /// that the halo2-lib RangeChip would emit (per the user's decision).
    fn range_check(&self, a: Fr, range_bits: usize);

    fn check_less_than(&self, a: Fr, b: Fr, num_bits: usize);
    fn check_less_than_safe(&self, a: Fr, b: u64);
    fn check_big_less_than_safe(&self, a: Fr, b: BigUint);

    fn is_less_than(&self, a: Fr, b: Fr, num_bits: usize) -> Fr;
    fn is_less_than_safe(&self, a: Fr, b: u64) -> Fr;
    fn is_big_less_than_safe(&self, a: Fr, b: BigUint) -> Fr;

    /// BigUint-based integer division. Returns (div, rem) as Fr witnesses.
    fn div_mod(&self, a: Fr, b: BigUint, a_num_bits: usize) -> (Fr, Fr);
}

/// BabyBear-in-Fr arithmetic (base field).
pub trait BabyBearExt {
    type Range: RangeExt;

    fn range(&self) -> &Self::Range;

    #[inline]
    fn gate(&self) -> &GateChip {
        self.range().gate()
    }

    // Loading.
    fn load_witness(&self, value: BabyBear) -> Wire;
    fn load_reduced_witness(&self, value: BabyBear) -> ReducedWire;
    fn load_constant(&self, value: BabyBear) -> Wire;
    fn load_reduced_constant(&self, value: BabyBear) -> ReducedWire;

    // Arithmetic.
    fn add(&self, a: Wire, b: Wire) -> Wire;
    fn sub(&self, a: Wire, b: Wire) -> Wire;
    fn mul(&self, a: Wire, b: Wire) -> Wire;
    fn mul_add(&self, a: Wire, b: Wire, c: Wire) -> Wire;
    fn div(&self, a: Wire, b: Wire) -> Wire;
    fn neg(&self, a: Wire) -> Wire;

    // Reduction bookkeeping.
    fn reduce(&self, a: Wire) -> Wire;
    fn reduce_max_bits(&self, a: Wire) -> Wire;

    // Extension-mul helper.
    fn special_inner_product(&self, a: &mut [Wire], b: &mut [Wire], s: usize) -> Wire;

    // Constants and shortcuts.
    fn zero(&self) -> Wire;
    fn one(&self) -> Wire;
    fn mul_const(&self, a: Wire, c: BabyBear) -> Wire;
    fn square(&self, a: Wire) -> Wire;
    fn pow_power_of_two(&self, a: Wire, n: usize) -> Wire;

    // Assertions — no-op in arithonly (constraints are dropped).
    fn assert_zero(&self, a: Wire);
    fn assert_equal(&self, a: Wire, b: Wire);

    fn select(&self, cond: Fr, a: Wire, b: Wire) -> Wire;
}

/// Quartic-extension BabyBear-in-Fr arithmetic.
pub trait BabyBearExtInst {
    type Base: BabyBearExt;

    fn base(&self) -> &Self::Base;

    #[inline]
    fn range(&self) -> &<Self::Base as BabyBearExt>::Range {
        self.base().range()
    }

    // Loading.
    fn load_witness(&self, value: BabyBearExt4) -> ExtWire;
    fn load_reduced_witness(&self, value: BabyBearExt4) -> ReducedExtWire;
    fn load_constant(&self, value: BabyBearExt4) -> ExtWire;
    fn load_reduced_constant(&self, value: BabyBearExt4) -> ReducedExtWire;

    // Arithmetic.
    fn add(&self, a: ExtWire, b: ExtWire) -> ExtWire;
    fn sub(&self, a: ExtWire, b: ExtWire) -> ExtWire;
    fn mul(&self, a: ExtWire, b: ExtWire) -> ExtWire;
    fn div(&self, a: ExtWire, b: ExtWire) -> ExtWire;
    fn neg(&self, a: ExtWire) -> ExtWire;
    fn square(&self, a: ExtWire) -> ExtWire;
    fn scalar_mul(&self, a: ExtWire, b: Wire) -> ExtWire;
    fn scalar_mul_add(&self, a: ExtWire, b: Wire, c: ExtWire) -> ExtWire;
    fn mul_base_const(&self, a: ExtWire, c: BabyBear) -> ExtWire;
    fn reduce_max_bits(&self, a: ExtWire) -> ExtWire;

    fn zero(&self) -> ExtWire;
    fn from_base_const(&self, value: BabyBear) -> ExtWire;
    fn from_base_var(&self, value: Wire) -> ExtWire;
    fn select(&self, cond: Fr, a: ExtWire, b: ExtWire) -> ExtWire;
    fn pow_power_of_two(&self, a: ExtWire, n: usize) -> ExtWire;

    // Assertions — no-op.
    fn assert_zero(&self, a: ExtWire);
    fn assert_equal(&self, a: ExtWire, b: ExtWire);
}
