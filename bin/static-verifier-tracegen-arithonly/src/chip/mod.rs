//! Chip traits for the arithmetic-only static verifier.
//!
//! All traits carry an associated `R: FieldRepr` so the same code compiles
//! against both `FrRepr` (eager Fr inversion in `is_zero`) and `FractionRepr`
//! (Assigned<Fr>-style deferred inversion).

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use num_bigint::BigUint;
use openvm_stark_sdk::p3_baby_bear::BabyBear;

use crate::repr::FieldRepr;
use crate::wire::{ExtWire, ReducedExtWire, ReducedWire, Wire};

pub mod baby_bear;
pub mod baby_bear_ext;
pub mod gate;
pub mod range;

pub use baby_bear::BabyBearChip;
pub use baby_bear_ext::BabyBearExt4Chip;
pub use gate::GateChip;
pub use range::RangeChip;

pub type BabyBearExt4 =
    openvm_stark_sdk::openvm_stark_backend::p3_field::extension::BinomialExtensionField<BabyBear, 4>;

/// Range-check + integer-division primitives.
pub trait RangeExt {
    type R: FieldRepr;

    fn gate(&self) -> &GateChip<Self::R>;
    fn lookup_bits(&self) -> usize;

    /// Emits the limb-decomposition + inner-product reconstruction that the
    /// halo2-lib RangeChip would emit.
    fn range_check(&self, a: Self::R, range_bits: usize);
    fn check_less_than(&self, a: Self::R, b: Self::R, num_bits: usize);
    fn check_less_than_safe(&self, a: Self::R, b: u64);
    fn check_big_less_than_safe(&self, a: Self::R, b: BigUint);
    fn is_less_than(&self, a: Self::R, b: Self::R, num_bits: usize) -> Self::R;
    fn is_less_than_safe(&self, a: Self::R, b: u64) -> Self::R;
    fn is_big_less_than_safe(&self, a: Self::R, b: BigUint) -> Self::R;
    fn div_mod(&self, a: Self::R, b: BigUint, a_num_bits: usize) -> (Self::R, Self::R);
}

/// BabyBear-in-Fr arithmetic.
pub trait BabyBearExt {
    type R: FieldRepr;
    type Range: RangeExt<R = Self::R>;

    fn range(&self) -> &Self::Range;

    #[inline]
    fn gate(&self) -> &GateChip<Self::R> {
        self.range().gate()
    }

    fn load_witness(&self, value: BabyBear) -> Wire<Self::R>;
    fn load_reduced_witness(&self, value: BabyBear) -> ReducedWire<Self::R>;
    fn load_constant(&self, value: BabyBear) -> Wire<Self::R>;
    fn load_reduced_constant(&self, value: BabyBear) -> ReducedWire<Self::R>;

    fn add(&self, a: Wire<Self::R>, b: Wire<Self::R>) -> Wire<Self::R>;
    fn sub(&self, a: Wire<Self::R>, b: Wire<Self::R>) -> Wire<Self::R>;
    fn mul(&self, a: Wire<Self::R>, b: Wire<Self::R>) -> Wire<Self::R>;
    fn mul_add(&self, a: Wire<Self::R>, b: Wire<Self::R>, c: Wire<Self::R>) -> Wire<Self::R>;
    fn div(&self, a: Wire<Self::R>, b: Wire<Self::R>) -> Wire<Self::R>;
    fn neg(&self, a: Wire<Self::R>) -> Wire<Self::R>;

    fn reduce(&self, a: Wire<Self::R>) -> Wire<Self::R>;
    fn reduce_max_bits(&self, a: Wire<Self::R>) -> Wire<Self::R>;

    fn special_inner_product(
        &self,
        a: &mut [Wire<Self::R>],
        b: &mut [Wire<Self::R>],
        s: usize,
    ) -> Wire<Self::R>;

    fn zero(&self) -> Wire<Self::R>;
    fn one(&self) -> Wire<Self::R>;
    fn mul_const(&self, a: Wire<Self::R>, c: BabyBear) -> Wire<Self::R>;
    fn square(&self, a: Wire<Self::R>) -> Wire<Self::R>;
    fn pow_power_of_two(&self, a: Wire<Self::R>, n: usize) -> Wire<Self::R>;

    fn assert_zero(&self, a: Wire<Self::R>);
    fn assert_equal(&self, a: Wire<Self::R>, b: Wire<Self::R>);

    fn select(&self, cond: Self::R, a: Wire<Self::R>, b: Wire<Self::R>) -> Wire<Self::R>;
}

/// Quartic-extension chip.
pub trait BabyBearExtInst {
    type R: FieldRepr;
    type Base: BabyBearExt<R = Self::R>;

    fn base(&self) -> &Self::Base;

    #[inline]
    fn range(&self) -> &<Self::Base as BabyBearExt>::Range {
        self.base().range()
    }

    fn load_witness(&self, value: BabyBearExt4) -> ExtWire<Self::R>;
    fn load_reduced_witness(&self, value: BabyBearExt4) -> ReducedExtWire<Self::R>;
    fn load_constant(&self, value: BabyBearExt4) -> ExtWire<Self::R>;
    fn load_reduced_constant(&self, value: BabyBearExt4) -> ReducedExtWire<Self::R>;

    fn add(&self, a: ExtWire<Self::R>, b: ExtWire<Self::R>) -> ExtWire<Self::R>;
    fn sub(&self, a: ExtWire<Self::R>, b: ExtWire<Self::R>) -> ExtWire<Self::R>;
    fn mul(&self, a: ExtWire<Self::R>, b: ExtWire<Self::R>) -> ExtWire<Self::R>;
    fn div(&self, a: ExtWire<Self::R>, b: ExtWire<Self::R>) -> ExtWire<Self::R>;
    fn neg(&self, a: ExtWire<Self::R>) -> ExtWire<Self::R>;
    fn square(&self, a: ExtWire<Self::R>) -> ExtWire<Self::R>;
    fn scalar_mul(&self, a: ExtWire<Self::R>, b: Wire<Self::R>) -> ExtWire<Self::R>;
    fn scalar_mul_add(
        &self,
        a: ExtWire<Self::R>,
        b: Wire<Self::R>,
        c: ExtWire<Self::R>,
    ) -> ExtWire<Self::R>;
    fn mul_base_const(&self, a: ExtWire<Self::R>, c: BabyBear) -> ExtWire<Self::R>;
    fn reduce_max_bits(&self, a: ExtWire<Self::R>) -> ExtWire<Self::R>;

    fn zero(&self) -> ExtWire<Self::R>;
    fn from_base_const(&self, value: BabyBear) -> ExtWire<Self::R>;
    fn from_base_var(&self, value: Wire<Self::R>) -> ExtWire<Self::R>;
    fn select(&self, cond: Self::R, a: ExtWire<Self::R>, b: ExtWire<Self::R>) -> ExtWire<Self::R>;
    fn pow_power_of_two(&self, a: ExtWire<Self::R>, n: usize) -> ExtWire<Self::R>;

    fn assert_zero(&self, a: ExtWire<Self::R>);
    fn assert_equal(&self, a: ExtWire<Self::R>, b: ExtWire<Self::R>);
}

/// Convenience: `Fr` re-exported so downstream files can `use crate::chip::Fr`.
pub use halo2_base::halo2_proofs::halo2curves::bn256::Fr as HFr;
#[allow(dead_code)]
pub(crate) fn _fr_unused(_: Fr) {}
