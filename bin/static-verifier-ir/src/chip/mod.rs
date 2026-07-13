//! Backend-generic chips. Chips are shared structs (not per-backend traits)
//! so every backend emits the exact same op/slot stream.

use openvm_stark_sdk::p3_baby_bear::BabyBear;

pub mod baby_bear;
pub mod baby_bear_ext;
pub mod gate;
pub mod range;

pub use baby_bear::BabyBearChip;
pub use baby_bear_ext::BabyBearExt4Chip;
pub use range::RangeChip;

pub type BabyBearExt4 =
    openvm_stark_sdk::openvm_stark_backend::p3_field::extension::BinomialExtensionField<
        BabyBear,
        4,
    >;
