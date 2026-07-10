//! Field element representation trait.
//!
//! Two flavors:
//! - [`FrRepr`]: plain BN254 `Fr`. `invert()` calls `Fr::invert()` (expensive
//!   Fermat / binary-GCD path — matches what tracegen would pay if it resolved
//!   every `Assigned::Rational` cell immediately).
//! - [`FractionRepr`]: an enum matching halo2's `Assigned<F>`. `invert()`
//!   swaps numerator and denominator (O(1)); the inversion is *deferred* and
//!   never actually computed in the arithonly path.
//!
//! Wires are `Wire<R>`, chips are `SomeChip<R>`, so the whole pipeline
//! monomorphizes twice — once per repr — and `main.rs` runs both back-to-back.

use std::fmt::Debug;

use halo2_base::halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};

/// Field-like element used for wire values. All chip arithmetic goes through
/// this trait.
pub trait FieldRepr: Copy + Clone + Debug + Send + Sync + 'static {
    /// Short name used in log output.
    const NAME: &'static str;

    fn zero() -> Self;
    fn one() -> Self;
    fn from_fr(fr: Fr) -> Self;

    fn add(a: Self, b: Self) -> Self;
    fn sub(a: Self, b: Self) -> Self;
    fn mul(a: Self, b: Self) -> Self;
    fn neg(a: Self) -> Self;

    /// Multiplicative inverse. For `FrRepr` this is a real `Fr::invert()`; for
    /// `FractionRepr` it constructs the deferred `Rational` cell.
    fn invert(a: Self) -> Self;

    /// Resolve to a plain `Fr`. `FractionRepr` may need to invert the
    /// denominator here — used for boundary conversions (BigUint reductions).
    fn resolve(a: Self) -> Fr;

    /// True iff the represented value equals zero in the field.
    fn is_field_zero(a: Self) -> bool;
}

// ---------------------------------------------------------------------------
// FrRepr: plain Fr, eager inversion.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct FrRepr(pub Fr);

impl FieldRepr for FrRepr {
    const NAME: &'static str = "fr";

    #[inline]
    fn zero() -> Self {
        Self(Fr::ZERO)
    }
    #[inline]
    fn one() -> Self {
        Self(Fr::ONE)
    }
    #[inline]
    fn from_fr(fr: Fr) -> Self {
        Self(fr)
    }
    #[inline]
    fn add(a: Self, b: Self) -> Self {
        Self(a.0 + b.0)
    }
    #[inline]
    fn sub(a: Self, b: Self) -> Self {
        Self(a.0 - b.0)
    }
    #[inline]
    fn mul(a: Self, b: Self) -> Self {
        Self(a.0 * b.0)
    }
    #[inline]
    fn neg(a: Self) -> Self {
        Self(-a.0)
    }
    #[inline]
    fn invert(a: Self) -> Self {
        // Real Fr inversion via Fermat / binary-GCD.
        Self(a.0.invert().unwrap())
    }
    #[inline]
    fn resolve(a: Self) -> Fr {
        a.0
    }
    #[inline]
    fn is_field_zero(a: Self) -> bool {
        a.0 == Fr::ZERO
    }
}

// ---------------------------------------------------------------------------
// FractionRepr: (num, denom), deferred inversion.
// ---------------------------------------------------------------------------

/// Mirrors halo2's `plonk::Assigned<F>`.
#[derive(Copy, Clone, Debug)]
pub enum FractionRepr {
    Zero,
    Trivial(Fr),
    Rational(Fr, Fr),
}

impl FieldRepr for FractionRepr {
    const NAME: &'static str = "fraction";

    #[inline]
    fn zero() -> Self {
        Self::Zero
    }
    #[inline]
    fn one() -> Self {
        Self::Trivial(Fr::ONE)
    }
    #[inline]
    fn from_fr(fr: Fr) -> Self {
        if fr == Fr::ZERO {
            Self::Zero
        } else {
            Self::Trivial(fr)
        }
    }

    fn add(a: Self, b: Self) -> Self {
        use FractionRepr::*;
        match (a, b) {
            (Zero, x) | (x, Zero) => x,
            (Trivial(x), Trivial(y)) => Trivial(x + y),
            (Trivial(x), Rational(n, d)) | (Rational(n, d), Trivial(x)) => Rational(n + x * d, d),
            (Rational(n1, d1), Rational(n2, d2)) => Rational(n1 * d2 + n2 * d1, d1 * d2),
        }
    }

    #[inline]
    fn sub(a: Self, b: Self) -> Self {
        Self::add(a, Self::neg(b))
    }

    fn mul(a: Self, b: Self) -> Self {
        use FractionRepr::*;
        match (a, b) {
            (Zero, _) | (_, Zero) => Zero,
            (Trivial(x), Trivial(y)) => Trivial(x * y),
            (Trivial(x), Rational(n, d)) | (Rational(n, d), Trivial(x)) => Rational(x * n, d),
            (Rational(n1, d1), Rational(n2, d2)) => Rational(n1 * n2, d1 * d2),
        }
    }

    fn neg(a: Self) -> Self {
        use FractionRepr::*;
        match a {
            Zero => Zero,
            Trivial(x) => Trivial(-x),
            Rational(n, d) => Rational(-n, d),
        }
    }

    fn invert(a: Self) -> Self {
        use FractionRepr::*;
        match a {
            Zero => panic!("cannot invert zero"),
            // Deferred: no `Fr::invert()` here — just represent as 1/x.
            Trivial(x) => Rational(Fr::ONE, x),
            Rational(n, d) => Rational(d, n),
        }
    }

    fn resolve(a: Self) -> Fr {
        use FractionRepr::*;
        match a {
            Zero => Fr::ZERO,
            Trivial(x) => x,
            // At the boundary we must materialize the inversion.
            Rational(n, d) => n * d.invert().unwrap(),
        }
    }

    #[inline]
    fn is_field_zero(a: Self) -> bool {
        use FractionRepr::*;
        match a {
            Zero => true,
            Trivial(x) => x == Fr::ZERO,
            // A non-zero denominator can never wrap the fraction to zero.
            Rational(n, _) => n == Fr::ZERO,
        }
    }
}
