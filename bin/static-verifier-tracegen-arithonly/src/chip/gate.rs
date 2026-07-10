//! Arithmetic-only `GateChip<R>`.

use std::marker::PhantomData;

use halo2_base::halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};

use crate::repr::FieldRepr;

#[derive(Clone, Debug)]
pub struct GateChip<R: FieldRepr> {
    /// Precomputed `2^i` for `i in 0..254`. Stored as plain `Fr` and lifted to
    /// `R` at use site — these are pure constants and only ever get consumed
    /// as `R::from_fr`.
    pub pow_of_two: Vec<Fr>,
    _marker: PhantomData<R>,
}

impl<R: FieldRepr> Default for GateChip<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: FieldRepr> GateChip<R> {
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
    pub fn pow_of_two(&self) -> &[Fr] {
        &self.pow_of_two
    }

    // ---- arithmetic ----

    #[inline]
    pub fn add(&self, a: R, b: R) -> R {
        R::add(a, b)
    }

    #[inline]
    pub fn sub(&self, a: R, b: R) -> R {
        R::sub(a, b)
    }

    #[inline]
    pub fn neg(&self, a: R) -> R {
        R::neg(a)
    }

    #[inline]
    pub fn mul(&self, a: R, b: R) -> R {
        #[cfg(feature = "coz")]
        coz::scope!("mul");
        R::mul(a, b)
    }

    #[inline]
    pub fn mul_add(&self, a: R, b: R, c: R) -> R {
        R::add(R::mul(a, b), c)
    }

    /// `a - b * c`
    #[inline]
    pub fn sub_mul(&self, a: R, b: R, c: R) -> R {
        R::sub(a, R::mul(b, c))
    }

    #[inline]
    pub fn mul_not(&self, a: R, b: R) -> R {
        // (1 - a) * b
        R::mul(R::sub(R::one(), a), b)
    }

    pub fn sum<I: IntoIterator<Item = R>>(&self, iter: I) -> R {
        iter.into_iter().fold(R::zero(), |acc, x| R::add(acc, x))
    }

    pub fn inner_product<I, J>(&self, a: I, b: J) -> R
    where
        I: IntoIterator<Item = R>,
        J: IntoIterator<Item = R>,
    {
        a.into_iter()
            .zip(b.into_iter())
            .fold(R::zero(), |acc, (ai, bi)| R::add(acc, R::mul(ai, bi)))
    }

    // ---- boolean and selection ----

    /// `1 if a == 0 else 0`. Also computes the "inv witness" that the tracegen
    /// would allocate — for `FrRepr` this is a full `Fr::invert()`; for
    /// `FractionRepr` it's just a `Rational(1, a)` construction. Result is
    /// discarded.
    #[inline]
    pub fn is_zero(&self, a: R) -> R {
        if R::is_field_zero(a) {
            R::one()
        } else {
            // Model the Assigned::Rational(1, a) witness cell. Use black_box
            // so the compiler can't elide the Fr::invert() call in FrRepr.
            let inv_witness = R::invert(a);
            std::hint::black_box(inv_witness);
            R::zero()
        }
    }

    #[inline]
    pub fn is_equal(&self, a: R, b: R) -> R {
        self.is_zero(R::sub(a, b))
    }

    #[inline]
    pub fn not(&self, a: R) -> R {
        R::sub(R::one(), a)
    }

    #[inline]
    pub fn and(&self, a: R, b: R) -> R {
        R::mul(a, b)
    }

    /// `sel ? a : b` = `(a - b) * sel + b`.
    #[inline]
    pub fn select(&self, a: R, b: R, sel: R) -> R {
        R::add(R::mul(R::sub(a, b), sel), b)
    }

    pub fn idx_to_indicator(&self, idx: R, len: usize) -> Vec<R> {
        (0..len)
            .map(|i| {
                if i == 0 {
                    self.is_zero(idx)
                } else {
                    self.is_equal(idx, R::from_fr(Fr::from(i as u64)))
                }
            })
            .collect()
    }

    pub fn select_by_indicator<I: IntoIterator<Item = R>>(
        &self,
        a: I,
        indicator: impl IntoIterator<Item = R>,
    ) -> R {
        let mut sum = R::zero();
        for (ai, ind) in a.into_iter().zip(indicator.into_iter()) {
            if !R::is_field_zero(ind) {
                sum = ai;
            }
        }
        sum
    }

    // ---- bits ----

    pub fn num_to_bits(&self, a: R, range_bits: usize) -> Vec<R> {
        debug_assert!(range_bits > 0);
        // Resolve to Fr for bit extraction (Fraction repr must materialize any
        // pending inversion here — but in practice these values are always
        // Trivial coming from a `sample_bits` output).
        let fr = R::resolve(a);
        let bytes = fr.to_bytes();
        let mut bits = Vec::with_capacity(range_bits);
        for i in 0..range_bits {
            let byte = bytes[i / 8];
            bits.push(R::from_fr(Fr::from(((byte >> (i % 8)) & 1) as u64)));
        }
        bits
    }

    // ---- no-op assertions ----

    #[inline]
    pub fn assert_bit(&self, _x: R) {}

    #[inline]
    pub fn assert_is_const(&self, _a: R, _constant: &Fr) {}
}
