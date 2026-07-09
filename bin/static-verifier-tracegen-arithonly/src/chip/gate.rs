//! Arithmetic-only re-implementation of `halo2_base::gates::flex_gate::GateChip`.
//!
//! Every method computes the same Fr witnesses the original would emit, but
//! never assigns cells / advice — inputs and outputs are raw `Fr`.

use halo2_base::halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};

#[derive(Clone, Debug)]
pub struct GateChip {
    pub pow_of_two: Vec<Fr>,
}

impl Default for GateChip {
    fn default() -> Self {
        Self::new()
    }
}

impl GateChip {
    pub fn new() -> Self {
        // Fr::NUM_BITS is 254, but the halo2-lib version pushes NUM_BITS entries.
        let num_bits = 254usize;
        let mut pow_of_two = Vec::with_capacity(num_bits);
        let two = Fr::from(2u64);
        pow_of_two.push(Fr::ONE);
        pow_of_two.push(two);
        for _ in 2..num_bits {
            let last = *pow_of_two.last().unwrap();
            pow_of_two.push(two * last);
        }
        Self { pow_of_two }
    }

    #[inline]
    pub fn pow_of_two(&self) -> &[Fr] {
        &self.pow_of_two
    }

    // --- basic arithmetic ---

    #[inline]
    pub fn add(&self, a: Fr, b: Fr) -> Fr {
        a + b
    }

    #[inline]
    pub fn sub(&self, a: Fr, b: Fr) -> Fr {
        a - b
    }

    #[inline]
    pub fn neg(&self, a: Fr) -> Fr {
        -a
    }

    #[inline]
    pub fn mul(&self, a: Fr, b: Fr) -> Fr {
        #[cfg(feature = "coz")]
        coz::scope!("mul");
        a * b
    }

    #[inline]
    pub fn mul_add(&self, a: Fr, b: Fr, c: Fr) -> Fr {
        a * b + c
    }

    /// `a - b * c`
    #[inline]
    pub fn sub_mul(&self, a: Fr, b: Fr, c: Fr) -> Fr {
        a - b * c
    }

    #[inline]
    pub fn mul_not(&self, a: Fr, b: Fr) -> Fr {
        (Fr::ONE - a) * b
    }

    // --- reductions ---

    pub fn sum<I: IntoIterator<Item = Fr>>(&self, iter: I) -> Fr {
        iter.into_iter().fold(Fr::ZERO, |acc, x| acc + x)
    }

    pub fn inner_product<I, J>(&self, a: I, b: J) -> Fr
    where
        I: IntoIterator<Item = Fr>,
        J: IntoIterator<Item = Fr>,
    {
        a.into_iter()
            .zip(b.into_iter())
            .fold(Fr::ZERO, |acc, (ai, bi)| acc + ai * bi)
    }

    // --- boolean and selection ---

    /// Returns 1 if `a == 0`, else 0. Matches the tracegen behavior: no real
    /// Fr inversion (the rational-cell inverse is deferred to prove-time batch
    /// inversion in the real circuit; in arithonly we drop it entirely).
    #[inline]
    pub fn is_zero(&self, a: Fr) -> Fr {
        if a == Fr::ZERO {
            Fr::ONE
        } else {
            Fr::ZERO
        }
    }

    #[inline]
    pub fn is_equal(&self, a: Fr, b: Fr) -> Fr {
        self.is_zero(a - b)
    }

    #[inline]
    pub fn not(&self, a: Fr) -> Fr {
        Fr::ONE - a
    }

    #[inline]
    pub fn and(&self, a: Fr, b: Fr) -> Fr {
        a * b
    }

    /// `sel ? a : b` = `sel * (a - b) + b`.
    #[inline]
    pub fn select(&self, a: Fr, b: Fr, sel: Fr) -> Fr {
        (a - b) * sel + b
    }

    pub fn idx_to_indicator(&self, idx: Fr, len: usize) -> Vec<Fr> {
        (0..len)
            .map(|i| {
                if i == 0 {
                    self.is_zero(idx)
                } else {
                    self.is_equal(idx, Fr::from(i as u64))
                }
            })
            .collect()
    }

    pub fn select_by_indicator<I: IntoIterator<Item = Fr>>(
        &self,
        a: I,
        indicator: impl IntoIterator<Item = Fr>,
    ) -> Fr {
        // Semantics match halo2-lib: `sum` accumulates `a[i]` whenever `ind[i] != 0`.
        let mut sum = Fr::ZERO;
        for (ai, ind) in a.into_iter().zip(indicator.into_iter()) {
            if ind != Fr::ZERO {
                sum = ai;
            }
        }
        sum
    }

    // --- bits ---

    pub fn num_to_bits(&self, a: Fr, range_bits: usize) -> Vec<Fr> {
        debug_assert!(range_bits > 0);
        // Extract bits little-endian from the raw Fr representation.
        let bytes = a.to_bytes();
        let mut bits = Vec::with_capacity(range_bits);
        for i in 0..range_bits {
            let byte = bytes[i / 8];
            bits.push(Fr::from(((byte >> (i % 8)) & 1) as u64));
        }
        bits
    }

    // --- constraint no-ops ---

    /// The original constrains `x * (x - 1) == 0` by writing 4 cells. Arithmetically
    /// that is a no-op (no witnesses produced). Left as a no-op.
    #[inline]
    pub fn assert_bit(&self, _x: Fr) {}

    #[inline]
    pub fn assert_is_const(&self, _a: Fr, _constant: &Fr) {}
}
