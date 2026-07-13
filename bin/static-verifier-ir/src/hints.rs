//! Concrete-`Fr` hint math shared by the eager backend and the IR
//! interpreter, so both produce bit-identical witness streams.

use core::array;

use halo2_base::{
    halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr},
    utils::{bigint_to_fe, biguint_to_fe, decompose_fe_to_u64_limbs, fe_to_bigint, fe_to_biguint},
};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use openvm_stark_sdk::{
    openvm_stark_backend::p3_field::{
        extension::BinomiallyExtendable, BasedVectorSpace, Field as P3Field,
        PrimeCharacteristicRing, PrimeField64,
    },
    p3_baby_bear::BabyBear,
};

use crate::{
    chip::{baby_bear::BABY_BEAR_MODULUS_U64, BabyBearExt4},
    hash::{Poseidon2Params, POSEIDON2_COMPRESS_PARAMS, POSEIDON2_PARAMS},
};

/// Reduce the signed representative of `a` into BabyBear.
fn fr_to_baby_bear(a: Fr) -> BabyBear {
    let m = BigInt::from(BABY_BEAR_MODULUS_U64);
    let mut r = fe_to_bigint(&a) % &m;
    if r < BigInt::from(0) {
        r += &m;
    }
    BabyBear::from_u32(u32::try_from(r).unwrap())
}

fn baby_bear_to_fr(a: BabyBear) -> Fr {
    Fr::from(a.as_canonical_u64())
}

fn fr_to_ext4(a: [Fr; 4]) -> BabyBearExt4 {
    BabyBearExt4::from_basis_coefficients_fn(|i| fr_to_baby_bear(a[i]))
}

fn ext4_to_fr(a: BabyBearExt4) -> [Fr; 4] {
    let coeffs = a.as_basis_coefficients_slice();
    array::from_fn(|i| baby_bear_to_fr(coeffs[i]))
}

/// `(inv_or_zero, indicator)`.
pub fn is_zero_hint(a: Fr) -> (Fr, Fr) {
    if a == Fr::ZERO {
        (Fr::ZERO, Fr::ONE)
    } else {
        (a.invert().unwrap(), Fr::ZERO)
    }
}

/// Floor divmod of the canonical integer of `a` by `divisor`.
pub fn div_mod_u32_hint(a: Fr, divisor: u32) -> (Fr, Fr) {
    let a_val = fe_to_biguint(&a);
    let (div, rem) = a_val.div_mod_floor(&BigUint::from(divisor));
    (biguint_to_fe(&div), biguint_to_fe(&rem))
}

/// Floor divmod of the signed representative of `a` by the BabyBear modulus.
pub fn signed_div_mod_p_hint(a: Fr) -> (Fr, Fr) {
    let b_int = BigInt::from(BABY_BEAR_MODULUS_U64);
    let (div, rem) = fe_to_bigint(&a).div_mod_floor(&b_int);
    (bigint_to_fe(&div), biguint_to_fe(&rem.to_biguint().unwrap()))
}

/// LSB-first base-`2^limb_bits` limbs of the canonical integer of `a`.
pub fn decompose_hint(a: Fr, num_limbs: u32, limb_bits: u32) -> Vec<Fr> {
    decompose_fe_to_u64_limbs(&a, num_limbs as usize, limb_bits as usize)
        .into_iter()
        .map(Fr::from)
        .collect()
}

struct BbReduceConsts {
    /// `(p_Fr - 1) / 2` as LE u64 limbs (signed-representative threshold).
    half: [u64; 4],
    /// `p_Fr mod p_BabyBear`.
    p_mod_bb: u64,
}

static BB_REDUCE_CONSTS: std::sync::LazyLock<BbReduceConsts> = std::sync::LazyLock::new(|| {
    let p_minus_1 = fe_to_biguint(&(-Fr::ONE));
    let half_bits: BigUint = &p_minus_1 >> 1;
    let mut half = [0u64; 4];
    for (i, d) in half_bits.to_u64_digits().into_iter().enumerate() {
        half[i] = d;
    }
    let p = p_minus_1 + 1u64;
    let p_mod_bb = (&p % BABY_BEAR_MODULUS_U64).to_u64_digits()[0];
    BbReduceConsts { half, p_mod_bb }
});

/// Reduce the signed representative of `a` into canonical BabyBear `[0, p)`.
///
/// Fixed-width fast path for [`signed_div_mod_p_hint`]`.1`: the divisor is a
/// compile-time constant, so the u256 mod lowers to reciprocal multiplies.
pub fn bb_reduce_hint(a: Fr) -> Fr {
    const BB: u64 = BABY_BEAR_MODULUS_U64;
    let c = &*BB_REDUCE_CONSTS;
    let bytes = a.to_bytes();
    let mut v = [0u64; 4];
    for (i, limb) in v.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    let mut rem = 0u64;
    for &l in v.iter().rev() {
        rem = ((((rem as u128) << 64) | l as u128) % BB as u128) as u64;
    }
    // v > (p-1)/2 means the signed representative is v - p (negative):
    // (v - p) mod bb = (rem - p mod bb) mod bb.
    if v.iter().rev().cmp(c.half.iter().rev()) == core::cmp::Ordering::Greater {
        rem = (rem + BB - c.p_mod_bb) % BB;
    }
    Fr::from(rem)
}

pub fn bb_div_hint(a: Fr, b: Fr) -> Fr {
    let b_inv = fr_to_baby_bear(b).try_inverse().unwrap();
    baby_bear_to_fr(fr_to_baby_bear(a) * b_inv)
}

/// Unreduced binomial-extension product over `Fr` coefficient residues
/// (`x^4 = W`). Matches the fixed formula both the eager backend and the IR
/// interpreter evaluate for `Ext4Mul`.
pub fn ext4_mul_fr(a: [Fr; 4], b: [Fr; 4]) -> [Fr; 4] {
    let w = Fr::from(<BabyBear as BinomiallyExtendable<4>>::W.as_canonical_u64());
    let mut low = [Fr::ZERO; 7];
    for i in 0..4 {
        for j in 0..4 {
            low[i + j] += a[i] * b[j];
        }
    }
    array::from_fn(|s| if s < 3 { low[s] + w * low[s + 4] } else { low[s] })
}

pub fn ext4_div_hint(a: [Fr; 4], b: [Fr; 4]) -> [Fr; 4] {
    let b_inv = fr_to_ext4(b).try_inverse().unwrap();
    ext4_to_fr(fr_to_ext4(a) * b_inv)
}

/// `packed = d0 + d1*p + ... + d4*p^4 + q*p^5` over the canonical integer.
pub fn bn_to_bb_digits_hint(packed: Fr) -> ([Fr; 5], Fr) {
    let p = BigUint::from(BABY_BEAR_MODULUS_U64);
    let mut value = fe_to_biguint(&packed);
    let digits: [Fr; 5] = array::from_fn(|_| {
        let digit = &value % &p;
        value /= &p;
        biguint_to_fe(&digit)
    });
    (digits, biguint_to_fe(&value))
}

// ---------------------------------------------------------------------------
// Poseidon2 permutation on concrete Fr (BN254 sponge / compress).
// ---------------------------------------------------------------------------

fn x_power5(x: Fr) -> Fr {
    let x2 = x * x;
    let x4 = x2 * x2;
    x * x4
}

fn matmul_external<const T: usize>(s: &mut [Fr; T]) {
    let mut sum = Fr::ZERO;
    for x in s.iter() {
        sum += x;
    }
    for x in s.iter_mut() {
        *x += sum;
    }
}

fn matmul_internal<const T: usize>(s: &mut [Fr; T], diag: &[Fr; T]) {
    let mut sum = Fr::ZERO;
    for x in s.iter() {
        sum += x;
    }
    for i in 0..T {
        s[i] = s[i] * diag[i] + sum;
    }
}

pub fn poseidon2_permute<const T: usize>(s: &mut [Fr; T], params: &Poseidon2Params<T>) {
    let rounds_f_beginning = params.rounds_f / 2;
    matmul_external(s);
    for r in 0..rounds_f_beginning {
        for (x, rc) in s.iter_mut().zip(params.external_rc[r].iter()) {
            *x += rc;
        }
        for x in s.iter_mut() {
            *x = x_power5(*x);
        }
        matmul_external(s);
    }
    for r in 0..params.rounds_p {
        s[0] += params.internal_rc[r];
        s[0] = x_power5(s[0]);
        matmul_internal(s, &params.mat_internal_diag_m_1);
    }
    for r in rounds_f_beginning..params.rounds_f {
        for (x, rc) in s.iter_mut().zip(params.external_rc[r].iter()) {
            *x += rc;
        }
        for x in s.iter_mut() {
            *x = x_power5(*x);
        }
        matmul_external(s);
    }
}

pub fn poseidon2_t3_hint(state: [Fr; 3]) -> [Fr; 3] {
    let mut s = state;
    poseidon2_permute(&mut s, &POSEIDON2_PARAMS);
    s
}

pub fn poseidon2_t2_hint(state: [Fr; 2]) -> [Fr; 2] {
    let mut s = state;
    poseidon2_permute(&mut s, &POSEIDON2_COMPRESS_PARAMS);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixed-width `bb_reduce_hint` must agree with the halo2-base-backed
    /// bigint reference on signed-threshold boundaries and random values.
    #[test]
    fn bb_reduce_matches_bigint_reference() {
        let reference = |a: Fr| signed_div_mod_p_hint(a).1;
        let half: Fr = biguint_to_fe(&(fe_to_biguint(&(-Fr::ONE)) >> 1));
        let bb = Fr::from(BABY_BEAR_MODULUS_U64);
        let mut cases = vec![
            Fr::ZERO,
            Fr::ONE,
            Fr::from(2),
            half - Fr::ONE,
            half,
            half + Fr::ONE,
            half + Fr::from(2),
            -Fr::ONE,
            -Fr::from(2),
            bb,
            bb - Fr::ONE,
            bb + Fr::ONE,
            -bb,
            half - bb,
            half + bb,
            bb * bb * bb,
            -(bb * bb * bb),
        ];
        let mut s = Fr::from(0x9e37_79b9_7f4a_7c15_u64);
        for _ in 0..1000 {
            s = s * s + Fr::ONE;
            cases.push(s);
        }
        for a in cases {
            assert_eq!(bb_reduce_hint(a), reference(a), "mismatch for {a:?}");
        }
    }
}
