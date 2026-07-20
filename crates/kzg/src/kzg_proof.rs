use crate::{dtypes::*, enums::KzgError, types::KzgSettings};

use alloc::{string::ToString, vec::Vec};
#[cfg(not(feature = "use-intrinsics"))]
use bls12_381::{multi_miller_loop, G2Prepared, Gt};
use bls12_381::{G1Affine, G2Affine, Scalar};
#[cfg(any(openvm_intrinsics, target_os = "openvm"))]
use core::cmp::Ordering;
use hex_literal::hex;
use openvm_algebra_guest::{field::FieldExtension, IntMod};
#[cfg(any(openvm_intrinsics, target_os = "openvm"))]
use openvm_curve_utils::SubgroupCheck;
use openvm_ecc_guest::{
    weierstrass::{CachedMulTable, IntrinsicCurve, WeierstrassPoint},
    AffinePoint, CyclicGroup, Group,
};
use openvm_pairing::bls12_381::{
    Bls12_381 as Bls12_381_G1, Fp, Fp2, G1Affine as Bls12_381G1Affine,
    G2Affine as Bls12_381G2Affine, Scalar as Bls12_381Scalar,
};

const G2_AFFINE_GENERATOR: Bls12_381G2Affine = Bls12_381G2Affine::new(
    Fp2::new(
        Fp::from_const_bytes(hex!("B8BD21C1C85680D4EFBB05A82603AC0B77D1E37A640B51B4023B40FAD47AE4C65110C52D27050826910A8FF0B2A24A02")),
        Fp::from_const_bytes(hex!("7E2B045D057DACE5575D941312F14C3349507FDCBB61DAB51AB62099D0D06B59654F2788A0D3AC7D609F7152602BE013"))
    ),
    Fp2::new(
        Fp::from_const_bytes(hex!("0128B808865493E189A2AC3BCCC93A922CD16051699A426DA7D3BD8CAA9BFDAD1A352EDAC6CDC98C116E7D7227D5E50C")),
        Fp::from_const_bytes(hex!("BE795FF05F07A9AAA11DEC5C270D373FAB992E57AB927426AF63A7857E283ECB998BC22BB0D2AC32CC34A72EA0C40606"))
    ),
    // z = 1: projective representation of the affine generator
    Fp2::ONE,
);

#[derive(Debug)]
pub struct KzgProof {}

impl KzgProof {
    /// This function asserts that the KZG proof is valid. It will panic if the proof is not valid.
    ///
    /// **WARNING:** a dishonest host of the VM may cause this function to panic even on valid
    /// inputs, so this function cannot be used to prove that the KZG proof is definitely
    /// invalid.
    ///
    /// Therefore this function should only be used in cases where successful guest program
    /// execution requires the KZG proof to be valid.
    #[cfg(feature = "use-intrinsics")]
    pub fn verify_kzg_proof(
        commitment_bytes: &Bytes48,
        z_bytes: &Bytes32,
        y_bytes: &Bytes32,
        proof_bytes: &Bytes48,
        kzg_settings: &KzgSettings,
    ) -> Result<bool, KzgError> {
        // Check that the scalar is valid
        let z = Bls12_381Scalar::from_be_bytes(z_bytes.as_slice())
            .ok_or_else(|| KzgError::BadArgs("Scalar z is not reduced".to_string()))?;
        let y = Bls12_381Scalar::from_be_bytes(y_bytes.as_slice())
            .ok_or_else(|| KzgError::BadArgs("Scalar y is not reduced".to_string()))?;

        let commitment = safe_g1_affine_from_bytes(commitment_bytes)?;
        let proof = safe_g1_affine_from_bytes(proof_bytes)?;

        let openvm_kzg_g2_point = to_openvm_g2_affine(kzg_settings.g2_points[1]);

        // Used for CachedMulTable implementation of msm for Bls12_381_G2.
        #[allow(non_camel_case_types)]
        struct Bls12_381_G2;
        impl IntrinsicCurve for Bls12_381_G2 {
            type Scalar = Bls12_381Scalar; // order of the generator is prime
            type Point = Bls12_381G2Affine;

            fn msm(coeffs: &[Self::Scalar], bases: &[Self::Point]) -> Self::Point {
                openvm_ecc_guest::msm(coeffs, bases)
            }
        }

        // We use the fact that g2_affine_generator has prime order.
        let table = CachedMulTable::<Bls12_381_G2>::new_with_prime_order(&[G2_AFFINE_GENERATOR], 4);
        let g2_z = table.windowed_mul(&[z]);

        // `g2_z` is an MSM result (projective, z != 1), so the difference is projective;
        // normalize once here so `pairings_verify` can skip re-normalizing.
        let x_minus_z = (openvm_kzg_g2_point - g2_z).normalize();

        // We use the fact that Bls12_381G1Affine::GENERATOR has prime order.
        let table = CachedMulTable::<Bls12_381_G1>::new_with_prime_order(
            &[Bls12_381G1Affine::GENERATOR],
            4,
        );
        let g1_y = table.windowed_mul(&[y]);

        // `g1_y` is an MSM result (projective, z != 1); normalize the difference once here.
        let p_minus_y = (commitment - g1_y).normalize();

        let success = pairings_verify(p_minus_y, G2_AFFINE_GENERATOR.clone(), proof, x_minus_z);
        Ok(success)
    }

    /// Does not use intrinsics. Pure Rust implementation.
    #[cfg(not(feature = "use-intrinsics"))]
    pub fn verify_kzg_proof(
        commitment_bytes: &Bytes48,
        z_bytes: &Bytes32,
        y_bytes: &Bytes32,
        proof_bytes: &Bytes48,
        kzg_settings: &KzgSettings,
    ) -> Result<bool, KzgError> {
        // Check that the scalar is valid
        let z = safe_scalar_affine_from_bytes(z_bytes)?;
        let y = safe_scalar_affine_from_bytes(y_bytes)?;

        let commitment = safe_g1_affine_from_bytes_native(commitment_bytes)?;
        let proof = safe_g1_affine_from_bytes_native(proof_bytes)?;

        let kzg_g2_point = kzg_settings.g2_points[1];
        let g2_z = G2Affine::generator() * z;
        let x_minus_z = G2Affine::from(kzg_g2_point - g2_z);
        let g1_y = G1Affine::generator() * y;
        let p_minus_y = G1Affine::from(commitment - g1_y);

        let success = multi_miller_loop(&[
            (&-p_minus_y, &G2Prepared::from(G2Affine::generator())),
            (&proof, &G2Prepared::from(x_minus_z)),
        ])
        .final_exponentiation() ==
            Gt::identity();
        Ok(success)
    }
}

/// Verifies the pairing of two G1 and two G2 points are equivalent using the multi-miller loop.
///
/// All inputs must be in affine form (`z == 1`); this function does not normalize. Callers passing
/// a projective point (e.g. an un-normalized MSM/`Sub` result) must `.normalize()` it first.
fn pairings_verify(
    p0: Bls12_381G1Affine,
    p1: Bls12_381G2Affine,
    q0: Bls12_381G1Affine,
    q1: Bls12_381G2Affine,
) -> bool {
    use openvm_pairing::{bls12_381::Bls12_381, PairingCheck};

    // All four inputs are affine (z = 1): the two computed points are normalized by the caller,
    // and the generator/proof come from `from_xy`. Extract coords without re-normalizing.
    let [p0, q0] = [p0, q0].map(|p| {
        let (x, y, _) = p.into_coords();
        AffinePoint::new(x, y)
    });
    let g1_points = [-p0, q0];
    let g2_points = [p1, q1].map(|p| {
        let (x, y, _) = p.into_coords();
        AffinePoint::new(x, y)
    });

    Bls12_381::pairing_check(&g1_points, &g2_points).is_ok()
}

pub fn g1_affine_is_on_curve(p: &AffinePoint<Fp>) -> bool {
    if p.is_infinity() {
        return true;
    }
    let x = &p.x;
    let y = &p.y;
    // y^2 == x^3 + 4
    y * y - x * x * x - Fp::from_u8(4) == Fp::ZERO
}

pub fn g2_affine_is_on_curve(p: &AffinePoint<Fp2>) -> bool {
    if p.is_infinity() {
        return true;
    }
    let x = &p.x;
    let y = &p.y;
    // y^2 - x^3 ?= 4(u + 1)
    let x_3 = x * x * x;
    let y_2 = y * y;
    let four = Fp2::new(Fp::from_u32(4), Fp::from_u32(4));
    y_2 - x_3 == four
}

// Conversion functions:

/// Assumes that G2Affine is a point on the curve in the correct subgroup.
fn to_openvm_g2_affine(g2: G2Affine) -> Bls12_381G2Affine {
    if g2.is_identity().unwrap_u8() != 0 {
        return <Bls12_381G2Affine as Group>::IDENTITY;
    }
    let g2_bytes = g2.to_uncompressed();
    let x_c1: [u8; 48] = g2_bytes[0..48].try_into().unwrap();
    let x_c0: [u8; 48] = g2_bytes[48..96].try_into().unwrap();
    let y_c1: [u8; 48] = g2_bytes[96..144].try_into().unwrap();
    let y_c0: [u8; 48] = g2_bytes[144..192].try_into().unwrap();

    let ox =
        Fp2::from_coeffs([Fp::from_be_bytes_unchecked(&x_c0), Fp::from_be_bytes_unchecked(&x_c1)]);
    let oy =
        Fp2::from_coeffs([Fp::from_be_bytes_unchecked(&y_c0), Fp::from_be_bytes_unchecked(&y_c1)]);
    unsafe { Bls12_381G2Affine::from_xy_unchecked(ox, oy) }
}

/// Returns true if the field element is lexicographically larger than its negation.
///
/// The input `y` does not need to be reduced modulo the modulus.
#[cfg(any(openvm_intrinsics, target_os = "openvm"))]
fn is_lex_largest(y: &Fp) -> bool {
    let neg_y = -y.clone();
    // This is a way to force y and -y are both in reduced form simultaneously using `iseqmod`
    // opcode Guest execution will never terminate if these elements are not reduced
    let _ = core::hint::black_box(y == &neg_y);
    // Compare y big endian bytes lexicographically with -y big endian bytes
    for (l, r) in y.as_le_bytes().iter().rev().zip(neg_y.as_le_bytes().iter().rev()) {
        match l.cmp(r) {
            Ordering::Greater => return true,
            Ordering::Less => return false,
            Ordering::Equal => continue,
        }
    }
    // all bytes are equal
    false
}

// hint_decompress is currently not implemented on host because of the need to do a sqrt
#[cfg(any(openvm_intrinsics, target_os = "openvm"))]
pub fn safe_g1_affine_from_bytes(bytes: &Bytes48) -> Result<Bls12_381G1Affine, KzgError> {
    use openvm_ecc_guest::weierstrass::FromCompressed;

    let mut x_bytes = [0u8; 48];
    x_bytes.copy_from_slice(&bytes.0[0..48]);

    let compression_flag_set = ((x_bytes[0] >> 7) & 1) != 0;
    let infinity_flag_set = ((x_bytes[0] >> 6) & 1) != 0;
    let sort_flag_set = ((x_bytes[0] >> 5) & 1) != 0;

    // Mask away the flag bits
    x_bytes[0] &= 0b0001_1111;
    let x = Fp::from_be_bytes(&x_bytes)
        .ok_or_else(|| KzgError::BadArgs("x bytes not in canonical form".to_string()))?;

    if infinity_flag_set && compression_flag_set && !sort_flag_set && x == Fp::ZERO {
        return Ok(<Bls12_381G1Affine as Group>::IDENTITY);
    }
    if infinity_flag_set || !compression_flag_set {
        return Err(KzgError::BadArgs("invalid G1 point encoding".to_string()));
    }

    // Note that we need to determine the y-coord using lexicographic ordering instead of parity, so
    // the value for rec_id does not matter and we can pass in either 0 or 1.
    let mut point = Bls12_381G1Affine::decompress(x, &0u8)
        .ok_or_else(|| KzgError::BadArgs("Failed to decompress G1Affine".to_string()))?;
    if is_lex_largest(point.y()) ^ sort_flag_set {
        point.y_mut().neg_assign();
    }
    // `decompress` only guarantees the point is on the curve. BLS12-381 G1 has cofactor > 1,
    // so an on-curve point may lie outside the prime-order subgroup; reject those. (The
    // identity is valid and is already returned by the early check above.)
    if !point.is_in_correct_subgroup() {
        return Err(KzgError::BadArgs("G1Affine not in correct subgroup".to_string()));
    }
    Ok(point)
}

/// Assumes that G1Affine is a point on the curve in the correct subgroup.
#[cfg(not(any(openvm_intrinsics, target_os = "openvm")))]
fn to_openvm_g1_affine(g1: G1Affine) -> Bls12_381G1Affine {
    if g1.is_identity().unwrap_u8() != 0 {
        return <Bls12_381G1Affine as Group>::IDENTITY;
    }
    let g1_bytes = g1.to_uncompressed();
    let x = Fp::from_be_bytes_unchecked(&g1_bytes[0..48]);
    let y = Fp::from_be_bytes_unchecked(&g1_bytes[48..96]);
    unsafe { Bls12_381G1Affine::from_xy_unchecked(x, y) }
}

#[cfg(not(any(openvm_intrinsics, target_os = "openvm")))]
pub fn safe_g1_affine_from_bytes(bytes: &Bytes48) -> Result<Bls12_381G1Affine, KzgError> {
    let g1 = safe_g1_affine_from_bytes_native(bytes)?;
    Ok(to_openvm_g1_affine(g1))
}

pub fn safe_g1_affine_from_bytes_native(bytes: &Bytes48) -> Result<G1Affine, KzgError> {
    let g1 = G1Affine::from_compressed(&bytes.0);
    g1.into_option()
        .ok_or_else(|| KzgError::BadArgs("Failed to parse G1Affine from bytes".to_string()))
}

pub fn safe_scalar_affine_from_bytes(bytes: &Bytes32) -> Result<Scalar, KzgError> {
    let lendian: [u8; 32] =
        bytes.as_slice().iter().rev().copied().collect::<Vec<u8>>().try_into().unwrap();

    let scalar = Scalar::from_bytes(&lendian);
    if scalar.is_none().into() {
        return Err(KzgError::BadArgs("Failed to parse Scalar from bytes32".to_string()));
    }
    Ok(scalar.unwrap())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        test_files::VERIFY_KZG_PROOF_TESTS,
        test_utils::{Input, Test},
    };

    // This is a test on host
    #[test]
    pub fn test_verify_kzg_proof() {
        let kzg_settings = KzgSettings::load_trusted_setup_file().unwrap();

        for (test_file, data) in &VERIFY_KZG_PROOF_TESTS {
            let test: Test<Input<'_>> = serde_yaml::from_str(data).unwrap();
            let (Ok(commitment), Ok(z), Ok(y), Ok(proof)) = (
                test.input.get_commitment(),
                test.input.get_z(),
                test.input.get_y(),
                test.input.get_proof(),
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };

            let result = KzgProof::verify_kzg_proof(&commitment, &z, &y, &proof, &kzg_settings);
            println!("test: {test_file}: {result:?}");
            let is_ok = result.unwrap_or(false);
            assert_eq!(is_ok, test.get_output().unwrap_or(false));
        }
    }
}
