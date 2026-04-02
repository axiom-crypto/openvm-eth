//! Subgroup membership checks for elliptic curve points.
//!
//! For pairing-based cryptography to be secure, points must lie in the correct
//! prime-order subgroup of the curve. A point that satisfies the curve equation
//! is not necessarily in the correct subgroup — this only holds when the curve's
//! cofactor is 1 (i.e., the curve group itself is prime-order). When the
//! cofactor is greater than 1, the curve group contains additional points
//! outside the prime-order subgroup, and accepting such points can lead to
//! invalid-curve or small-subgroup attacks.
//!
//! ## When is a subgroup check needed?
//!
//! An elliptic curve group of order `n` can be written as `n = h * r`, where
//! `r` is the prime subgroup order used in the cryptographic protocol and `h`
//! is the **cofactor**. If `h = 1`, every point on the curve is in the
//! prime-order subgroup and no additional check is required. If `h > 1`, a
//! dedicated subgroup check is necessary to reject points that lie in a
//! different subgroup of order dividing `h`.
//!
//! ## Cofactors for the supported curves
//!
//! | Curve       | Group | Cofactor | Subgroup check needed? |
//! |-------------|-------|----------|------------------------|
//! | BN254       | G1    | 1        | No                     |
//! | BN254       | G2    | > 1      | Yes                    |
//! | BLS12-381   | G1    | > 1      | Yes                    |
//! | BLS12-381   | G2    | > 1      | Yes                    |
//!
//! ## Assumption
//!
//! All implementations in this module assume that the point has **already been
//! verified to lie on the curve** (i.e., it satisfies the curve equation). This
//! trait only checks the additional condition of subgroup membership.

use openvm_ecc_guest::weierstrass::WeierstrassPoint;

/// Scalar multiplication using simple double-and-add
fn scalar_mul<P: WeierstrassPoint, const CHECK_SETUP: bool>(
    base: &P,
    scalar: impl AsRef<[u64]>,
) -> P {
    let mut result = P::IDENTITY;
    let mut temp = base.clone();
    for limb in scalar.as_ref() {
        for bit_idx in 0..64u32 {
            if (limb >> bit_idx) & 1 == 1 {
                result = result.add_impl::<CHECK_SETUP>(&temp);
            }
            temp = temp.double_impl::<CHECK_SETUP>();
        }
    }
    result
}

/// Checks whether an elliptic curve point belongs to the correct prime-order
/// subgroup.
///
/// This trait assumes that the point is already known to be on the curve. It
/// only verifies the additional property of subgroup membership, which is
/// necessary when the curve has cofactor greater than 1.
pub(crate) trait SubgroupCheck: WeierstrassPoint {
    /// Returns `true` if this point lies in the correct prime-order subgroup.
    ///
    /// # Assumption
    ///
    /// The caller must ensure that the point satisfies the curve equation
    /// before calling this method. If the point is not on the curve, the
    /// result is meaningless.
    fn is_in_correct_subgroup(&self) -> bool;
}

mod impl_bn {
    use alloy_primitives::hex;
    use openvm_ecc_guest::{algebra::field::FieldExtension, weierstrass::WeierstrassPoint};
    use openvm_pairing::bn254 as bn;

    /// The value `6x²` is the BN254 curve parameter stored as two little-endian `u64` limbs.
    const SIX_X_SQUARED: [u64; 2] = [17887900258952609094, 8020209761171036667];

    /// First Fp2 coefficient of the untwist-Frobenius-twist endomorphism ψ on BN254's
    /// G2 twist curve.
    ///
    /// Ref: [arkworks bn254/g2.rs](https://github.com/arkworks-rs/algebra/blob/master/curves/bn254/src/curves/g2.rs).
    const P_POWER_ENDOMORPHISM_COEFF_0: bn::Fp2 = bn::Fp2::new(
        bn::Fp::from_const_bytes(hex!(
            "3d556f175795e3990c33c3c210c38cb743b159f53cec0b4cf711794f9847b32f"
        )),
        bn::Fp::from_const_bytes(hex!(
            "a2cb0f641cd56516ce9d7c0b1d2aae3294075ad78bcca44b20aeeb6150e5c916"
        )),
    );

    /// Second Fp2 coefficient of the untwist-Frobenius-twist endomorphism ψ on BN254's
    /// G2 twist curve.
    ///
    /// Ref: [arkworks bn254/g2.rs](https://github.com/arkworks-rs/algebra/blob/master/curves/bn254/src/curves/g2.rs).
    const P_POWER_ENDOMORPHISM_COEFF_1: bn::Fp2 = bn::Fp2::new(
        bn::Fp::from_const_bytes(hex!(
            "5a13a071460154dc9859c9a9ede0aadbb9f9e2b698c65edcdcf59a4805f33c06"
        )),
        bn::Fp::from_const_bytes(hex!(
            "e3b02326637fd382d25ba28fc97d80212b6f79eca7b504079a0441acbc3cc007"
        )),
    );

    /// BN254 G1 has cofactor 1, so the curve group is exactly the prime-order
    /// subgroup. Any point that lies on the curve is necessarily in the correct
    /// subgroup, making an explicit check unnecessary.
    impl super::SubgroupCheck for bn::G1Affine {
        fn is_in_correct_subgroup(&self) -> bool {
            true
        }
    }

    /// BN254 G2 is defined over the sextic twist curve, which has cofactor > 1.
    /// A point on the twist curve may not be in the prime-order subgroup.
    ///
    /// Implements section 4.3 of https://eprint.iacr.org/2022/352.pdf to check `[6x²]P == ψ(P)`.
    impl super::SubgroupCheck for bn::G2Affine {
        fn is_in_correct_subgroup(&self) -> bool {
            // The identity is always in the subgroup.
            if WeierstrassPoint::is_identity(self) {
                return true;
            }

            // 1. Compute [6x²]P using double-and-add.
            //
            // `CHECK_SETUP=false` since `set_up_once` is a no-op for [`impl_sw_proj`] types.
            let x_times_point = super::scalar_mul::<_, false>(self, SIX_X_SQUARED);

            // 2. Compute ψ(P), i.e. "untwist-Frobenius-twist".
            //
            // - ψ(P).x = frob(P.x) · COEFF_0
            // - ψ(P).y = frob(P.y) · COEFF_1
            let endomorphism_point = {
                let psi_x = self.x().frobenius_map(1) * P_POWER_ENDOMORPHISM_COEFF_0;
                let psi_y = self.y().frobenius_map(1) * P_POWER_ENDOMORPHISM_COEFF_1;
                Self::from_xy_unchecked(psi_x, psi_y)
            };

            x_times_point.eq(&endomorphism_point)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::subgroup_check::SubgroupCheck;
        use openvm_ecc_guest::{algebra::IntMod, CyclicGroup};

        #[test]
        fn test_six_x_squared() {
            use ark_bn254::Config;
            use ark_ec::bn::BnConfig;
            let x = Config::X[0] as u128;
            let val = 6 * x * x;
            let lo = val as u64;
            let hi = (val >> 64) as u64;
            assert_eq!(SIX_X_SQUARED, [lo, hi]);
        }

        #[test]
        fn test_p_power_endomorphism_coeff_0() {
            use ark_ff::{BigInteger, MontFp, PrimeField};
            let c0: ark_bn254::Fq = MontFp!(
                "21575463638280843010398324269430826099269044274347216827212613867836435027261"
            );
            let c1: ark_bn254::Fq = MontFp!(
                "10307601595873709700152284273816112264069230130616436755625194854815875713954"
            );
            assert_eq!(
                c0.into_bigint().to_bytes_le(),
                P_POWER_ENDOMORPHISM_COEFF_0.c0.as_le_bytes()
            );
            assert_eq!(
                c1.into_bigint().to_bytes_le(),
                P_POWER_ENDOMORPHISM_COEFF_0.c1.as_le_bytes()
            );
        }

        #[test]
        fn test_p_power_endomorphism_coeff_1() {
            use ark_ff::{BigInteger, MontFp, PrimeField};
            let c0: ark_bn254::Fq = MontFp!(
                "2821565182194536844548159561693502659359617185244120367078079554186484126554"
            );
            let c1: ark_bn254::Fq = MontFp!(
                "3505843767911556378687030309984248845540243509899259641013678093033130930403"
            );
            assert_eq!(
                c0.into_bigint().to_bytes_le(),
                P_POWER_ENDOMORPHISM_COEFF_1.c0.as_le_bytes()
            );
            assert_eq!(
                c1.into_bigint().to_bytes_le(),
                P_POWER_ENDOMORPHISM_COEFF_1.c1.as_le_bytes()
            );
        }

        #[test]
        fn test_bn254_g1_generator_in_subgroup() {
            assert!(bn::G1Affine::GENERATOR.is_in_correct_subgroup());
        }

        #[test]
        fn test_bn254_g1_identity_in_subgroup() {
            assert!(bn::G1Affine::IDENTITY.is_in_correct_subgroup());
        }

        #[test]
        fn test_bn254_g2_generator_in_subgroup() {
            use ark_ec::AffineRepr;
            use ark_ff::{BigInteger, PrimeField};
            let ark_gen = ark_bn254::G2Affine::generator();
            let (ark_x, ark_y) = ark_gen.xy().unwrap();

            let x_c0_bytes = ark_x.c0.into_bigint().to_bytes_le();
            let x_c1_bytes = ark_x.c1.into_bigint().to_bytes_le();
            let y_c0_bytes = ark_y.c0.into_bigint().to_bytes_le();
            let y_c1_bytes = ark_y.c1.into_bigint().to_bytes_le();

            let x = bn::Fp2::new(
                bn::Fp::from_le_bytes_unchecked(&x_c0_bytes),
                bn::Fp::from_le_bytes_unchecked(&x_c1_bytes),
            );
            let y = bn::Fp2::new(
                bn::Fp::from_le_bytes_unchecked(&y_c0_bytes),
                bn::Fp::from_le_bytes_unchecked(&y_c1_bytes),
            );
            let g2 = bn::G2Affine::from_xy(x, y).expect("G2 generator should be on curve");
            assert!(g2.is_in_correct_subgroup());
        }

        #[test]
        fn test_bn254_g2_identity_in_subgroup() {
            assert!(bn::G2Affine::IDENTITY.is_in_correct_subgroup());
        }

        #[test]
        fn test_bn254_g2_rejects_non_subgroup_point() {
            // Test vector from scroll-tech. EVM encoding: [x.c1, x.c0, y.c1, y.c0] in big-endian.
            let x_c1 = hex!("263e2979dbc2fa0e7c73e38ccc6890b84f4191abb9cba88ed36e9e3726f5142d");
            let x_c0 = hex!("21f24401109878b0eee42d80f405a63c5912bcdfd4aa49ee1e7abf9b41bc3f93");
            let y_c1 = hex!("2173aec93d1b4f8542cbf320eb5b3e7bf495f3a9b3288c9384e91b54c2bff969");
            let y_c0 = hex!("23c6f9d2be4bdaabb95148a8d78a725db01fc6d66c2bc2b0a964511b778e4238");

            let x = bn::Fp2::new(
                bn::Fp::from_be_bytes(&x_c0).unwrap(),
                bn::Fp::from_be_bytes(&x_c1).unwrap(),
            );
            let y = bn::Fp2::new(
                bn::Fp::from_be_bytes(&y_c0).unwrap(),
                bn::Fp::from_be_bytes(&y_c1).unwrap(),
            );
            let point = bn::G2Affine::from_xy(x, y).expect("point should be on curve");
            assert!(!point.is_in_correct_subgroup());
        }
    }
}

mod impl_bls {
    use std::ops::{MulAssign, Neg};

    use alloy_primitives::hex;
    use openvm_ecc_guest::{algebra::field::FieldExtension, weierstrass::WeierstrassPoint};
    use openvm_pairing::bls12_381 as bls;

    /// The BLS12-381 curve parameter `|u| = 0xd201000000010000`. The parameter `u`
    /// is negative; the sign is applied via explicit `.neg()` in the algorithms.
    const X: [u64; 1] = [0xd201000000010000];

    /// A non-trivial cube root of unity in Fq (`β³ = 1, β ≠ 1`), used for the GLV
    /// endomorphism `σ: (x, y) → (βx, y)` on G1.
    ///
    /// Ref: [arkworks bls12_381/g1.rs](https://github.com/arkworks-rs/algebra/blob/master/curves/bls12_381/src/curves/g1.rs).
    const BETA: bls::Fp = bls::Fp::from_const_bytes(hex!(
        "fefffeffffff012e02000a6213d817de8896f8e63ba9b3ddea770f6a07c669ba51ce76df2f67195f0000000000000000"
    ));

    /// Fp2 coefficient for the untwist-Frobenius-twist endomorphism ψ on BLS12-381's
    /// G2 twist curve. Has `c0 = 0`, which the implementation exploits to replace a
    /// full Fp2 multiplication with two Fp multiplications.
    ///
    /// Ref: [arkworks bls12_381/g2.rs](https://github.com/arkworks-rs/algebra/blob/master/curves/bls12_381/src/curves/g2.rs).
    const P_POWER_ENDOMORPHISM_COEFF_0: bls::Fp2 = bls::Fp2::new(
        bls::Fp::from_const_bytes(hex!(
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        )),
        bls::Fp::from_const_bytes(hex!(
            "adaa00000000fd8bfdff494feb2794409b5fb80f65297d89d49a75897d850daa85ded463864002ec99e67f39ea11011a"
        )),
    );

    /// Second Fp2 coefficient for the untwist-Frobenius-twist endomorphism ψ on
    /// BLS12-381's G2 twist curve: `ψ(P).y = frob(P.y) · COEFF_1`.
    ///
    /// Ref: [arkworks bls12_381/g2.rs](https://github.com/arkworks-rs/algebra/blob/master/curves/bls12_381/src/curves/g2.rs).
    const P_POWER_ENDOMORPHISM_COEFF_1: bls::Fp2 = bls::Fp2::new(
        bls::Fp::from_const_bytes(hex!(
            "a2de1b12047beef10afa673ecf6644305eb41ef6896439ef60cfb130d9ed3d1cd92c7ad748c4e9e28ea68001e6035213"
        )),
        bls::Fp::from_const_bytes(hex!(
            "09cce3edfb8410c8f405ec722f9967eec5419200176ef7775e43d3c2ab5d3948fe7fd16b6de331680b40ff37040eaf06"
        )),
    );

    /// BLS12-381 G1 has cofactor > 1, so not every point on the curve is in the
    /// prime-order subgroup.
    ///
    /// Implements section 6 of https://eprint.iacr.org/2021/1130.
    impl super::SubgroupCheck for bls::G1Affine {
        fn is_in_correct_subgroup(&self) -> bool {
            // 1. Compute [x]P using double-and-add.
            //
            // `CHECK_SETUP=true` given that bls12_381::G1Affine is implemented via [`sw_declare`]
            // that does in fact do a setup.
            //
            // If [x]P == P but P != identity then point is not in the right subgroup.
            let x_times_point = super::scalar_mul::<_, true>(self, X);
            if self.eq(&x_times_point) && !WeierstrassPoint::is_identity(self) {
                return false;
            }

            // 2. Compute -[x²]P.
            //
            // Here we can assume `CHECK_SETUP=false` since setup has necessarily been done above.
            let minus_x_squared_times_point =
                super::scalar_mul::<_, false>(&x_times_point, X).neg();

            // 2. Compute endomorphism
            //
            // - σ: (x, y) → (βx, y)
            let endomorphism_point = {
                let mut result = self.clone();
                result.x_mut().mul_assign(&BETA);
                result
            };

            minus_x_squared_times_point.eq(&endomorphism_point)
        }
    }

    /// BLS12-381 G2 is defined over the twist curve, which has cofactor > 1.
    /// A point on the twist curve may not be in the prime-order subgroup.
    ///
    /// Implements section 4 of https://eprint.iacr.org/2021/1130.
    impl super::SubgroupCheck for bls::G2Affine {
        fn is_in_correct_subgroup(&self) -> bool {
            // The identity is always in the subgroup.
            if WeierstrassPoint::is_identity(self) {
                return true;
            }

            // 1. Compute -[x]P using double-and-add (X is negative).
            let x_times_point = super::scalar_mul::<_, true>(self, X).neg();

            // 2. Compute ψ(P)
            let endomorphism_point = {
                let tmp_x = self.x().frobenius_map(1);
                let psi_x_c0 = -P_POWER_ENDOMORPHISM_COEFF_0.c1 * tmp_x.c1;
                let psi_x_c1 = P_POWER_ENDOMORPHISM_COEFF_0.c1 * tmp_x.c0;
                let psi_x = bls::Fp2::new(psi_x_c0, psi_x_c1);
                let psi_y = self.y().frobenius_map(1) * P_POWER_ENDOMORPHISM_COEFF_1;
                Self::from_xy_unchecked(psi_x, psi_y)
            };

            x_times_point.eq(&endomorphism_point)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::subgroup_check::SubgroupCheck;
        use openvm_ecc_guest::{algebra::IntMod, weierstrass::WeierstrassPoint, CyclicGroup};

        #[test]
        fn test_beta() {
            use ark_ff::{BigInteger, MontFp, PrimeField};
            let beta: ark_bls12_381::Fq = MontFp!("793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350");
            assert_eq!(beta.into_bigint().to_bytes_le(), BETA.as_le_bytes());
        }

        #[test]
        fn test_p_power_endomorphism_coeff_0() {
            use ark_ff::{BigInteger, MontFp, PrimeField};
            let c0: ark_bls12_381::Fq = MontFp!("0");
            let c1: ark_bls12_381::Fq = MontFp!("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437");
            assert_eq!(
                c0.into_bigint().to_bytes_le(),
                P_POWER_ENDOMORPHISM_COEFF_0.c0.as_le_bytes()
            );
            assert_eq!(
                c1.into_bigint().to_bytes_le(),
                P_POWER_ENDOMORPHISM_COEFF_0.c1.as_le_bytes()
            );
        }

        #[test]
        fn test_p_power_endomorphism_coeff_1() {
            use ark_ff::{BigInteger, MontFp, PrimeField};
            let c0: ark_bls12_381::Fq = MontFp!("2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530");
            let c1: ark_bls12_381::Fq = MontFp!("1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257");
            assert_eq!(
                c0.into_bigint().to_bytes_le(),
                P_POWER_ENDOMORPHISM_COEFF_1.c0.as_le_bytes()
            );
            assert_eq!(
                c1.into_bigint().to_bytes_le(),
                P_POWER_ENDOMORPHISM_COEFF_1.c1.as_le_bytes()
            );
        }

        #[test]
        fn test_bls12381_g1_generator_in_subgroup() {
            assert!(bls::G1Affine::GENERATOR.is_in_correct_subgroup());
        }

        #[test]
        fn test_bls12381_g1_identity_in_subgroup() {
            assert!(<bls::G1Affine as WeierstrassPoint>::IDENTITY.is_in_correct_subgroup());
        }

        #[test]
        fn test_bls12381_g1_rejects_non_subgroup_point() {
            let x_bytes = [0u8; 48];
            let y_bytes = hex!("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaa9");
            let px = bls::Fp::from_be_bytes(&x_bytes).unwrap();
            let py = bls::Fp::from_be_bytes(&y_bytes).unwrap();
            let point = bls::G1Affine::from_xy(px, py).expect("point should be on curve");
            assert!(!point.is_in_correct_subgroup());
        }

        #[test]
        fn test_bls12381_g2_generator_in_subgroup() {
            use ark_ec::AffineRepr;
            use ark_ff::{BigInteger, PrimeField};
            let ark_gen = ark_bls12_381::G2Affine::generator();
            let (ark_x, ark_y) = ark_gen.xy().unwrap();

            let x_c0_bytes = ark_x.c0.into_bigint().to_bytes_le();
            let x_c1_bytes = ark_x.c1.into_bigint().to_bytes_le();
            let y_c0_bytes = ark_y.c0.into_bigint().to_bytes_le();
            let y_c1_bytes = ark_y.c1.into_bigint().to_bytes_le();

            let x = bls::Fp2::new(
                bls::Fp::from_le_bytes_unchecked(&x_c0_bytes),
                bls::Fp::from_le_bytes_unchecked(&x_c1_bytes),
            );
            let y = bls::Fp2::new(
                bls::Fp::from_le_bytes_unchecked(&y_c0_bytes),
                bls::Fp::from_le_bytes_unchecked(&y_c1_bytes),
            );
            let g2 = bls::G2Affine::from_xy(x, y).expect("G2 generator should be on curve");
            assert!(g2.is_in_correct_subgroup());
        }

        #[test]
        fn test_bls12381_g2_identity_in_subgroup() {
            assert!(<bls::G2Affine as WeierstrassPoint>::IDENTITY.is_in_correct_subgroup());
        }

        #[test]
        fn test_bls12381_g2_rejects_non_subgroup_point() {
            let mut one_be = [0u8; 48];
            one_be[47] = 1;
            let x = bls::Fp2::new(
                bls::Fp::from_be_bytes(&[0u8; 48]).unwrap(),
                bls::Fp::from_be_bytes(&one_be).unwrap(),
            );
            let y_c0_bytes = hex!("135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2");
            let y_c1_bytes = hex!("140d2a0ca7fdc0223895aa4843747ffad8ac19034879ca1b67e64a4501b6c551cb36cb8e58c411de58318ef3c9ab641b");
            let y = bls::Fp2::new(
                bls::Fp::from_be_bytes(&y_c0_bytes).unwrap(),
                bls::Fp::from_be_bytes(&y_c1_bytes).unwrap(),
            );
            let point = bls::G2Affine::from_xy(x, y).expect("point should be on twist curve");
            assert!(!point.is_in_correct_subgroup());
        }
    }
}
