//! C backend: generates chunked C from a [`Program`], compiles it to a shared
//! object with `cc`, dlopens it, and runs it in-process.

pub mod codegen;
pub mod compile;
pub mod runner;

use halo2_base::{halo2_proofs::halo2curves::bn256::Fr, utils::fe_to_biguint};
use num_bigint::BigUint;

pub(crate) fn fr_limbs(f: Fr) -> [u64; 4] {
    // Layout validated by `assert_fr_layout` before any codegen runs.
    unsafe { std::mem::transmute::<Fr, [u64; 4]>(f) }
}

pub(crate) fn biguint_limbs(v: &BigUint) -> [u64; 4] {
    let digits = v.to_u64_digits();
    assert!(digits.len() <= 4);
    core::array::from_fn(|i| digits.get(i).copied().unwrap_or(0))
}

pub(crate) fn fr_modulus() -> BigUint {
    fe_to_biguint(&-Fr::one()) + 1u64
}

/// The generated C casts `&[Fr]` buffers directly to `fr_t*`: 4 LE u64 limbs
/// in Montgomery form (R = 2^256). Refuse to run if the layout ever changes.
pub fn assert_fr_layout() {
    assert_eq!(std::mem::size_of::<Fr>(), 32);
    assert_eq!(std::mem::align_of::<Fr>(), 8);
    let p = fr_modulus();
    let r = (BigUint::from(1u64) << 256) % &p;
    assert_eq!(
        fr_limbs(Fr::one()),
        biguint_limbs(&r),
        "Fr::one() is not R mod p — halo2curves Fr layout changed"
    );
    let two_r = (BigUint::from(2u64) * &r) % &p;
    assert_eq!(
        fr_limbs(Fr::from(2)),
        biguint_limbs(&two_r),
        "Fr::from(2) is not 2R mod p — halo2curves Fr layout changed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::BabyBearInst,
        eager::{EagerBackend, EagerCtx},
        ir::{exercise_all_opcodes, IrBackend, IrCtx},
    };

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("svir-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run_c(ir_ctx: &IrCtx, tag: &str) -> Vec<Fr> {
        assert_fr_layout();
        let dir = temp_dir(tag);
        let generated = codegen::generate(&ir_ctx.prog, &dir).unwrap();
        let so = compile::compile(&dir, &generated.c_files).unwrap();
        let compiled = runner::Compiled::load(&so).unwrap();
        let out = compiled.run(&ir_ctx.inputs, ir_ctx.prog.num_slots as usize);
        std::fs::remove_dir_all(&dir).ok();
        out
    }

    #[test]
    fn c_all_opcodes_matches_eager() {
        let mut eager = EagerCtx::new();
        exercise_all_opcodes::<EagerBackend>(&mut eager);
        let mut ir_ctx = IrCtx::new();
        exercise_all_opcodes::<IrBackend>(&mut ir_ctx);
        assert_eq!(ir_ctx.prog.num_slots as usize, eager.witness.len());
        let got = run_c(&ir_ctx, "allops");
        assert_eq!(got, eager.witness);
    }

    /// Boundary vectors for the signed-representative hints (`bb_reduce`,
    /// `bn_to_bb5`, `decompose`, `div_mod_u32`).
    #[test]
    fn c_boundary_vectors_match_eager() {
        let p = fr_modulus();
        let half = (&p - 1u64) / 2u64;
        let bb = BigUint::from(crate::chip::baby_bear::BABY_BEAR_MODULUS_U64);
        let cases: Vec<BigUint> = vec![
            BigUint::from(0u64),
            BigUint::from(1u64),
            &p - 1u64,
            half.clone(),
            &half + 1u64,
            &half - 1u64,
            bb.clone(),
            &bb * 12345u64,
            &p - &bb,
        ];
        let values: Vec<Fr> = cases.iter().map(|v| halo2_base::utils::biguint_to_fe(v)).collect();

        fn emit<B: BabyBearInst>(ctx: &mut B::Ctx, values: &[Fr]) {
            for &v in values {
                let x = B::input(ctx, v);
                let _ = B::bb_reduce(ctx, x);
                let _ = B::bn_to_bb_digits(ctx, x);
                let _ = B::decompose(ctx, x, 12, 22);
                let _ = B::div_mod_u32(ctx, x, 0x78000001);
                let _ = B::neg(ctx, x);
            }
        }

        let mut eager = EagerCtx::new();
        emit::<EagerBackend>(&mut eager, &values);
        let mut ir_ctx = IrCtx::new();
        emit::<IrBackend>(&mut ir_ctx, &values);
        assert_eq!(ir_ctx.prog.num_slots as usize, eager.witness.len());

        let interpreted = crate::ir::interp::interpret(&ir_ctx.prog, &ir_ctx.inputs);
        assert_eq!(interpreted, eager.witness, "interpreter boundary mismatch");

        let got = run_c(&ir_ctx, "boundary");
        assert_eq!(got, eager.witness, "C boundary mismatch");
    }
}
