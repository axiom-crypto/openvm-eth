//! Backend-generic Poseidon2 sponge helpers. Permutations are atomic backend
//! ops (`B::poseidon2_t3` / `B::poseidon2_t2`).

pub(crate) use openvm_stark_sdk::config::baby_bear_bn254_poseidon2::{
    BABY_BEAR_RATE as MULTI_FIELD32_RATE, BN254_RATE as POSEIDON2_RATE, DIGEST_WIDTH,
};

use halo2_base::halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};

use crate::{backend::Backend, wire::ReducedWire};

pub(crate) const MULTI_FIELD32_NUM_F_ELMS: usize = MULTI_FIELD32_RATE / POSEIDON2_RATE;

pub(crate) fn pack_base_2_31_cells<B: Backend>(
    ctx: &mut B::Ctx,
    values: &[ReducedWire<B>],
) -> B::V {
    assert!(values.len() <= MULTI_FIELD32_NUM_F_ELMS);
    let base = Fr::from(1u64 << 31);
    let mut acc = B::constant(ctx, Fr::ZERO);
    let mut pow = Fr::from(1u64);
    for v in values {
        let pow_val = B::constant(ctx, pow);
        let term = B::mul(ctx, v.value(), pow_val);
        acc = B::add(ctx, acc, term);
        pow *= base;
    }
    acc
}

pub(crate) fn hash_babybear_slice_to_digest<B: Backend>(
    ctx: &mut B::Ctx,
    values: &[ReducedWire<B>],
) -> B::V {
    let zero = B::constant(ctx, Fr::ZERO);
    let mut state = [zero; super::POSEIDON2_WIDTH];
    for block_chunk in values.chunks(MULTI_FIELD32_RATE) {
        for (chunk_id, chunk) in block_chunk.chunks(MULTI_FIELD32_NUM_F_ELMS).enumerate() {
            state[chunk_id] = pack_base_2_31_cells::<B>(ctx, chunk);
        }
        state = B::poseidon2_t3(ctx, state);
    }
    state[0]
}

pub(crate) fn compress_bn254_digests<B: Backend>(
    ctx: &mut B::Ctx,
    left: B::V,
    right: B::V,
) -> B::V {
    let out = B::poseidon2_t2(ctx, [left, right]);
    out[0]
}
