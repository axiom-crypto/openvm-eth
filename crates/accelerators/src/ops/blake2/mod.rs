//! BLAKE2b compression function F (EIP-152).
//!
//! Vendored from revm-precompile, which adapted the compression function from
//! [`blake2b_simd`](https://github.com/oconnor663/blake2_simd) (MIT license)
//! for EIP-152 variable round counts.

mod portable;

use crate::{
    ops::Error,
    types::{ZkvmBlake2fMessage, ZkvmBlake2fOffset, ZkvmBlake2fState},
};

type Word = u64;

const IV: [Word; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

// SIGMA has spec period 10 (RFC 7693 §2.7). BLAKE2b runs 12 rounds by reusing
// SIGMA[0]/SIGMA[1] for rounds 10/11; for EIP-152's variable round count we
// must index with `r % 10`, not `r % 12`.
const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Apply the BLAKE2 compression function F to the state vector `h` in place.
///
/// `h`, `m` and `t` hold little-endian words; `f` is the final-block
/// indicator and must be `0` or `1`.
pub fn blake2f(
    rounds: u32,
    h: &mut ZkvmBlake2fState,
    m: &ZkvmBlake2fMessage,
    t: &ZkvmBlake2fOffset,
    f: u8,
) -> Result<(), Error> {
    if f > 1 {
        return Err(Error::InvalidFinalFlag);
    }

    let mut state = [0u64; 8];
    for (word, chunk) in state.iter_mut().zip(h.data.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let mut message = [0u64; 16];
    for (word, chunk) in message.iter_mut().zip(m.data.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let offset = [
        u64::from_le_bytes(t.data[..8].try_into().unwrap()),
        u64::from_le_bytes(t.data[8..].try_into().unwrap()),
    ];

    portable::compress(rounds, &mut state, &message, &offset, f == 1);

    for (chunk, word) in h.data.chunks_exact_mut(8).zip(state.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    Ok(())
}
