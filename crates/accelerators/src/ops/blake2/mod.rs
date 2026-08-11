//! BLAKE2b compression function F (EIP-152).
//!
//! Uses REVM's EIP-152 implementation so the standard interface and REVM's
//! precompile provider share one compression function.

use crate::{
    ops::Error,
    types::{ZkvmBlake2fMessage, ZkvmBlake2fOffset, ZkvmBlake2fState},
};

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

    blake2f_words(rounds, &mut state, &message, &offset, f == 1);

    for (chunk, word) in h.data.chunks_exact_mut(8).zip(state.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    Ok(())
}

/// Apply BLAKE2 compression to word-oriented state without byte conversion.
#[inline]
pub fn blake2f_words(rounds: u32, h: &mut [u64; 8], m: &[u64; 16], t: &[u64; 2], f: bool) {
    revm_precompile::blake2::compress(rounds, h, m, t, f);
}
