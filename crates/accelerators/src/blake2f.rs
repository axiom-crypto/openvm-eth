//! BLAKE2b compression function F (EIP-152).
//!
//! Operates on raw BLAKE2b state with an arbitrary round count.

// Ported from revm-precompile 36.0.3's EIP-152 adaptation:
// https://docs.rs/crate/revm-precompile/36.0.3/source/src/blake2/portable.rs
// That implementation is adapted from blake2b_simd:
// https://github.com/oconnor663/blake2_simd
//
// Copyright (c) 2018 Jack O'Connor
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::types::{zkvm_status, ZkvmBytes, ZKVM_EFAIL, ZKVM_EOK};

pub type zkvm_blake2f_state = ZkvmBytes<64>;
pub type zkvm_blake2f_message = ZkvmBytes<128>;
pub type zkvm_blake2f_offset = ZkvmBytes<16>;

/// Apply BLAKE2 compression function F to `h` in place.
///
/// # Safety
///
/// - `h` must be valid for reads and writes of one [`zkvm_blake2f_state`].
/// - `m` must be valid for reads of one [`zkvm_blake2f_message`].
/// - `t` must be valid for reads of one [`zkvm_blake2f_offset`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_blake2f(
    rounds: u32,
    h: *mut zkvm_blake2f_state,
    m: *const zkvm_blake2f_message,
    t: *const zkvm_blake2f_offset,
    f: u8,
) -> zkvm_status {
    if h.is_null() || m.is_null() || t.is_null() || f > 1 {
        return ZKVM_EFAIL;
    }

    // SAFETY: the non-null inputs satisfy the function's pointer requirements.
    // Read every input before writing `h` so overlapping arguments are supported.
    let (state, message, offset) = unsafe { (h.read(), m.read(), t.read()) };

    let mut state_words = [0; 8];
    for (word, bytes) in state_words.iter_mut().zip(state.data.as_chunks::<8>().0) {
        *word = Word::from_le_bytes(*bytes);
    }
    let mut message_words = [0; 16];
    for (word, bytes) in message_words.iter_mut().zip(message.data.as_chunks::<8>().0) {
        *word = Word::from_le_bytes(*bytes);
    }
    let offset_words = [
        Word::from_le_bytes(offset.data[..8].try_into().unwrap()),
        Word::from_le_bytes(offset.data[8..].try_into().unwrap()),
    ];

    compress(rounds, &mut state_words, &message_words, &offset_words, f == 1);

    let mut value = zkvm_blake2f_state { data: [0; 64] };
    for (bytes, word) in value.data.as_chunks_mut::<8>().0.iter_mut().zip(state_words) {
        *bytes = word.to_le_bytes();
    }

    // SAFETY: `h` satisfies the function's write requirement; all reads are complete.
    unsafe { h.write(value) };
    ZKVM_EOK
}

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

// The message schedule has period 10 (RFC 7693 section 2.7). EIP-152 permits
// arbitrary round counts, so rounds beyond the standard 12 must use `r % 10`.
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

#[inline(always)]
const fn g(v: &mut [Word; 16], a: usize, b: usize, c: usize, d: usize, x: Word, y: Word) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[inline(always)]
const fn round(round: usize, m: &[Word; 16], v: &mut [Word; 16]) {
    let schedule = SIGMA[round % SIGMA.len()];

    g(v, 0, 4, 8, 12, m[schedule[0] as usize], m[schedule[1] as usize]);
    g(v, 1, 5, 9, 13, m[schedule[2] as usize], m[schedule[3] as usize]);
    g(v, 2, 6, 10, 14, m[schedule[4] as usize], m[schedule[5] as usize]);
    g(v, 3, 7, 11, 15, m[schedule[6] as usize], m[schedule[7] as usize]);

    g(v, 0, 5, 10, 15, m[schedule[8] as usize], m[schedule[9] as usize]);
    g(v, 1, 6, 11, 12, m[schedule[10] as usize], m[schedule[11] as usize]);
    g(v, 2, 7, 8, 13, m[schedule[12] as usize], m[schedule[13] as usize]);
    g(v, 3, 4, 9, 14, m[schedule[14] as usize], m[schedule[15] as usize]);
}

fn compress(rounds: u32, h: &mut [Word; 8], m: &[Word; 16], t: &[Word; 2], f: bool) {
    let mut v = [
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        IV[4] ^ t[0],
        IV[5] ^ t[1],
        IV[6] ^ if f { Word::MAX } else { 0 },
        IV[7],
    ];

    for round_index in 0..rounds as usize {
        round(round_index, m, &mut v);
    }

    for (index, word) in h.iter_mut().enumerate() {
        *word ^= v[index] ^ v[index + 8];
    }
}
