// Ported from revm-precompile 36.0.3's EIP-152 adaptation:
// https://docs.rs/crate/revm-precompile/36.0.3/source/src/blake2/portable.rs
// That implementation is adapted from blake2b_simd:
// https://github.com/oconnor663/blake2_simd
//
// Copyright (c) 2018 Jack O'Connor
// Copyright (c) 2021-2026 draganrakita
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

use super::{Word, IV, SIGMA};

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

pub(super) fn compress(rounds: u32, h: &mut [Word; 8], m: &[Word; 16], t: &[Word; 2], f: bool) {
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
