//! Word-at-a-time `memcmp`/`bcmp` for the guest.
//!
//! `openvm` ships optimized `memcpy`/`memset` assembly, but `memcmp` falls
//! back to compiler-builtins' byte-at-a-time loop, which costs several
//! instructions per byte on rv32. Slice equality on byte-array types (`U256`
//! words in the EVM interpreter, hashes, RLP node references) lowers to
//! `memcmp`/`bcmp` calls, making this one of the hottest functions in the
//! guest. The strong symbols defined here override compiler-builtins' weak
//! definitions at link time.
//!
//! `#![no_builtins]` prevents LLVM from recognizing the comparison loop as a
//! memcmp idiom and lowering it back into a `memcmp` libcall.

#![no_std]
#![no_builtins]

// The word-compare path derives the first differing byte from the least
// significant differing bits, which is only correct on little-endian targets.
const _: () = assert!(cfg!(target_endian = "little"));

const WORD: usize = core::mem::size_of::<usize>();

/// Compares `n` bytes at `a` and `b` with C `memcmp` semantics, reading a
/// word at a time when both pointers share the same alignment.
///
/// # Safety
///
/// `a` and `b` must be valid for reads of `n` bytes.
pub unsafe fn compare_bytes(mut a: *const u8, mut b: *const u8, mut n: usize) -> i32 {
    unsafe {
        if a.addr() % WORD == b.addr() % WORD {
            while a.addr() % WORD != 0 && n > 0 {
                let (x, y) = (*a, *b);
                if x != y {
                    return i32::from(x) - i32::from(y);
                }
                a = a.add(1);
                b = b.add(1);
                n -= 1;
            }
            while n >= WORD {
                let x = *a.cast::<usize>();
                let y = *b.cast::<usize>();
                if x != y {
                    // Little-endian: the lowest differing byte address holds
                    // the least significant differing byte of the word.
                    let shift = ((x ^ y).trailing_zeros() / 8) * 8;
                    return i32::from((x >> shift) as u8) - i32::from((y >> shift) as u8);
                }
                a = a.add(WORD);
                b = b.add(WORD);
                n -= WORD;
            }
        }
        while n > 0 {
            let (x, y) = (*a, *b);
            if x != y {
                return i32::from(x) - i32::from(y);
            }
            a = a.add(1);
            b = b.add(1);
            n -= 1;
        }
        0
    }
}

#[cfg(target_os = "openvm")]
mod c_exports {
    #[unsafe(no_mangle)]
    unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
        unsafe { super::compare_bytes(a, b, n) }
    }

    // Equality-only variant of `memcmp`; the compiler emits calls to it for
    // slice `==` where the ordering is unused.
    #[unsafe(no_mangle)]
    unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
        unsafe { super::compare_bytes(a, b, n) }
    }
}

#[cfg(test)]
mod tests {
    use super::compare_bytes;

    fn reference(a: &[u8], b: &[u8]) -> i32 {
        for (x, y) in core::iter::zip(a, b) {
            if x != y {
                return i32::from(*x) - i32::from(*y);
            }
        }
        0
    }

    #[test]
    fn matches_reference_across_alignments_lengths_and_diff_positions() {
        let mut base = [0u8; 96];
        for (i, byte) in base.iter_mut().enumerate() {
            *byte = (i * 37 % 251) as u8;
        }
        for a_off in 0..8 {
            for b_off in 0..8 {
                for len in 0..48 {
                    let a = &base[a_off..a_off + len];
                    let mut b_buf = [0u8; 96];
                    b_buf[b_off..b_off + len].copy_from_slice(a);
                    // diff_pos == len leaves the buffers equal.
                    for diff_pos in 0..=len {
                        let mut b_buf = b_buf;
                        if diff_pos < len {
                            b_buf[b_off + diff_pos] ^= 0x80;
                        }
                        let b = &b_buf[b_off..b_off + len];
                        let got = unsafe { compare_bytes(a.as_ptr(), b.as_ptr(), len) };
                        assert_eq!(
                            got,
                            reference(a, b),
                            "a_off={a_off} b_off={b_off} len={len} diff_pos={diff_pos}"
                        );
                    }
                }
            }
        }
    }
}
