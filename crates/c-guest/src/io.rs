//! The zkevm-standards I/O interface (`zkvm_io.h`).
//!
//! The private input is the first vector of the OpenVM input stream (on the host,
//! `StdIn::write_bytes`). [`read_input`] reads it on its first call and returns the same buffer on
//! every call. The host must write that vector, empty if there is no input: OpenVM fails the
//! execution when a guest reads an input stream that has no vector left.
//!
//! The public output is OpenVM's user public values, from byte 0 on. [`write_output`] reveals only
//! the 8-byte words that a call writes, so the output can fill all the public values of the VM
//! configuration (`SystemConfig::with_public_values`, in bytes; OpenVM's default is 32 bytes). A
//! longer output fails the execution.

use alloc::vec::Vec;

/// The private input, read by the first [`read_input`] call.
static mut INPUT: Option<Vec<u8>> = None;
/// The number of output bytes written so far.
static mut OUTPUT_LEN: usize = 0;
/// The bytes of the partly written last output word, little-endian.
static mut OUTPUT_TAIL: u64 = 0;

/// Sets `*buf_ptr` and `*buf_size` to the private input.
///
/// # Safety
///
/// `buf_ptr` and `buf_size` must be valid for writes. The guest is single-threaded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn read_input(buf_ptr: *mut *const u8, buf_size: *mut usize) {
    // SAFETY: the guest is single-threaded, so nothing else accesses `INPUT`.
    let input = unsafe { (*&raw mut INPUT).get_or_insert_with(openvm::io::read_vec) };
    // SAFETY: the caller guarantees that both pointers are valid for writes.
    unsafe {
        buf_ptr.write(input.as_ptr());
        buf_size.write(input.len());
    }
}

/// Appends `output[..size]` to the public output.
///
/// The interface doesn't treat NULL specially, so `output` may be NULL (address 0, which OpenVM
/// lets programs read).
///
/// # Safety
///
/// The `size` bytes from `output` must be readable memory; any pointer is valid when `size` is 0.
/// The guest is single-threaded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn write_output(output: *const u8, size: usize) {
    // SAFETY: the guest is single-threaded, so nothing else accesses the output state.
    let (mut len, mut tail) = unsafe { (OUTPUT_LEN, OUTPUT_TAIL) };
    for i in 0..size {
        // SAFETY: the caller guarantees that the `size` bytes from `output` are readable.
        let byte = unsafe { read_byte(output.wrapping_add(i)) };
        tail |= u64::from(byte) << (8 * (len % 8));
        len += 1;
        if len % 8 == 0 {
            openvm::io::reveal_u64(tail, len / 8 - 1);
            tail = 0;
        }
    }
    // Reveal the partly written last word. The next call that writes to it reveals it again, and
    // the later reveal replaces this one.
    if len % 8 != 0 {
        openvm::io::reveal_u64(tail, len / 8);
    }
    // SAFETY: as above.
    unsafe {
        OUTPUT_LEN = len;
        OUTPUT_TAIL = tail;
    }
}

/// Reads the byte at `address`, which may be 0.
///
/// The load is an `asm!` instruction, not a Rust read: a Rust read of address 0 is undefined
/// behavior, while `write_output` must read any readable address.
///
/// # Safety
///
/// The byte at `address` must be readable.
#[inline(always)]
unsafe fn read_byte(address: *const u8) -> u8 {
    let byte: u8;
    // SAFETY: the caller guarantees that the byte is readable.
    unsafe {
        core::arch::asm!(
            "lbu {0}, 0({1})",
            out(reg) byte,
            in(reg) address,
            options(nostack, readonly, preserves_flags),
        );
    }
    byte
}
