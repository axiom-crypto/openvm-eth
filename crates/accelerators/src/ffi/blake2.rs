//! C ABI for the BLAKE2 compression function.

use crate::{
    ops,
    types::{ZkvmBlake2fMessage, ZkvmBlake2fOffset, ZkvmBlake2fState, ZkvmStatus},
};

/// Apply the BLAKE2 compression function F (EIP-152) to `h` in place.
///
/// Returns [`ZkvmStatus::Fail`] if any pointer is NULL, or if `f` is neither
/// 0 nor 1.
///
/// # Safety
///
/// - `h`, if non-NULL, must be valid for reads and writes of 64 bytes.
/// - `m`, if non-NULL, must be valid for reads of 128 bytes.
/// - `t`, if non-NULL, must be valid for reads of 16 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_blake2f(
    rounds: u32,
    h: *mut ZkvmBlake2fState,
    m: *const ZkvmBlake2fMessage,
    t: *const ZkvmBlake2fOffset,
    f: u8,
) -> ZkvmStatus {
    if h.is_null() || m.is_null() || t.is_null() {
        return ZkvmStatus::Fail;
    }
    // SAFETY: the non-NULL inputs are valid for reads. Copy before writing to support overlap.
    let (mut state, message, offset) = unsafe { (h.read(), m.read(), t.read()) };
    if ops::blake2f(rounds, &mut state, &message, &offset, f).is_err() {
        return ZkvmStatus::Fail;
    }
    // SAFETY: `h` is non-NULL and valid for writes.
    unsafe { h.write(state) };
    ZkvmStatus::Ok
}
