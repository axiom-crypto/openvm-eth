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
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let (h, m, t) = unsafe { (&mut *h, &*m, &*t) };
    match ops::blake2f(rounds, h, m, t, f) {
        Ok(()) => ZkvmStatus::Ok,
        Err(_) => ZkvmStatus::Fail,
    }
}
