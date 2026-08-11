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
    if h.is_null() || m.is_null() || t.is_null() || f > 1 {
        return ZkvmStatus::Fail;
    }
    // SAFETY: the non-NULL inputs are valid for reads. Copy before writing to support overlap.
    let (state, message, offset) = unsafe { (h.read(), m.read(), t.read()) };

    let mut state_words = [0; 8];
    for (word, bytes) in state_words.iter_mut().zip(state.data.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*bytes);
    }
    let mut message_words = [0; 16];
    for (word, bytes) in message_words.iter_mut().zip(message.data.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*bytes);
    }
    let offset_words = [
        u64::from_le_bytes(offset.data[..8].try_into().unwrap()),
        u64::from_le_bytes(offset.data[8..].try_into().unwrap()),
    ];

    ops::blake2f(rounds, &mut state_words, &message_words, &offset_words, f == 1);

    let mut value = ZkvmBlake2fState { data: [0; 64] };
    for (bytes, word) in value.data.as_chunks_mut::<8>().0.iter_mut().zip(state_words) {
        *bytes = word.to_le_bytes();
    }
    // SAFETY: `h` is non-NULL and valid for writes.
    unsafe { h.write(value) };
    ZkvmStatus::Ok
}
