//! C ABI for modular exponentiation.

use crate::{ops, types::ZkvmStatus};

/// Compute `base[..base_len] ^ exp[..exp_len] % modulus[..mod_len]` into
/// `output`, which receives exactly `mod_len` bytes, left-padded with zeros.
///
/// Returns [`ZkvmStatus::Fail`] if any pointer is NULL while its length is
/// non-zero; a NULL pointer with a zero length is the empty input.
///
/// # Safety
///
/// - `base`, `exp` and `modulus`, if non-NULL, must be valid for reads of their respective lengths.
/// - `output`, if non-NULL, must be valid for writes of `mod_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_modexp(
    base: *const u8,
    base_len: usize,
    exp: *const u8,
    exp_len: usize,
    modulus: *const u8,
    mod_len: usize,
    output: *mut u8,
) -> ZkvmStatus {
    if (base.is_null() && base_len != 0) ||
        (exp.is_null() && exp_len != 0) ||
        (modulus.is_null() && mod_len != 0) ||
        (output.is_null() && mod_len != 0)
    {
        return ZkvmStatus::Fail;
    }
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let base =
        if base_len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(base, base_len) } };
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let exp = if exp_len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(exp, exp_len) } };
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let modulus =
        if mod_len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(modulus, mod_len) } };
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let output = if mod_len == 0 {
        &mut [][..]
    } else {
        unsafe { core::slice::from_raw_parts_mut(output, mod_len) }
    };
    ops::modexp(base, exp, modulus, output);
    ZkvmStatus::Ok
}
