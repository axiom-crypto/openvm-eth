//! Types for the standard zkVM accelerator C interface.

pub type zkvm_status = core::ffi::c_int;

pub const ZKVM_EOK: zkvm_status = 0;
pub const ZKVM_EFAIL: zkvm_status = -1;

/// Panics because `function` was called with a NULL pointer.
///
/// The interface says that a function called with a NULL pointer SHOULD panic. A NULL buffer
/// pointer with a zero length does not get here: this crate treats it as an empty buffer.
#[cold]
#[inline(never)]
pub(crate) fn null_pointer(function: &str) -> ! {
    panic!("{function}: NULL pointer argument")
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug)]
pub struct ZkvmBytes<const N: usize> {
    pub data: [u8; N],
}
