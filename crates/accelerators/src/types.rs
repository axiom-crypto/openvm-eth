//! Types for the standard zkVM accelerator C interface.

pub type zkvm_status = core::ffi::c_int;

pub const ZKVM_EOK: zkvm_status = 0;
pub const ZKVM_EFAIL: zkvm_status = -1;

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug)]
pub struct ZkvmBytes<const N: usize> {
    pub data: [u8; N],
}
