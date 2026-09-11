//! RIPEMD-160 C-interface conformance vectors.

use hex_literal::hex;
use openvm_accelerators::{zkvm_ripemd160, zkvm_ripemd160_hash, ZKVM_EFAIL, ZKVM_EOK};

#[test]
fn ripemd160_abc() {
    let data = *b"abc";
    let mut output = zkvm_ripemd160_hash { data: [0xff; 32] };
    let status = unsafe { zkvm_ripemd160(data.as_ptr(), data.len(), &mut output) };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(
        output.data,
        hex!("0000000000000000000000008eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
    );
}

#[test]
fn ripemd160_null_pointers() {
    let data = *b"abc";
    let mut output = zkvm_ripemd160_hash { data: [0xff; 32] };

    // A NULL `data` with `len == 0` is the empty input.
    let status = unsafe { zkvm_ripemd160(core::ptr::null(), 0, &mut output) };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(
        output.data,
        hex!("0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31")
    );

    let status = unsafe { zkvm_ripemd160(core::ptr::null(), data.len(), &mut output) };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe { zkvm_ripemd160(data.as_ptr(), data.len(), core::ptr::null_mut()) };
    assert_eq!(status, ZKVM_EFAIL);
}
