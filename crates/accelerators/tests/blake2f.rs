//! BLAKE2f conformance using the official EIP-152 test vectors 4-7.

use hex_literal::hex;
use openvm_accelerators::{
    zkvm_blake2f, zkvm_blake2f_message, zkvm_blake2f_offset, zkvm_blake2f_state, ZKVM_EFAIL,
    ZKVM_EOK,
};

/// EIP-152 vectors 4-7 share the same h, m and t inputs.
const H: [u8; 64] = hex!(
    "48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5"
    "d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b"
);
const T: [u8; 16] = hex!("03000000000000000000000000000000");

fn m() -> zkvm_blake2f_message {
    let mut m = zkvm_blake2f_message { data: [0; 128] };
    m.data[..3].copy_from_slice(b"abc");
    m
}

fn check(rounds: u32, f: u8, expected: [u8; 64]) {
    let mut h = zkvm_blake2f_state { data: H };
    let m = m();
    let t = zkvm_blake2f_offset { data: T };

    let status = unsafe { zkvm_blake2f(rounds, &mut h, &m, &t, f) };
    assert_eq!(status, ZKVM_EOK, "rounds={rounds}, f={f}");
    assert_eq!(h.data, expected, "rounds={rounds}, f={f}");
}

#[test]
fn blake2f_eip152_vector_4_zero_rounds() {
    check(
        0,
        1,
        hex!(
            "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5"
            "d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b"
        ),
    );
}

#[test]
fn blake2f_eip152_vector_5_twelve_rounds() {
    check(
        12,
        1,
        hex!(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        ),
    );
}

#[test]
fn blake2f_eip152_vector_6_no_final_flag() {
    check(
        12,
        0,
        hex!(
            "75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d28752"
            "98743e7f6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735"
        ),
    );
}

#[test]
fn blake2f_eip152_vector_7_one_round() {
    check(
        1,
        1,
        hex!(
            "b63a380cb2897d521994a85234ee2c181b5f844d2c624c002677e9703449d2fb"
            "a551b3a8333bcdf5f2f7e08993d53923de3d64fcc68c034e717b9293fed7a421"
        ),
    );
}

#[test]
fn zkvm_blake2f_invalid_final_flag_preserves_state() {
    let mut h = zkvm_blake2f_state { data: H };
    let m = m();
    let t = zkvm_blake2f_offset { data: T };

    let status = unsafe { zkvm_blake2f(12, &mut h, &m, &t, 2) };
    assert_eq!(status, ZKVM_EFAIL);
    assert_eq!(h.data, H);
}

#[test]
fn zkvm_blake2f_null_pointers() {
    let mut h = zkvm_blake2f_state { data: H };
    let m = m();
    let t = zkvm_blake2f_offset { data: T };

    let status = unsafe { zkvm_blake2f(12, core::ptr::null_mut(), &m, &t, 1) };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe { zkvm_blake2f(12, &mut h, core::ptr::null(), &t, 1) };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe { zkvm_blake2f(12, &mut h, &m, core::ptr::null(), 1) };
    assert_eq!(status, ZKVM_EFAIL);
    // The state must be untouched when a pointer is NULL.
    assert_eq!(h.data, H);
}
