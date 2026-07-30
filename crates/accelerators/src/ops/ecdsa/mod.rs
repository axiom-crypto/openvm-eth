//! ECDSA operations.
//!
//! Split by curve: the two crates providing them use the same type names, and
//! secp256k1 additionally needs a guest/host split that secp256r1 does not.

mod secp256k1;
mod secp256r1;

pub use secp256k1::{secp256k1_ecrecover, secp256k1_verify};
pub use secp256r1::secp256r1_verify;
