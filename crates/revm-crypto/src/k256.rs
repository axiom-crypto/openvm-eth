#[cfg(all(not(target_os = "zkvm"), feature = "native-k256"))]
mod backend {
    use revm::precompile::{Crypto, DefaultCrypto, PrecompileHalt};

    pub(crate) fn install_alloy_provider() -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    pub(crate) fn secp256k1_ecrecover(
        sig_bytes: &[u8; 64],
        recid: u8,
        msg_hash: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        DefaultCrypto.secp256k1_ecrecover(sig_bytes, recid, msg_hash)
    }
}

#[cfg(not(all(not(target_os = "zkvm"), feature = "native-k256")))]
mod backend {
    use alloc::{boxed::Box, sync::Arc};
    use alloy_consensus::crypto::{
        backend::{install_default_provider, CryptoProvider},
        RecoveryError,
    };
    use alloy_primitives::Address;
    use openvm_k256::ecdsa::{
        signature::hazmat::PrehashVerifier, RecoveryId, Signature, VerifyingKey,
    };
    use openvm_keccak256::keccak256;
    use revm::precompile::PrecompileHalt;

    /// Recovers a signer's public key hash from a signature over a prehashed message.
    ///
    /// The signer's address is the low 20 bytes of the hash. Returning the hash rather than the
    /// address lets each caller build the output shape it needs — a 20-byte `Address`, or a
    /// 32-byte left-padded precompile word — with a single copy. `None` covers a malformed
    /// signature, a malformed recovery id, and an unrecoverable key; each caller maps it to its
    /// own error type, so no error value is constructed here.
    #[inline(always)]
    fn recovered_pubkey_hash(sig: &[u8], mut recid: u8, msg_hash: &[u8; 32]) -> Option<[u8; 32]> {
        let mut signature = Signature::from_slice(sig).ok()?;

        // A signature with a high `s` is normalized to its low-`s` equivalent, which flips the
        // parity the recovery id encodes.
        if let Some(normalized) = signature.normalize_s() {
            signature = normalized;
            recid ^= 1;
        }

        let recovery_id = RecoveryId::from_byte(recid)?;
        let recovered_key = VerifyingKey::recover_from_prehash_noverify(
            msg_hash,
            &signature.to_bytes(),
            recovery_id,
        )
        .ok()?;

        // The address is derived from the uncompressed SEC1 encoding without its 0x04 prefix.
        let public_key = recovered_key.to_encoded_point(false);
        Some(keccak256(&public_key.as_bytes()[1..65]))
    }

    /// OpenVM k256 backend for Alloy crypto operations (transaction validation)
    #[derive(Debug, Default)]
    struct OpenVmK256Provider;

    impl CryptoProvider for OpenVmK256Provider {
        fn recover_signer_unchecked(
            &self,
            sig: &[u8; 65],
            msg: &[u8; 32],
        ) -> Result<Address, RecoveryError> {
            // sig[0..32]=r, sig[32..64]=s, sig[64]=recovery_id
            let pubkey_hash =
                recovered_pubkey_hash(&sig[..64], sig[64], msg).ok_or_else(RecoveryError::new)?;
            Ok(Address::from_slice(&pubkey_hash[12..32]))
        }

        fn verify_and_compute_signer_unchecked(
            &self,
            pubkey: &[u8; 65],
            sig: &[u8; 64],
            msg: &[u8; 32],
        ) -> Result<Address, RecoveryError> {
            let vk = VerifyingKey::from_sec1_bytes(pubkey).map_err(|_| RecoveryError::new())?;

            let mut signature = Signature::from_slice(sig).map_err(|_| RecoveryError::new())?;
            if let Some(sig_normalized) = signature.normalize_s() {
                signature = sig_normalized;
            }

            vk.verify_prehash(msg.as_ref(), &signature).map_err(|_| RecoveryError::new())?;

            // Compute address directly from the provided pubkey bytes (skip 0x04 prefix)
            let pubkey_hash = keccak256(&pubkey[1..65]);
            Ok(Address::from_slice(&pubkey_hash[12..32]))
        }
    }

    pub(crate) fn install_alloy_provider() -> Result<(), Box<dyn core::error::Error>> {
        install_default_provider(Arc::new(OpenVmK256Provider))?;
        Ok(())
    }

    pub(crate) fn secp256k1_ecrecover(
        sig_bytes: &[u8; 64],
        recid: u8,
        msg_hash: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        let pubkey_hash = recovered_pubkey_hash(sig_bytes, recid, msg_hash)
            .ok_or_else(|| PrecompileHalt::other("secp256k1 signature recovery failed"))?;

        let mut address = [0u8; 32];
        address[12..].copy_from_slice(&pubkey_hash[12..]);

        Ok(address)
    }
}

pub(super) use backend::{install_alloy_provider, secp256k1_ecrecover};
