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
    use std::sync::Arc;

    /// OpenVM k256 backend for Alloy crypto operations (transaction validation)
    #[derive(Debug, Default)]
    struct OpenVmK256Provider;

    impl CryptoProvider for OpenVmK256Provider {
        fn recover_signer_unchecked(
            &self,
            sig: &[u8; 65],
            msg: &[u8; 32],
        ) -> Result<Address, RecoveryError> {
            // Extract components: sig[0..32]=r, sig[32..64]=s, sig[64]=recovery_id
            // Parse signature using OpenVM k256
            let mut signature =
                Signature::from_slice(&sig[..64]).map_err(|_| RecoveryError::new())?;

            // Normalize signature if needed
            let mut recid = sig[64];
            if let Some(sig_normalized) = signature.normalize_s() {
                signature = sig_normalized;
                recid ^= 1;
            }

            // Create recovery ID
            let recovery_id = RecoveryId::from_byte(recid).ok_or(RecoveryError::new())?;

            // Recover public key using OpenVM
            let recovered_key = VerifyingKey::recover_from_prehash_noverify(
                msg,
                &signature.to_bytes(),
                recovery_id,
            )
            .map_err(|_| RecoveryError::new())?;

            // Hash the uncompressed SEC1 key without the 0x04 prefix.
            let public_key = recovered_key.to_encoded_point(false);
            let encoded_pubkey = &public_key.as_bytes()[1..65];

            // Hash to get Ethereum address
            let pubkey_hash = keccak256(encoded_pubkey);
            let address_bytes = &pubkey_hash[12..32]; // Last 20 bytes

            Ok(Address::from_slice(address_bytes))
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

    pub(crate) fn install_alloy_provider() -> Result<(), Box<dyn std::error::Error>> {
        install_default_provider(Arc::new(OpenVmK256Provider))?;
        Ok(())
    }

    pub(crate) fn secp256k1_ecrecover(
        sig_bytes: &[u8; 64],
        mut recid: u8,
        msg_hash: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        let mut sig = Signature::from_slice(sig_bytes)
            .map_err(|_| PrecompileHalt::other("Invalid signature format"))?;

        if let Some(sig_normalized) = sig.normalize_s() {
            sig = sig_normalized;
            recid ^= 1;
        }

        let recovery_id = RecoveryId::from_byte(recid)
            .ok_or_else(|| PrecompileHalt::other("Invalid recovery ID"))?;

        let recovered_key =
            VerifyingKey::recover_from_prehash_noverify(msg_hash, &sig.to_bytes(), recovery_id)
                .map_err(|_| PrecompileHalt::other("Key recovery failed"))?;

        let public_key = recovered_key.to_encoded_point(false);
        let encoded_pubkey = &public_key.as_bytes()[1..65];

        let pubkey_hash = keccak256(encoded_pubkey);
        let mut address = [0u8; 32];
        address[12..].copy_from_slice(&pubkey_hash[12..]);

        Ok(address)
    }
}

pub(super) use backend::{install_alloy_provider, secp256k1_ecrecover};
