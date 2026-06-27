//! Thin Ed25519 sign/verify primitives.
//!
//! What gets signed and how the payload is constructed is the server's
//! responsibility; this module provides only the raw cryptographic operations.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Sign `payload` with `signing_key`.  Returns the 64-byte signature.
pub fn sign_seal(signing_key: &SigningKey, payload: &[u8]) -> Vec<u8> {
    signing_key.sign(payload).to_bytes().to_vec()
}

/// Return `true` if `sig` is a valid Ed25519 signature of `payload` under
/// `verifying_key`.
pub fn verify_seal(verifying_key: &VerifyingKey, payload: &[u8], sig: &[u8]) -> bool {
    let Ok(signature) = Signature::from_slice(sig) else {
        return false;
    };
    verifying_key.verify(payload, &signature).is_ok()
}

// ---------------------------------------------------------------------------
// Inline unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn make_signing_key() -> SigningKey {
        // Deterministic seed for tests.
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn test_seal_roundtrip() {
        let sk = make_signing_key();
        let vk = sk.verifying_key();
        let payload = b"soma-audit seal test payload";

        let sig = sign_seal(&sk, payload);
        assert!(verify_seal(&vk, payload, &sig));
    }

    #[test]
    fn test_verify_seal_wrong_payload() {
        let sk = make_signing_key();
        let vk = sk.verifying_key();
        let payload = b"correct payload";
        let sig = sign_seal(&sk, payload);

        assert!(!verify_seal(&vk, b"wrong payload", &sig));
    }

    #[test]
    fn test_verify_seal_wrong_key() {
        let sk1 = make_signing_key();
        let sk2 = SigningKey::from_bytes(&[9u8; 32]);
        let vk2 = sk2.verifying_key();
        let payload = b"payload";
        let sig = sign_seal(&sk1, payload);
        // Signature made with sk1 must not verify under vk2.
        assert!(!verify_seal(&vk2, payload, &sig));
    }
}
