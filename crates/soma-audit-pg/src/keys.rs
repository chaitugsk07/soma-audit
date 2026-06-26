use ed25519_dalek::SigningKey;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::AuditPgError;

pub struct AuditKeys {
    master_secret: Zeroizing<[u8; 32]>,
    signing_key: SigningKey,
}

impl std::fmt::Debug for AuditKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omit secrets from Debug output.
        f.debug_struct("AuditKeys")
            .field("signing_key", &"[redacted]")
            .field("master_secret", &"[redacted]")
            .finish()
    }
}

impl AuditKeys {
    pub fn from_secret(master_secret: [u8; 32], signing_key: [u8; 32]) -> Self {
        Self {
            master_secret: Zeroizing::new(master_secret),
            signing_key: SigningKey::from_bytes(&signing_key),
        }
    }

    pub fn from_env() -> Result<Self, AuditPgError> {
        let master_hex = std::env::var("SOMA_AUDIT_MASTER_SECRET")
            .map_err(|_| AuditPgError::Env("SOMA_AUDIT_MASTER_SECRET not set".into()))?;
        let signing_hex = std::env::var("SOMA_AUDIT_SIGNING_KEY")
            .map_err(|_| AuditPgError::Env("SOMA_AUDIT_SIGNING_KEY not set".into()))?;

        let master = decode_hex_32(&master_hex)
            .map_err(|e| AuditPgError::Env(format!("SOMA_AUDIT_MASTER_SECRET: {e}")))?;
        let signing = decode_hex_32(&signing_hex)
            .map_err(|e| AuditPgError::Env(format!("SOMA_AUDIT_SIGNING_KEY: {e}")))?;

        Ok(Self::from_secret(master, signing))
    }

    pub(crate) fn hmac_key(&self, tenant_id: Uuid) -> Zeroizing<[u8; 32]> {
        soma_audit_core::derive_tenant_hmac_key(&self.master_secret, tenant_id)
    }

    #[allow(dead_code)]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    #[allow(dead_code)]
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

fn decode_hex_32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars (32 bytes), got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", b as char)),
    }
}

/// Fold a tenant UUID's u128 into an i64 advisory lock key.
/// XOR high and low 64-bit halves for better entropy than first-8-bytes.
pub(crate) fn tenant_lock_key(tenant_id: Uuid) -> i64 {
    let n = tenant_id.as_u128();
    let hi = (n >> 64) as u64;
    let lo = n as u64;
    (hi ^ lo) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    /// Mutex to prevent env var races between tests that use SOMA_AUDIT_*.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env<F: FnOnce()>(master: &str, signing: &str, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        #[allow(deprecated)]
        env::set_var("SOMA_AUDIT_MASTER_SECRET", master);
        #[allow(deprecated)]
        env::set_var("SOMA_AUDIT_SIGNING_KEY", signing);
        f();
    }

    #[test]
    fn test_from_env_valid() {
        with_env(&"a".repeat(64), &"b".repeat(64), || {
            assert!(AuditKeys::from_env().is_ok());
        });
    }

    #[test]
    fn test_from_env_wrong_length() {
        with_env(&"aa".repeat(31), &"bb".repeat(32), || {
            let err = AuditKeys::from_env().unwrap_err();
            assert!(err.to_string().contains("64 hex chars"));
        });
    }

    #[test]
    fn test_from_env_non_hex() {
        with_env(&"zz".repeat(32), &"bb".repeat(32), || {
            let err = AuditKeys::from_env().unwrap_err();
            assert!(err.to_string().contains("invalid hex"));
        });
    }

    #[test]
    fn test_lock_key_deterministic() {
        let id = Uuid::new_v4();
        assert_eq!(tenant_lock_key(id), tenant_lock_key(id));
    }

    #[test]
    fn test_lock_key_different_tenants() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_ne!(tenant_lock_key(a), tenant_lock_key(b));
    }
}
