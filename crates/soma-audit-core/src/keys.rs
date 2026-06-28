//! Per-tenant HMAC key derivation.
//!
//! A separate key is derived for each tenant using HKDF-SHA256.  If a single
//! tenant's key is ever compromised, only that tenant's chain is affected;
//! the master secret and all other tenants remain safe.

use uuid::Uuid;
use zeroize::Zeroizing;

/// Derive a 32-byte HMAC key for `tenant_id` from `master_secret`.
///
/// Algorithm: HKDF-SHA256(IKM=master_secret, salt=None,
///            info=b"soma-audit-hmac-v1" ++ tenant_id.as_bytes())
pub fn derive_tenant_hmac_key(master_secret: &[u8; 32], tenant_id: Uuid) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(18 + 16);
    info.extend_from_slice(b"soma-audit-hmac-v1");
    info.extend_from_slice(tenant_id.as_bytes());

    let vec = soma_infra::crypto::hkdf_sha256(master_secret, None, &info, 32)
        .expect("32 bytes is within HKDF output limit");
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&vec);
    out
}

// ---------------------------------------------------------------------------
// Inline unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_per_tenant_keys_differ() {
        let master = [0u8; 32];
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let k1 = derive_tenant_hmac_key(&master, t1);
        let k2 = derive_tenant_hmac_key(&master, t2);
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn test_key_is_deterministic() {
        let master = [42u8; 32];
        let tenant = Uuid::new_v4();
        let k1 = derive_tenant_hmac_key(&master, tenant);
        let k2 = derive_tenant_hmac_key(&master, tenant);
        assert_eq!(*k1, *k2);
    }
}
