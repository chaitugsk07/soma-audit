//! Hash-chain math for soma-audit.
//!
//! # Canonical message format
//!
//! Fields are joined with ASCII RS (0x1E), which cannot appear in any of the
//! structured field values (UUIDs, IP addresses, RFC3339 timestamps, enum
//! strings).
//!
//! ## Epoch 1 (13 fields — legacy, no metadata)
//!
//!   seq_num · tenant_id · source_service · event_type · actor_id ·
//!   actor_role · resource_type · resource_id · outcome · actor_ip ·
//!   occurred_at · chain_epoch · prev_hash
//!
//! ## Epoch 2 (14 fields — current, includes metadata)
//!
//!   seq_num · tenant_id · source_service · event_type · actor_id ·
//!   actor_role · resource_type · resource_id · outcome · actor_ip ·
//!   occurred_at · chain_epoch · prev_hash · metadata
//!
//! Changing this format requires bumping `chain_epoch` so old and new records
//! can coexist in the same tenant without confusing the verifier.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::event::{AuditEvent, AuditRecord, Outcome};

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const RS: char = '\x1e';

fn outcome_str(o: Outcome) -> &'static str {
    match o {
        Outcome::Success => "success",
        Outcome::Denied => "denied",
        Outcome::Error => "error",
    }
}

/// Build the deterministic canonical message for a record.
///
/// The format is versioned by `chain_epoch`.  Epoch 1 uses 13 fields (no
/// metadata); epoch 2 adds `metadata` as field 14.  Pass `metadata` as the
/// JSON string of the event's metadata field; it is ignored for epoch 1.
#[allow(clippy::too_many_arguments)]
pub fn canonical_msg(
    seq_num: i64,
    tenant_id: Uuid,
    source_service: &str,
    event_type: &str,
    actor_id: Option<Uuid>,
    actor_role: Option<&str>,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
    outcome: Outcome,
    actor_ip: Option<std::net::IpAddr>,
    occurred_at: DateTime<Utc>,
    chain_epoch: i32,
    prev_hash: Option<&str>,
    metadata: &str,
) -> String {
    let sep = RS.to_string();
    // Using fixed-size arrays makes the field count statically visible.
    let fields_13: [&str; 13] = [
        &seq_num.to_string(),
        &tenant_id.to_string(),
        source_service,
        event_type,
        &actor_id.map(|u| u.to_string()).unwrap_or_default(),
        actor_role.unwrap_or(""),
        resource_type.unwrap_or(""),
        resource_id.unwrap_or(""),
        outcome_str(outcome),
        &actor_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        &occurred_at.to_rfc3339(),
        &chain_epoch.to_string(),
        prev_hash.unwrap_or(""),
    ];
    if chain_epoch >= 2 {
        // Epoch 2: append metadata as field 14.
        format!("{}{sep}{metadata}", fields_13.join(&sep))
    } else {
        // Epoch 1: legacy 13-field format, metadata excluded.
        fields_13.join(&sep)
    }
}

/// HMAC-SHA256(`key`, `canonical`) → lowercase hex string.
pub fn compute_entry_hash(canonical: &str, key: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    to_hex(&mac.finalize().into_bytes())
}

/// Build a fully-formed [`AuditRecord`] from an [`AuditEvent`] and the
/// chain-position fields that the storage layer supplies after acquiring its
/// per-tenant advisory lock.
///
/// Call order (storage layer):
/// 1. Begin transaction.
/// 2. Acquire advisory lock for `(tenant_id, chain_epoch)`.
/// 3. Read `MAX(seq_num)` and `entry_hash` of the last row → `prev_hash`.
/// 4. Call `seal_record` with those values.
/// 5. INSERT the returned `AuditRecord`.
/// 6. Commit.
pub fn seal_record(
    event: &AuditEvent,
    id: Uuid,
    seq_num: i64,
    prev_hash: Option<&str>,
    chain_epoch: i32,
    created_at: DateTime<Utc>,
    key: &[u8],
) -> AuditRecord {
    let metadata_json = serde_json::to_string(&event.metadata).unwrap_or_else(|_| "{}".to_owned());
    let canonical = canonical_msg(
        seq_num,
        event.tenant_id,
        &event.source_service,
        &event.event_type,
        event.actor_id,
        event.actor_role.as_deref(),
        event.resource_type.as_deref(),
        event.resource_id.as_deref(),
        event.outcome,
        event.actor_ip,
        event.occurred_at,
        chain_epoch,
        prev_hash,
        &metadata_json,
    );
    let entry_hash = compute_entry_hash(&canonical, key);

    AuditRecord {
        id,
        seq_num,
        prev_hash: prev_hash.map(str::to_owned),
        entry_hash,
        chain_epoch,
        created_at,
        event: event.clone(),
    }
}

// ---------------------------------------------------------------------------
// Inline unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Outcome;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_event(tenant_id: Uuid) -> AuditEvent {
        AuditEvent {
            source_service: "soma-vault".into(),
            idempotency_key: Uuid::new_v4(),
            tenant_id,
            event_type: "secret.write".into(),
            actor_id: None,
            actor_role: None,
            resource_type: None,
            resource_id: None,
            outcome: Outcome::Success,
            actor_ip: None,
            occurred_at: Utc::now(),
            metadata: serde_json::Value::Object(Default::default()),
        }
    }

    #[test]
    fn test_single_entry() {
        let tenant_id = Uuid::new_v4();
        let event = make_event(tenant_id);
        let key = b"test-key-32-bytes-padded-to-work!";
        let record = seal_record(&event, Uuid::new_v4(), 1, None, 1, Utc::now(), key);

        assert_eq!(record.seq_num, 1);
        assert!(record.prev_hash.is_none());
        assert!(!record.entry_hash.is_empty());
    }

    #[test]
    fn test_chain_links() {
        let tenant_id = Uuid::new_v4();
        let key = b"test-key-32-bytes-padded-to-work!";
        let mut records = Vec::new();

        for i in 1i64..=3 {
            let event = make_event(tenant_id);
            let prev_hash = records.last().map(|r: &AuditRecord| r.entry_hash.as_str());
            let record = seal_record(&event, Uuid::new_v4(), i, prev_hash, 1, Utc::now(), key);
            records.push(record);
        }

        // prev_hash chain is correct
        assert!(records[0].prev_hash.is_none());
        assert_eq!(
            records[1].prev_hash.as_deref(),
            Some(records[0].entry_hash.as_str())
        );
        assert_eq!(
            records[2].prev_hash.as_deref(),
            Some(records[1].entry_hash.as_str())
        );

        let result = crate::verify::verify_chain(&records, key);
        assert!(result.ok);
        assert_eq!(result.entries_checked, 3);
    }

    #[test]
    fn test_wrong_key_fails_verify() {
        let tenant_id = Uuid::new_v4();
        let key_a = b"key-A-32-bytes-padded-correctly!!";
        let key_b = b"key-B-32-bytes-padded-correctly!!";
        let mut records = Vec::new();

        for i in 1i64..=3 {
            let event = make_event(tenant_id);
            let prev_hash = records.last().map(|r: &AuditRecord| r.entry_hash.as_str());
            let record = seal_record(&event, Uuid::new_v4(), i, prev_hash, 1, Utc::now(), key_a);
            records.push(record);
        }

        let result = crate::verify::verify_chain(&records, key_b);
        assert!(!result.ok);
        assert_eq!(result.first_broken_seq, Some(1));
    }

    // ── BUG 3 regression tests ────────────────────────────────────────────────

    /// Two epoch-2 events that differ ONLY in metadata must produce different
    /// entry_hashes (metadata is now part of the HMAC canonical message).
    #[test]
    fn test_metadata_changes_hash_epoch2() {
        let tenant_id = Uuid::new_v4();
        let key = b"test-key-32-bytes-padded-to-work!";

        let mut event_a = make_event(tenant_id);
        event_a.metadata = serde_json::json!({"action": "read"});

        let mut event_b = make_event(tenant_id);
        // Same event but different metadata value.
        event_b.metadata = serde_json::json!({"action": "delete"});

        let record_a = seal_record(&event_a, Uuid::new_v4(), 1, None, 2, Utc::now(), key);
        let record_b = seal_record(&event_b, Uuid::new_v4(), 1, None, 2, Utc::now(), key);

        // The two records must produce different hashes because metadata differs.
        assert_ne!(
            record_a.entry_hash, record_b.entry_hash,
            "epoch-2 entry_hash must reflect metadata"
        );
    }

    /// Epoch-1 records still verify correctly (backward compatibility): canonical_msg
    /// with epoch=1 ignores metadata, so old records can be verified without it.
    #[test]
    fn test_epoch1_backward_compat() {
        let tenant_id = Uuid::new_v4();
        let key = b"test-key-32-bytes-padded-to-work!";

        // Build a small epoch-1 chain.
        let mut records = Vec::new();
        for i in 1i64..=2 {
            let mut event = make_event(tenant_id);
            event.metadata = serde_json::json!({"ignored": true});
            let prev_hash = records.last().map(|r: &AuditRecord| r.entry_hash.as_str());
            let record = seal_record(&event, Uuid::new_v4(), i, prev_hash, 1, Utc::now(), key);
            records.push(record);
        }

        // verify_chain must still pass for epoch-1 records (ignores metadata).
        let result = crate::verify::verify_chain(&records, key);
        assert!(result.ok, "epoch-1 chain must still verify correctly");
        assert_eq!(result.entries_checked, 2);
    }

    /// Epoch-1 canonical_msg ignores metadata; epoch-2 includes it.  The same
    /// metadata string must produce DIFFERENT messages across the two epochs.
    #[test]
    fn test_canonical_msg_epoch_branching() {
        let tenant_id = Uuid::new_v4();
        let now = Utc::now();
        let metadata = r#"{"key":"value"}"#;

        let msg1 = canonical_msg(
            1,
            tenant_id,
            "svc",
            "evt",
            None,
            None,
            None,
            None,
            Outcome::Success,
            None,
            now,
            1,
            None,
            metadata,
        );
        let msg2 = canonical_msg(
            1,
            tenant_id,
            "svc",
            "evt",
            None,
            None,
            None,
            None,
            Outcome::Success,
            None,
            now,
            2,
            None,
            metadata,
        );

        // Epoch 2 appends metadata; epoch 1 does not — they must differ.
        assert_ne!(msg1, msg2, "epoch-1 and epoch-2 canonical msgs must differ");
        // Epoch 2 message must contain the metadata string.
        assert!(msg2.contains(metadata), "epoch-2 msg must include metadata");
        // Epoch 1 message must NOT contain the metadata string.
        assert!(
            !msg1.contains(metadata),
            "epoch-1 msg must not include metadata"
        );
    }
}
