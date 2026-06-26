//! Hash-chain verification.
//!
//! [`verify_chain`] detects three classes of tampering:
//!
//! - **Field mutation**: recomputing the HMAC and comparing to the stored
//!   `entry_hash` catches any change to a chain-covered field.
//! - **Row deletion**: a gap in `seq_num` means one or more rows are missing.
//! - **Reordering / prev_hash tampering**: each row's `prev_hash` must equal
//!   the previous row's `entry_hash`; a mismatch is reported immediately.

use serde::Serialize;

use crate::chain::{canonical_msg, compute_entry_hash};
use crate::event::AuditRecord;

/// Result of a chain verification pass.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub ok: bool,
    pub entries_checked: u64,
    /// The `seq_num` of the first record where integrity failed, if any.
    pub first_broken_seq: Option<i64>,
}

/// Verify the integrity of a slice of records for a **single tenant+epoch**,
/// sorted ascending by `seq_num`.
///
/// Checks per record:
/// 1. Recompute `entry_hash` from fields; must match stored value.
/// 2. `prev_hash` must match the previous record's `entry_hash` (or be `None`
///    for the very first record).
/// 3. `seq_num` must be exactly `prev_seq_num + 1`; a gap signals a deleted row.
///
/// Stops at the first broken record and returns its `seq_num`.
pub fn verify_chain(records: &[AuditRecord], key: &[u8]) -> VerifyResult {
    let mut entries_checked: u64 = 0;

    for (i, record) in records.iter().enumerate() {
        let canonical = canonical_msg(
            record.seq_num,
            record.event.tenant_id,
            &record.event.source_service,
            &record.event.event_type,
            record.event.actor_id,
            record.event.actor_role.as_deref(),
            record.event.resource_type.as_deref(),
            record.event.resource_id.as_deref(),
            record.event.outcome,
            record.event.actor_ip,
            record.event.occurred_at,
            record.chain_epoch,
            record.prev_hash.as_deref(),
        );
        let expected_hash = compute_entry_hash(&canonical, key);

        // 1. HMAC integrity
        if record.entry_hash != expected_hash {
            return VerifyResult {
                ok: false,
                entries_checked,
                first_broken_seq: Some(record.seq_num),
            };
        }

        if i == 0 {
            // 2a. First record must have no prev_hash.
            if record.prev_hash.is_some() {
                return VerifyResult {
                    ok: false,
                    entries_checked,
                    first_broken_seq: Some(record.seq_num),
                };
            }
        } else {
            let prev = &records[i - 1];

            // 3. seq_num must be exactly prev + 1 (gap → deletion).
            if record.seq_num != prev.seq_num + 1 {
                return VerifyResult {
                    ok: false,
                    entries_checked,
                    first_broken_seq: Some(record.seq_num),
                };
            }

            // 2b. prev_hash must point to the previous entry_hash.
            if record.prev_hash.as_deref() != Some(prev.entry_hash.as_str()) {
                return VerifyResult {
                    ok: false,
                    entries_checked,
                    first_broken_seq: Some(record.seq_num),
                };
            }
        }

        entries_checked += 1;
    }

    VerifyResult {
        ok: true,
        entries_checked,
        first_broken_seq: None,
    }
}

// ---------------------------------------------------------------------------
// Inline unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::seal_record;
    use crate::event::{AuditEvent, AuditRecord, Outcome};
    use chrono::Utc;
    use uuid::Uuid;

    const KEY: &[u8] = b"test-key-32-bytes-padded-to-work!";

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

    fn build_chain(tenant_id: Uuid, n: i64) -> Vec<AuditRecord> {
        let mut records = Vec::new();
        for i in 1..=n {
            let event = make_event(tenant_id);
            let prev_hash = records.last().map(|r: &AuditRecord| r.entry_hash.as_str());
            let record = seal_record(&event, Uuid::new_v4(), i, prev_hash, 1, Utc::now(), KEY);
            records.push(record);
        }
        records
    }

    #[test]
    fn test_verify_chain_happy_path() {
        let tenant_id = Uuid::new_v4();
        let records = build_chain(tenant_id, 3);
        let result = verify_chain(&records, KEY);
        assert!(result.ok);
        assert_eq!(result.entries_checked, 3);
        assert!(result.first_broken_seq.is_none());
    }

    #[test]
    fn test_verify_detects_field_mutation() {
        let tenant_id = Uuid::new_v4();
        let mut records = build_chain(tenant_id, 3);
        // Mutate the event_type of record 2 without recomputing the hash.
        records[1].event.event_type = "secret.delete".into();
        let result = verify_chain(&records, KEY);
        assert!(!result.ok);
        assert_eq!(result.first_broken_seq, Some(2));
    }

    #[test]
    fn test_verify_detects_deletion() {
        let tenant_id = Uuid::new_v4();
        let mut records = build_chain(tenant_id, 5);
        // Remove seq 3 (index 2).
        records.remove(2);
        // records are now [1,2,4,5] — seq gap at 4.
        let result = verify_chain(&records, KEY);
        assert!(!result.ok);
        assert_eq!(result.first_broken_seq, Some(4));
    }

    #[test]
    fn test_verify_detects_prev_hash_tamper() {
        let tenant_id = Uuid::new_v4();
        let mut records = build_chain(tenant_id, 3);
        // Corrupt prev_hash on record 2.
        records[1].prev_hash = Some("deadbeef".repeat(8));
        let result = verify_chain(&records, KEY);
        assert!(!result.ok);
        // The HMAC will also fail because prev_hash is part of canonical_msg,
        // but the first failure is still at seq 2.
        assert_eq!(result.first_broken_seq, Some(2));
    }
}
