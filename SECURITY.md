# Security Policy

## Supported versions

soma-audit is pre-1.0. No stable release has been made yet. The `main` branch
is the only supported version. Patches for security issues will be applied to
`main`; no backport policy exists before 1.0.

## Reporting a vulnerability

Email **security@kreesalis.com** with:

- A clear description of the issue and the impact you believe it has.
- Steps to reproduce or a proof-of-concept (redact any production data).
- Whether you want credit in the disclosure.

We aim to acknowledge reports within 48 hours and provide an initial assessment
within 7 days. Please do not open a public GitHub issue for security
vulnerabilities — disclose privately first.

> **Note to maintainers:** replace `security@kreesalis.com` above with the
> real monitored address before making this repository public.

---

## Threat model

### What soma-audit protects against

soma-audit is a tamper-evident audit log. Its security properties are layered:

**HMAC chain (in-database integrity)**

Every audit event carries an HMAC-SHA256 commitment over its fields, chained to
the previous event for the same tenant (`prev_hash → entry_hash → prev_hash`).
The HMAC key is derived per-tenant using HKDF-SHA256 from the
`SOMA_AUDIT_MASTER_SECRET`:

```
HKDF-SHA256(IKM=master_secret, salt=None, info=b"soma-audit-hmac-v1" || tenant_id)
```

This chain detects three tampering classes:

- **Field mutation** — an attacker changes a stored field value.
- **Row deletion** — a gap in consecutive `seq_num` values for a tenant.
- **Reordering or `prev_hash` tampering** — the chain linkage is broken.

Calling `GET /v1/audit/verify?tenant_id=<uuid>` walks the full chain and
reports the first broken record.

**Append-only triggers (application-role enforcement)**

The `no_update` and `no_delete` triggers on `soma_audit.fct_audit_events` raise
an exception on any `UPDATE` or `DELETE`. An attacker who compromises the
application credentials cannot silently edit or remove audit rows through the
application's database role.

**Row-level security (tenant isolation)**

`FORCE ROW LEVEL SECURITY` ensures that any query without a valid
`soma_audit.tenant_id` GUC sees no rows. Even if application code
inadvertently omits the tenant filter, the policy prevents cross-tenant reads.

**Ed25519 chain seals (external cryptographic anchoring)**

A background sweep runs every 60 seconds on the central server. It signs the
current chain head hash for each tenant with `SOMA_AUDIT_SIGNING_KEY` (an
Ed25519 private key) and stores the seal in `soma_audit.audit_chain_seals`. The
corresponding public key is available at `GET /v1/audit/keys`.

A seal is a cryptographic commitment to the chain state at a point in time.
Any deletion or mutation of events that predates the seal will cause both
`verify` to fail AND the seal signature to be invalid against the published
public key. Seals are the primary defense for high-assurance environments and
are verifiable independently of the database.

**HKDF per-tenant key isolation**

Per-tenant key derivation limits blast radius: compromising one tenant's derived
key does not compromise other tenants' chains.

---

### What soma-audit does NOT protect against

**Postgres superuser / schema owner**

A Postgres superuser (or any role with `SUPERUSER` or the ability to `ALTER
SYSTEM`) can:

- Drop the `soma_audit` schema or truncate the table.
- Disable the `no_update` / `no_delete` triggers and then update or delete rows.
- Read `SOMA_AUDIT_MASTER_SECRET` from the environment or process memory and
  re-derive HMAC keys to forge consistent chain entries.

The append-only property is enforced at the application-role level. It is not
a database-level guarantee against a sufficiently privileged database principal.
This is a well-known constraint of in-database audit approaches.

**Mitigation:** The `soma-audit-server` process should connect with a role that
has only the permissions it needs (INSERT, SELECT on `soma_audit.*`). Superuser
credentials must be held exclusively by the DBA and never by the application.
The Ed25519 seals, pinned at a trusted external location, provide the
higher-assurance defense: even if an attacker rewrites rows and recomputes
HMACs, they cannot forge the Ed25519 signatures without `SOMA_AUDIT_SIGNING_KEY`
— and old seals embedded in external systems (monitoring dashboards, regulatory
records) remain valid anchors for detecting tampering.

**Seal key compromise**

If `SOMA_AUDIT_SIGNING_KEY` is compromised, an attacker can forge new seals over
a rewritten chain. Rotate the signing key immediately if this occurs (see
OPERATIONS.md for the correct procedure). Retain the old public key so that
seals issued before the rotation can still be verified.

**Master secret compromise**

If `SOMA_AUDIT_MASTER_SECRET` is compromised, an attacker can derive per-tenant
HMAC keys and forge chain entries that pass `verify`. Rotate per the procedure
in OPERATIONS.md; note that rotation is a breaking event for historical chain
verification without an epoch transition.

**Central server availability**

If the central `soma-audit-server` is unavailable, clients in Remote mode
accumulate events in their local outbox (`soma_audit_outbox.events`) and
forward them when the server comes back. Events are not lost, but seals will
lag while the server is down.

**Outbox retention**

Delivered outbox rows are never automatically pruned. Plan a maintenance job to
prune `soma_audit_outbox.events WHERE delivered_at IS NOT NULL AND delivered_at
< now() - interval '30 days'`.

---

## Cryptographic choices

| Primitive | Algorithm | Purpose |
|---|---|---|
| Per-entry HMAC | HMAC-SHA256 | Binds each audit record to its fields and the previous chain entry |
| Key derivation | HKDF-SHA256 | Derives per-tenant HMAC keys from the master secret |
| Chain seals | Ed25519 (dalek) | Signs the chain head hash at intervals; externally verifiable |
| Seal payload | SHA-256 of canonical JSON | The value that Ed25519 signs |

These choices follow current NIST / IETF recommendations. HMAC-SHA256 and
HKDF-SHA256 are FIPS-approved constructions. Ed25519 is widely deployed and
resistant to side-channel timing attacks via the `dalek` constant-time
implementation.

---

## Disclosure and CVE process

We follow responsible disclosure. Public details will not be published until a
patch is available, or until 90 days after the initial report (whichever comes
first), following the Google Project Zero policy.

We do not currently have a bug bounty program.
