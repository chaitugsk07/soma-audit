# soma-audit Operations Runbook

How to deploy and operate the central `soma-audit-server`. For the threat model
and what the system does and does not protect against, read
[SECURITY.md](../SECURITY.md). For adopting the library in your own app, read
[docs/INTEGRATION.md](INTEGRATION.md).

## Secrets

The server requires four secrets, supplied as environment variables. Generate
them with a CSPRNG and inject them through your platform's secret manager — do
**not** bake them into images or commit them.

```sh
openssl rand -hex 32   # SOMA_AUDIT_MASTER_SECRET  (32 bytes, hex)
openssl rand -hex 32   # SOMA_AUDIT_SIGNING_KEY    (32 bytes, hex — Ed25519 seed)
openssl rand -hex 32   # SOMA_AUDIT_INGEST_SECRET  (bearer for service relays)
openssl rand -hex 32   # SOMA_AUDIT_ADMIN_TOKEN    (bearer for /v1/audit/*)
```

`SOMA_AUDIT_INGEST_SECRET` must match the `ingest_secret` configured in every
client service's `RelayConfig`. `SOMA_AUDIT_ADMIN_TOKEN` gates all query
endpoints and the admin portal. See [deploy/.env.example](../deploy/.env.example)
for the full list including optional variables.

## Deployment

**Single node:** [deploy/docker-compose.yml](../deploy/docker-compose.yml)
brings up Postgres 16 and the server. Copy `deploy/.env.example` to `deploy/.env`,
fill it in, then `docker compose -f deploy/docker-compose.yml up`.

**Multi-node / Kubernetes:** run the server as a stateless Deployment behind a
Service, pointed at a managed Postgres. The server is horizontally scalable: the
chain append path is serialized per tenant by a Postgres advisory lock, so
multiple replicas are safe. Run exactly **one** replica with the seal sweep
active, or accept that concurrent sweeps will each attempt to seal (the inserts
are independent and harmless, but redundant). A future release will coordinate
the sweep across replicas.

The Docker build context must be the parent directory (`soma-platform/`) so the
`../soma-schema` path dependency resolves — see the comment at the top of
[deploy/Dockerfile](../deploy/Dockerfile).

## Postgres setup

- A database the server's role can connect to (`DATABASE_URL`).
- The connecting role needs the usual DML plus the ability to run the migrations
  on first boot (`CREATE SCHEMA`, `CREATE TABLE`, etc.). After the schema exists,
  a least-privilege runtime role needs `INSERT`/`SELECT` on
  `soma_audit.fct_audit_events`, `INSERT`/`SELECT` on `soma_audit.audit_chain_seals`,
  and the ability to `SET` the custom GUCs `soma_audit.tenant_id` and
  `soma_audit.bypass` (custom GUCs are settable by any role by default).
- The seal sweep reads across all tenants by setting `soma_audit.bypass = 'on'`
  inside its transaction, which a permissive RLS policy honors. This is the
  intended cross-tenant maintenance path; no `BYPASSRLS` role attribute is needed.

## Key rotation

This is the operationally sharp edge — read before rotating anything.

**`SOMA_AUDIT_MASTER_SECRET` (HMAC).** Per-tenant HMAC keys are derived from this
secret, so changing it means existing records **no longer verify** under the new
key. There is no seamless rotation today. The correct procedure when you must
rotate:

1. Stop writes (or accept that in-flight events use the old key).
2. Bump the chain epoch in code for new records (the canonical format is already
   epoch-versioned; a key change should coincide with an epoch bump so old and
   new segments are distinguishable).
3. Retain the **old** master secret in a vault as the key for verifying historical
   (pre-rotation) records. `verify_chain` must be run with the matching key per
   epoch segment.

Treat master-secret rotation as a deliberate, infrequent, documented event — not
a routine credential rotation. If you have no compromise, do not rotate it.

**`SOMA_AUDIT_SIGNING_KEY` (Ed25519 seals).** Rotation is cleaner: publish the
new public key at `GET /v1/audit/keys` with a new `kid`. Old seals continue to
verify against the **old** public key, so retain it for external verifiers.
New seals are signed with the new key going forward.

**Bearer tokens** (`INGEST_SECRET`, `ADMIN_TOKEN`) rotate freely — update the
server's env and every client's `RelayConfig`, then restart. Comparison is
constant-time.

## Backups and integrity after restore

The audit log is only as trustworthy as your ability to prove it wasn't altered.
After **any** restore from backup:

1. For each tenant, call `GET /v1/audit/verify?tenant_id=<uuid>` (admin bearer).
   A `{"ok": true, ...}` response confirms the HMAC chain is intact end to end.
2. Optionally re-check the latest seal: `GET /v1/audit/seals?tenant_id=<uuid>`
   gives the signed chain head; verify the Ed25519 signature against the public
   key from `/v1/audit/keys`. A valid seal proves the chain head you restored
   matches what was sealed at that point in time.

A restore that fails verification means the backup captured a tampered or
truncated chain — investigate before trusting it.

## Monitoring

- **Relay/outbox lag (client side).** Each emitting service has a
  `soma_audit_outbox.events` table; alert when undelivered rows
  (`delivered_at IS NULL`) exceed a threshold or the oldest pending row ages past
  a bound. The relay backs off exponentially (`next_retry_at`) when the central
  server is unreachable, so sustained lag means central is down or rejecting.
- **Seal freshness.** Alert if the newest `audit_chain_seals.sealed_at` for an
  active tenant is older than a few sweep intervals (default sweep is 60s) — it
  means the sweep is wedged or the server lost its signing key.
- **Logs.** The server emits structured `tracing` output; set `LOG_FORMAT=json`
  and ship to your aggregator. There is no `/metrics` endpoint yet.

## Current operational gaps

Tracked, not yet built: retention/archival of old events, a Prometheus
`/metrics` endpoint, an audit-of-the-audit (logging who queried the audit log),
and cross-replica seal-sweep coordination. See the review report
([docs/REVIEW.md](REVIEW.md)) for the full backlog.
