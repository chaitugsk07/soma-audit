# soma-audit demo explorer

Run the central server + admin dashboard ("explorer") locally with one command,
then seed a few audit events and browse them.

## 1. Start it

From the **`soma-platform/` parent directory** (the one containing both
`soma-audit/` and `soma-schema/`):

```sh
docker compose -f soma-audit/deploy/docker-compose.demo.yml up --build
```

First run builds the server image (a few minutes); subsequent runs are fast.
When you see `soma-audit-server listening on 0.0.0.0:8080`, open:

- **Dashboard:** <http://localhost:8080/>
- **Admin token:** `demo-admin-token` (enter it in the dashboard header)

> ⚠️ The secrets in `docker-compose.demo.yml` are public and hard-coded. Demo
> only — never use that file in production.

## 2. Seed some events

The explorer opens empty until events exist. Two ways to add some:

### a. With `curl` (fastest)

```sh
INGEST=demo-ingest-secret
TENANT=11111111-1111-1111-1111-111111111111
for ev in user.login note.create note.delete; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://localhost:8080/internal/v1/events \
    -H "Authorization: Bearer $INGEST" \
    -H "Content-Type: application/json" \
    -d "{\"source_service\":\"demo-app\",\"idempotency_key\":\"$(uuidgen)\",\"tenant_id\":\"$TENANT\",\"event_type\":\"$ev\",\"outcome\":\"success\",\"occurred_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
done
```

Each returns `201`. Refresh the dashboard's **Sources** page — `demo-app`
appears with an event count; click it to drill into the events. The **Verify**
page (tenant `11111111-1111-1111-1111-111111111111`) reports the chain intact.

### b. With the notes-app example (shows the embedded, atomic path)

The `examples/notes-app` crate writes audit events into its **own** Postgres
inside the same transaction as each note (the embedded `LocalSink` path). Point
it at the demo's Postgres:

```sh
cd soma-audit/examples/notes-app
DATABASE_URL=postgres://soma:soma@localhost:5432/soma_audit \
BIND=127.0.0.1:8090 \
cargo run
```

Then `POST /notes` and `GET /audit` / `GET /audit/verify` on port 8090 — see
that crate's README. (This demonstrates local embedded audit; the central
server demo above demonstrates the fleet view.)

## 3. Stop it

```sh
docker compose -f soma-audit/deploy/docker-compose.demo.yml down
```

The demo uses no volume, so everything is discarded on `down` — a fresh `up`
starts from an empty database and re-runs all migrations.
