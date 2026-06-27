# syntax=docker/dockerfile:1
# Build context: the soma-platform parent directory.
# Build command (from soma-platform/):
#   docker build -f soma-audit/deploy/Dockerfile -t soma-audit:dev .
#
# The build context must be the soma-platform/ parent because soma-audit
# depends on soma-schema via a Cargo path dep (../soma-schema in Cargo.toml).
# Both directories must be present in the build context.
#
# DASHBOARD NOTE: dashboard/dist is committed to the repository and is
# embedded into the server binary at compile time via rust-embed. This
# Dockerfile builds the server against the committed dist/ directory.
# If the dashboard source in dashboard/ has changed since the last dist/
# build, maintainers must run `trunk build --release` inside dashboard/
# and commit the updated dist/ before building this image.
# A full trunk-build stage is intentionally omitted here because it
# requires the soma-ui sibling repository (../../soma-ui relative to
# dashboard/) which is outside the soma-audit build context.

# ── Stage 1: builder ──────────────────────────────────────────────────────────
# Match the toolchain declared in workspace.package.rust-version (1.82).
# A mismatch triggers a full toolchain re-download on every build.
FROM rust:1.82-bookworm AS builder

# Network resilience: sparse index sends far fewer requests than the legacy
# git index; the retry/timeout knobs tolerate a flaky crates.io CDN.
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    CARGO_NET_RETRY=10 \
    CARGO_NET_TIMEOUT=120 \
    CARGO_HTTP_TIMEOUT=120 \
    CARGO_HTTP_LOW_SPEED_LIMIT=0

# System deps needed by sqlx / ring / openssl.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# ── manifests only (cache layer) ──────────────────────────────────────────────
# Copy manifests first so Docker can cache the dependency-download layer
# independently of source changes.

# Workspace manifests.
COPY soma-audit/Cargo.toml soma-audit/Cargo.lock /build/soma-audit/

# Crate manifests.
COPY soma-audit/crates/soma-audit-core/Cargo.toml   /build/soma-audit/crates/soma-audit-core/
COPY soma-audit/crates/soma-audit-pg/Cargo.toml     /build/soma-audit/crates/soma-audit-pg/
COPY soma-audit/crates/soma-audit-client/Cargo.toml /build/soma-audit/crates/soma-audit-client/
COPY soma-audit/crates/soma-audit-server/Cargo.toml /build/soma-audit/crates/soma-audit-server/

# soma-schema sibling (path dep: ../soma-schema in workspace Cargo.toml).
COPY soma-schema/Cargo.toml soma-schema/Cargo.lock /build/soma-schema/

# Stub out every lib/main so cargo can resolve the dependency graph and
# download all crates without needing the real source.
RUN bash -c '\
  set -e; \
  for f in \
    /build/soma-audit/crates/soma-audit-core/src/lib.rs \
    /build/soma-audit/crates/soma-audit-pg/src/lib.rs \
    /build/soma-audit/crates/soma-audit-client/src/lib.rs \
    /build/soma-audit/crates/soma-audit-server/src/main.rs; \
  do \
    mkdir -p "$(dirname $f)"; \
    echo "fn main() {}" > "$f"; \
  done; \
  mkdir -p /build/soma-schema/src; \
  echo "" > /build/soma-schema/src/lib.rs \
'

# Pre-fetch and compile workspace dependencies.  The subsequent full COPY
# will replace the stubs and invalidate this layer only if manifests changed.
WORKDIR /build/soma-audit
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo fetch

# ── full source copy ───────────────────────────────────────────────────────────
COPY soma-audit/  /build/soma-audit/
COPY soma-schema/ /build/soma-schema/

# ── build the server binary ───────────────────────────────────────────────────
# dashboard/dist is already present in the copied source (committed to the
# repo). rust-embed picks it up at compile time from
# crates/soma-audit-server/../../dashboard/dist (relative to the crate root).
WORKDIR /build/soma-audit
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release -p soma-audit-server

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# ca-certificates: needed for any TLS outbound calls the server may make.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 soma \
    && useradd --uid 10001 --gid soma --no-create-home --shell /sbin/nologin soma

# Copy only the server binary — the dashboard is embedded inside it.
COPY --from=builder /build/soma-audit/target/release/soma-audit-server /usr/local/bin/soma-audit-server

WORKDIR /app
RUN chown 10001:10001 /app

# Runtime defaults.  Callers MUST supply all five required env vars:
#   DATABASE_URL              – Postgres connection string
#   SOMA_AUDIT_MASTER_SECRET  – 64 lowercase hex chars (openssl rand -hex 32)
#   SOMA_AUDIT_SIGNING_KEY    – 64 lowercase hex chars (openssl rand -hex 32)
#   SOMA_AUDIT_INGEST_SECRET  – bearer token for relay ingest endpoint
#   SOMA_AUDIT_ADMIN_TOKEN    – bearer token for /v1/audit/* query endpoints
ENV SOMA_AUDIT_BIND=0.0.0.0:8080

USER 10001
EXPOSE 8080

ENTRYPOINT ["soma-audit-server"]
