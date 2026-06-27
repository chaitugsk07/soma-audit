# Publishing soma-audit to crates.io

The crates depend on each other and on `soma-schema`, so they must be published
**in dependency order**. Each `cargo publish` uploads to a public, immutable
registry — you cannot un-publish (only yank). Do a `--dry-run` of each step
first; the manifests are already prepared with `path` + `version` deps so local
development keeps using the path while published artifacts use the version.

## Prerequisite: publish soma-schema 0.4 first

`soma-audit-pg` and `soma-audit-client` require `soma-schema >= 0.4` — the
version that adds `Migrator::from_embedded`. crates.io currently has 0.3.0,
which does **not** have it. The local `soma-schema` repo is already bumped to
0.4.0.

```sh
cd ../soma-schema
cargo publish --dry-run
cargo publish              # publishes soma-schema 0.4.0
```

## Then publish soma-audit crates in this order

Wait for each to appear on crates.io (usually seconds) before the next, because
each verifies its dependencies against the live index.

```sh
cd ../soma-audit

# 1. core — no soma-audit deps
cargo publish -p soma-audit-core

# 2. pg — depends on core + soma-schema 0.4
cargo publish -p soma-audit-pg

# 3. client — depends on core + soma-schema 0.4
cargo publish -p soma-audit-client

# 4. server — depends on core + pg
cargo publish -p soma-audit-server
```

## Notes

- Run `cargo publish -p <crate> --dry-run` before each real publish. `core`
  already passes its dry-run; the others can only fully verify once their
  dependencies are live on the index (a dry-run before that reports
  "no matching package named ... found", which is expected, not an error in the
  crate).
- `examples/notes-app` and `dashboard/` are **not** published — they are a
  standalone example and a build artifact embedded in the server.
- Set the real security contact in `SECURITY.md` before making the repo public.
- After the first publish, drop the `path =` from the version deps in a later
  release if you want published-only resolution, or keep both (path wins locally,
  version is used by downstream consumers) — keeping both is fine and is the
  current setup.
