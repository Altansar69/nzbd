# Changelog

## Unreleased

### Security

- Password hashing and verification keep their concurrency slots until the blocking work actually finishes, even
  when a login or invitation request is cancelled. Cancelled waiters also leave the queue correctly.
- Downloads release their buffers and concurrency slots at the deadline even when a stalled client stops reading.
  Frames already handed to the HTTP connection retain only their chunk, not the entire NZB allocation.
- Upgrade Tantivy to 0.27.0 and its `lru` dependency to 0.18.5, fixing **RUSTSEC-2026-0253**.
- Reject non-whitespace text, CDATA and entity references outside the NZB document root, including after its closing
  tag. Opening stored blobs uses non-blocking, no-follow file access so a substituted FIFO cannot hang a reader.
- Cap the configured search offset window at its supported maximum, preventing oversized result allocations.
  Clippy now rejects Tantivy query APIs that bypass the bounded query builders.
- Invitation and recovery redemption revoke a presented old session in the same transaction as the new session.
  A revocation failure rolls everything back, preserving the code for a retry.
- Revoking sessions, API keys, invitations or recovery codes revalidates the calling session inside the mutation
  transaction, so a delayed request cannot use a revoked cookie to undo a later recovery.
- Sensitive account writes also refuse expired sessions that have not yet been purged, and a delayed session
  refresh cannot revive an expired cookie.
- Proxy error logs redact the complete request URI and Referer, covering tokens in arbitrary query parameters
  or path segments as well as the already protected authentication headers.
- Stored blobs refuse pre-existing symbolic links in either shard directory before reading, refreshing or deleting.
  Operator-configured links at the store root remain supported.
- Bulk archive timeouts retain concurrency slots until an in-flight storage read actually finishes.
- Quarantine purges respect the cleanup deadline and recheck the administrator's authority between batches.

### Fixed

- SQLite backups lock their destination directory through cleanup, publication and rotation. Concurrent backups
  cannot remove each other's temporary snapshot, and cancelling the caller does not release the lock early.
  Filesystem and encryption work runs off the async runtime threads.
- Importing a duplicate repairs an existing corrupt blob even when its size matches the incoming file.
- A cancelled garbage-collection removal preserves a healthy blob published by a concurrent repair; the old copy
  remains in quarantine instead of overwriting the repair.
- PostgreSQL encrypted restore clears the actual temporary decryption file left by an interrupted restore.
- PostgreSQL backups also lock the destination directory through cleanup and publication. Cancelled exports
  release the lock without publishing a partial backup.
- Database errors during indexing preserve the outbox and discard uncommitted index changes for a clean retry.
- Upload category hints respect the current user's UI visibility; the upload API retains its documented ability
  to ingest categories hidden from the UI, for both header and multipart hints.
- Bound panic tracking when ingestion repeatedly encounters new failing paths. SQLite credential writers acquire
  their write transaction before reading, and failed-ingest lookups use a partial SHA index.
- Ingestion resumes correctly after index lag falls below half the configured threshold, including thresholds of
  one or an odd number.
- Expired sessions and pending MFA redirect the whole page during HTMX navigation. Empty search results keep a
  valid swap target, and filters stay synchronized after sorting or navigating back.
- Network errors, timeouts and failed HTMX requests display an accessible message. The select-all checkbox reflects
  partial selection and restored pages; sorting and select-all remain usable on mobile. Email fields use the same
  styling as other inputs, and viewer empty states no longer suggest an upload they cannot perform.
- Selection actions stay disabled until a release or file is checked. Without JavaScript, empty submissions show a
  readable HTML error page with navigation; API requests continue to receive JSON errors.
- Enter in the bulk source field submits the source action when JavaScript is available. Ambiguous implicit bulk
  submissions are blocked; without JavaScript, the explicit action buttons remain usable.
- Proxy examples allow a complete web upload batch (321 MiB) while keeping the API request limit at 65 MiB.
  The nginx example preserves the port in the `Host` header so origin validation works on non-default ports.
- Refresh the CSS and JavaScript asset hashes, and make the installer and PostgreSQL bootstrap assignments explicit
  for shell linting.

### Changed

- Filtered release lists skip the unused ingest-timeline database query. Statistics dictionary decoding uses bounded
  batches to preserve query deadlines with Tantivy 0.27.
- Expand regression coverage for cancellation, stalled downloads, backup concurrency, blob repair, malformed NZBs,
  index upgrades, SQLite outbox transactions and restore credential revocation. The legacy SQLite check fixture is
  generated from migrations, and source-bundle tests work when the separate fuzz project is absent.
- Refresh the Rust licence inventory from the Linux production dependency tree and Cargo metadata.

### Upgrading

The search index schema is now **3**. On the first opening after this upgrade, nzbd automatically rebuilds an older
index from the database. Search stays in degraded mode until the rebuild finishes; allow time for large libraries.
The database and stored NZB files are retained, and no manual index deletion is required.

### Dependency audit status

`Cargo.lock` still contains `rsa` 0.9.10 through SQLx's optional MySQL dependency, so a raw `cargo audit` still reports
**RUSTSEC-2023-0071**. Neither `rsa` nor `sqlx-mysql` is present in the application's enabled dependency tree, including
`cargo tree --target all`. The advisory has not been suppressed or removed from the audit results.

## 0.5.1 (2026-10-18)

### Changed

- **One storage folder, no Docker volumes.** Everything nzbd keeps is a plain bind-mounted host folder under one storage
  folder the installer asks for (default `deploy/storage`): the library in `data/` and, next to it, `secrets/` (TOTP key,
  backup key, database passwords), `state/` and `caddy/` (the proxy's CA), plus `setup_secrets/` and `pg_secrets/` with
  PostgreSQL. With PostgreSQL the installer also asks for the database folder (default `<storage folder>/pg_data`).
  `docker compose down -v` and `docker volume prune` can no longer delete keys or data. The only named volume left is
  the PostgreSQL socket (`nzbd_pg_socket`).
- **Readable logs by default.** The stack now runs nzbd with `NZBD_LOG_FORMAT=pretty` (coloured lines and a startup
  banner in `docker compose logs`); set `NZBD_LOG_FORMAT=json` in `deploy/.env` for log shippers.
- **Traefik first.** The installer lists running Traefik containers first and recommends them; for any other proxy it
  skips every Traefik question.
- `install.sh` refuses to run with `compose-example/` or `volperms.sh` from another release.

### Fixed

- The pinned hash of `app.css` (served as its ETag) matches the file again.

### Upgrading from 0.5.0

0.5.0 kept the keys in the Docker volumes `nzbd_secrets`, `nzbd_state`, `nzbd_caddy` (and `nzbd_setup_secrets`,
`nzbd_pg_data`, `nzbd_pg_secrets` with PostgreSQL). Stop the stack (`docker compose stop`, never `down -v`) and copy each
volume once into its folder, or the new stack starts with a NEW TOTP key and nobody can log in. `install.sh` stops and
prints the command when it finds such volumes, for example:

```
mkdir -p storage/secrets && docker run --rm -u 0 -v nzbd_secrets:/from:ro -v "$PWD/storage/secrets":/to \
  --entrypoint sh caddy:2 -c 'cp -a /from/. /to/'
```

Then re-run `./install.sh`. Remove the old volumes yourself once the new stack works.

## 0.5.0 (2026-10-17)

First public release.

### Features

- **Collect** NZB files from a watch folder, a web upload form or an upload-only API (`POST /api/v1/nzb`).
- **Index and search** title, date, size, category (Scene-name rules) and full text, on SQLite or PostgreSQL with a
  Tantivy search index.
- **Explore and download** releases: file and segment structure, single files, selected files or several releases as a
  zip.
- **Roles:** viewer, uploader and admin. Only an admin edits categories and source labels or deletes releases.
  Demoting an account to viewer revokes its API keys.
- **Accounts:** password and mandatory TOTP per account, invitations with one-time codes, recovery codes, API keys.
- **Hidden invitation path:** `security.invite_path` (default `/invite`) moves the invitation page to an address of
  your choice. `install.sh` generates a random one for a fresh install.
- **Statistics page** for every role: totals, releases per category, top release groups, quality breakdown and releases
  added per month. Hidden categories are left out of every number.
- **Items per page:** 25 / 50 / 100 for release lists and 50 / 100 / 250 / 500 for file tables, remembered per account.
- **Audit trail:** upload, duplicate, rejected upload and delete events, with an admin-only **Activity** page
  (`/admin/activity`) filtered by user, event and date.
- **Readable logs:** `NZBD_LOG_FORMAT=pretty` prints coloured single-line logs; JSON stays the default and `NO_COLOR=1`
  removes the colour.
- **Release group:** the last `-` part of a name is the group even when the family is not recognised.

### Install notes

- **Fresh install only.** There is no upgrade path from earlier private versions: use a new data directory and bring
  your NZB files over (see [Quick install](QUICK_INSTALL.md)).
- Volumes and containers use short fixed names. `NZBD_NAME_PREFIX` (default `nzbd`, see `deploy/.env.example`) sets the
  prefix: volumes `nzbd_secrets`, `nzbd_state`, `nzbd_caddy` (and `nzbd_setup_secrets` with PostgreSQL); containers
  `nzbd`, `nzbd-proxy` and `nzbd-db`.
