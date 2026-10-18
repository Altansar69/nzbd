# Changelog

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
