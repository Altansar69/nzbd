# Changelog

## 0.5.1 (2026-10-18)

### Changed

- **One storage folder, no Docker volumes.** Everything nzbd keeps is a plain bind-mounted host folder under one storage
  folder the installer asks for (default `deploy/storage`): the library in `data/` and, next to it, `secrets/` (TOTP key,
  backup key, database passwords), `state/` and `caddy/` (the proxy's CA), plus `setup_secrets/` and `pg_secrets/` with
  PostgreSQL. With PostgreSQL the installer also asks for the database folder (default `<storage folder>/pg_data`).
  `docker compose down -v` and `docker volume prune` can no longer delete keys or data. The only named volume left is
  the PostgreSQL socket (`nzbd_pg_socket`).
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
