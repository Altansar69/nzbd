# Runbook (day-2 operations)

Audience: the person who deployed nzbd with the [install guide](INSTALL.md). Every command was run
against the production image unless marked otherwise. Conventions:

- Commands run in `nzbd/deploy/` (where `compose.yaml` and `.env` live; settings in `config/nzbd.toml`, applied by
  `docker compose restart nzbd`). The volumes have short fixed names
  (prefix `nzbd`, or `NZBD_NAME_PREFIX` in `.env`) and the containers are `nzbd`, `nzbd-proxy` and `nzbd-db`:
  the volumes are `nzbd_secrets` (TOTP key, backup key, PostgreSQL app password), `nzbd_state` (`paths.state`:
  `serve.lock` and the restore anchor) and `nzbd_caddy` (proxy CA); with PostgreSQL also `nzbd_pg_data` (the
  cluster), `nzbd_pg_socket`, `nzbd_pg_secrets` and `nzbd_setup_secrets` (the owner password, mounted only into the
  one-shot `setup` service). Check with `docker volume ls`. `NZBD_DB_BACKEND` in `.env` says which backend you run;
  where the two differ this runbook says **SQLite** or **PostgreSQL**.
- **The container user.** nzbd runs as `NZBD_UID:NZBD_GID` from `.env` (T128; the installer proposed the IDs of the
  account that ran it, or `10001:10001` when run as root or with rootless Docker / userns-remap). The commands below
  use it as `$IDS`; set it once per shell, in `deploy/`:
  `IDS="$(sed -n 's/^NZBD_UID=//p' .env):$(sed -n 's/^NZBD_GID=//p' .env)"`. "The container user" in the text means
  the same ids. With your own IDs you can read `data/` directly on the host, without the tools container. Changing
  it later is not supported: nzbd never re-owns existing key volumes (fresh start, section 6 "the key volumes are not
  owned by").
- `docker compose exec nzbd /nzbd <cmd>` runs the CLI inside the running container as the container user. The binary is
  `/nzbd`; it is not on `PATH` (the image has no shell). Never add `-u 0`: files it creates would not be readable
  by the service. Add `-it` when a command prompts (`user create`, `user reset-password`).
- If the container is not running (crash loop), use `docker compose run --rm --no-deps nzbd <cmd>` instead (same
  mounts, same user).
- "Tools container" below means `docker run --rm -u <NZBD_UID>:<NZBD_GID> ... --entrypoint sh caddy:2` (any small image with
  `sh`, `cat`, `tar` works). It is how you touch files in `data/` and in volumes without a shell in the app image.
- `data/` is `deploy/data` unless you set `NZBD_DATA_DIR`. It is owned by the container user with mode 0700 (the
  installer; 0750 is fine too).

## 1. Checklists

### Daily (30 seconds, or let a monitor do it)

| Check | How | Healthy |
|---|---|---|
| Overall health | `docker compose exec nzbd /nzbd health; echo $?` or the **Health** page | exit 0 (all OK); 1 = warnings, 2 = failures |
| Containers | `docker compose ps` | `nzbd` healthy, `proxy` running (PostgreSQL: `postgres` healthy), no restarts climbing |
| Failed files | **Admin** page, or `docker compose exec nzbd /nzbd failed list` | `0 file(s)`, or ones you know about |

`nzbd health` is read-only and prints no secrets or full paths. Typical cron monitor:
`cd /srv/nzbd/deploy && docker compose exec -T nzbd /nzbd health >/dev/null || mail -s "nzbd health $?" you@example.org`.

### Weekly

| Check | How |
|---|---|
| Free disk | `df -h` on the volume holding `data/` (library, search index `index/`, `failed/`, `duplicates/`, `backups/`, `tmp/` all share it). The health page warns below 10 % or 1 GiB free and fails below 2 % or 64 MiB; uploads are refused (507) below 1 GiB / 5 %. **PostgreSQL:** nzbd cannot see the database volume: check `docker system df -v | grep nzbd_pg_data` (and the disk under Docker's data root) yourself; plan ~3 GB plus WAL (up to `max_wal_size` 2 GB) at a million releases. |
| Backup age | Health row "Database backups" (WARN when none exists, `backups/` is unreadable, or the newest is older than 3 days; the in-process scheduler makes one daily). `ls -l data/backups` lists `nzbd-YYYYMMDDTHHMMSSZ.sqlite[.enc]` (SQLite) or `nzbd-YYYYMMDDTHHMMSSZ.nzbdpg[.enc]` (PostgreSQL). |
| Off-host copy | Latest backup and the TOTP key copied elsewhere (section 2). |
| Store consistency | the deep-check button on the Health page, or `docker compose exec nzbd /nzbd store verify` (re-hashes every blob; exit 2 = problems). |
| Logs | `docker compose logs --since 168h nzbd \| grep -E '"level":"(WARN|ERROR)"'` |
| Updates | `git fetch` and read `docs/CHANGELOG.md`; see section 5. Rebuild occasionally for base-image fixes (digests are pinned in the Dockerfiles). |

## 2. Backups and restore

### What needs backing up

A complete backup is **the database backup plus `data/store/`** (the NZB files live on the filesystem only, D36 a),
plus the keys kept apart.

| Item | Where | How | Contains |
|---|---|---|---|
| Database, **SQLite** | `data/nzbd.sqlite` (+ `-wal`, `-shm`) | the in-process scheduler or **`nzbd backup`**: a consistent `VACUUM INTO` copy, stripped of sessions, staged credentials, open invitations, recovery codes and throttle rows (`secure_delete`, then `VACUUM`), marked restore-pending, `integrity_check`ed, then encrypted if a backup key is set; mode 0600, keeps 14 | releases, Argon2 password hashes, **sealed** TOTP secrets, API-key hashes, emails, audit log |
| Database, **PostgreSQL** | volume `nzbd_pg_data` | the in-process scheduler or **`nzbd backup`**: the nzbd snapshot export (one `REPEATABLE READ` snapshot, binary `COPY` per table, manifest with row counts and SHA-256 per table and the audit anchors; no `pg_dump` needed), without sessions, staged credentials, open invitations, recovery codes, throttle rows and the search tables; encrypted if a backup key is set; mode 0600, keeps 14 | the same as SQLite; never the database role passwords |
| NZB library | `data/store/` | file copy (rsync/tar). Files are immutable and named by SHA-256, so incremental copies are cheap | the user's NZBs |
| **TOTP encryption key** | volume `nzbd_secrets`, file `nzbd_totp_key` | **separately from everything above**, offline | 32 random bytes (base64) |
| Backup encryption key (recommended) | the file named by `maintenance.backup_encryption_key_file` | **separately from the backups**, offline; without it encrypted backups are unreadable | 32 random bytes (base64), a different key than the TOTP key |
| PostgreSQL role passwords | volumes `nzbd_secrets` (`nzbd_db_password`), `nzbd_setup_secrets`, `nzbd_pg_secrets` | not needed in the backup: a restore goes into a fresh cluster that is initialized from the password files `dbsecrets` already wrote (it keeps an existing set); keep the volumes, or run `dbsecrets` on a new host to generate a new set | random |
| Proxy credentials | `deploy/.env` | password manager | bcrypt hash and user name |
| Proxy CA | volume `nzbd_caddy` | optional; if lost, Caddy makes a new CA and every device must trust the new root | CA private key: treat as secret |

`failed/`, `duplicates/`, `tmp/` and the search index `index/` do not need backups (`failed/` holds files that were
never indexed, copy it if you care about them; the index is rebuilt from the database after a restore). Backup files
are **backend-specific**: a SQLite backup restores into SQLite, a PostgreSQL export into PostgreSQL.

The keys are deliberately **not** in `data/` and **not** in `nzbd backup` output: someone who steals the backups must
not get the key that unseals TOTP secrets. Do not store them together.

### Automatic backups (in-process scheduler)

`nzbd serve` runs a maintenance task: the first run 60 seconds after start, then every
`maintenance.backup_interval_hours` (default 24). Each run writes a consistent snapshot to `paths.backups`
(`data/backups/nzbd-YYYYMMDDTHHMMSSZ.sqlite` or `.nzbdpg`, `.enc` when encrypted, mode 0600), rotates down to `maintenance.keep_backups` (default 14), then
purges expired sessions, audit and ingest-log rows past the database's retention policy (audit 90 days, account
audit 365 days, ingest log 90 days by default; the database refuses anything below the floors of 90 / 365 days, D35 d)
and API keys revoked more than 90 days ago. It logs counts at info level (a failed step at warn level; the steps are
independent) and never blocks requests. Nothing needs to be installed in cron.

Keys ([configuration reference](CONFIGURATION.md); env form `NZBD__maintenance__<key>`):

| Key | Default | Notes |
|---|---|---|
| `maintenance.backup_interval_hours` | `24` | `0` disables the whole job; maximum 8784 (366 days) |
| `maintenance.keep_backups` | `14` | 1-3650 |
| `maintenance.backup_encryption_key_file` | unset | recommended (next section) |

The retention periods are no longer settings in v3: they live in the database (`retention_policy`, owner-only on
PostgreSQL). The 2.x keys `maintenance.log_retention_days` / `account_audit_retention_days` are unknown in v3 and refused by
`config check`; remove them from `config/nzbd.toml`.

The scheduler's output is on the same disk as the database: **it is not an off-host backup**. Copy the backups and the
TOTP key away separately (next sections); both rules are unchanged. The health row "Database backups" turns WARN when
the newest backup is older than 3 days, which means the task is disabled, failing (`docker compose logs nzbd`) or the
container was not running.

To disable it and schedule yourself (for a fixed time of day or an external backup tool), set
`NZBD__maintenance__backup_interval_hours: "0"` in `deploy/compose.override.yaml`, `docker compose up -d`, and use
the manual command below from cron. Leaving the scheduler on and also running cron is harmless: it only creates more
snapshots, and rotation keeps the newest N.

### Encrypted backups (optional)

Set `maintenance.backup_encryption_key_file` to make every snapshot (scheduler and `nzbd backup`) an authenticated,
encrypted file `nzbd-YYYYMMDDTHHMMSSZ.sqlite.enc` / `.nzbdpg.enc` (XChaCha20-Poly1305, SEC-052). Recommended for
every install: backups hold password hashes, sealed TOTP secrets and emails. Setup, once:

```
# the one-shot keygen service has the secrets volume writable; the command is replaced by the arguments
docker compose --profile setup run --rm keygen keygen --out /run/secrets/nzbd_backup_key
# then in config/nzbd.toml, under [maintenance]:
#   backup_encryption_key_file = "/run/secrets/nzbd_backup_key"
docker compose restart nzbd
```

Rules: the key file is 0400 and owned by the container user (`$IDS`), it is **not** the TOTP key (startup refuses equal keys) and not
inside `paths.backups`; **back it up separately and offline** (same procedure as the TOTP key below), because a backup
without its key is unrecoverable. If the key is configured but unusable, `nzbd backup` and the scheduler fail with
an error and write nothing: they never fall back to plaintext. Old plaintext backups stay valid and rotate out with
the normal keep-N rotation. The plaintext snapshot exists only as a hidden 0600 temp file inside `backups/` for the
seconds the encryption takes (leftovers of a crash are removed by the next run); put `paths.backups` on an encrypted
volume if that window matters.

Restoring an encrypted backup: SQLite decrypts it into place with `nzbd backup decrypt` ("Restore (SQLite)" below);
PostgreSQL's `nzbd db restore` decrypts it itself with the configured key ("Restore (PostgreSQL)").
`backup decrypt --key-file FILE` selects another key (for example on a new host before the config is in place). The
output is mode 0600, never overwrites an existing file, and is only published after the whole file authenticated:
"wrong backup encryption key" means another key sealed it; "damaged or has been tampered with" means the file changed
or was cut off, so use an older backup. A plaintext backup is accepted by `db restore` while a key is configured only
with `--allow-unencrypted`. **A plaintext backup is neither confidential nor authenticated:** its manifest digests
catch accidents (truncation, bit rot), not a forged file, and it holds password hashes, sealed TOTP secrets, key
hashes and emails. Restore only backup files you produced and kept out of others' reach; configure a backup key so
every backup is encrypted and authenticated (review 39 I5).

### Hiding the XXX category

Set `NZBD__ui__show_xxx: "false"` (or `[ui] show_xxx = false`) and restart. Releases in `XXX` or any child category are then
not displayed: index, search, tiles, timeline and category selects omit them and their `/release/<id>`, `/raw`,
`/download` and segment URLs answer 404. Nothing is deleted or re-categorised; uploads and the watch folder keep
working, and setting it back to `true` restores everything. `/admin`, `/admin/health` and the CLI stay unfiltered.

### Take a backup manually

```
docker compose exec nzbd /nzbd backup
# backup written: /data/backups/nzbd-20261010T064056Z.sqlite.enc (encrypted)      (PostgreSQL: ...Z.nzbdpg.enc)
# audit chain anchor (keep off-host): head_log=... head_account=... rows=...
# rotated 0 old backup(s); purged 0 session(s), 0 audit and 0 ingest log row(s), 0 revoked API key(s), ...
```

Options: `--keep N` (default 14; retention is the database's policy, see above). It does
the same snapshot and purges as the scheduler. Before an upgrade always run it by hand (section 5). A cron example for
the disabled-scheduler case, in the crontab of a user in the `docker` group:

```
17 3 * * *  cd /srv/nzbd/deploy && docker compose exec -T nzbd /nzbd backup >> /var/log/nzbd-backup.log 2>&1
```

### File modes

SQLite: the database `data/nzbd.sqlite` and its `-wal` and `-shm` files are mode 0600, owned by the container user (`$IDS`) (SEC-102: a
group- or world-readable file owned by the service is set to 0600 with a warning; a file owned by someone else, a
symlink or a group/other-writable directory is refused with `DB_FILE_MODE`). Backups, the restore anchor and the
failed-file `.reason.json` sidecars are 0600 too; `paths.state` is 0700. Restore keeps this rule (restore steps below).

### Blob size cap

Reading a blob into memory (downloads and the explorer: there is no `store get` command) refuses any file larger than
`2 * limits.max_file_bytes` (128 MiB by default) with a "corrupt" error instead of loading it. Real blobs are never
above `limits.max_file_bytes`; a refusal means the file in `store/` was replaced or grown by hand. Do not raise the
limit: run `store verify` (it reports the blob), then restore that blob from your copy.

### Copy off-host

Backups are on the same disk as the data; a disk loss takes both. Copy them away (encrypted, see above, or encrypt the
copy: they hold password and key hashes), **together with `data/store/`** and the anchor line `nzbd backup` printed.
With a tools container (works whoever owns `data/`):

```
docker run --rm -u "$IDS" -v "$PWD/data/backups:/b:ro" --entrypoint tar caddy:2 -C /b -cf - . > nzbd-backups-$(date +%F).tar
docker run --rm -u "$IDS" -v "$PWD/data/store:/s:ro" --entrypoint tar caddy:2 -C /s -cf - . > nzbd-store-$(date +%F).tar
# then e.g.: age -p / gpg -c the tars (if the backups are not encrypted already), and move them off the host
```

Back up the key once, right after `keygen`, and again after every rotation:

```
docker run --rm -u "$IDS" -v nzbd_secrets:/s:ro --entrypoint cat caddy:2 /s/nzbd_totp_key > totp_key.backup
chmod 0400 totp_key.backup      # keep it in a password manager or on an offline medium, NOT next to the DB backups
```

Warning: `docker compose down -v` and `docker volume rm nzbd_secrets` delete the key. `docker compose down`
(without `-v`) is safe.

### Restore the database from a backup

Use this after disk loss, corruption (`nzbd health` shows Database integrity FAIL, or SQLite `nzbd db check --full`
exits 2) or a bad upgrade. Every nzbd backup is **restore-pending**: whatever puts it back in place, `serve` refuses it
(`RESTORE_PENDING`) until step "finish" below has run (SEC-068/SEC-094). The NZB files are not in the database backup:
restore `data/store/` from your copy too if it was lost.

#### Restore (SQLite)

1. Stop the app (the proxy may keep running): `docker compose stop nzbd`
2. Set the broken database aside (do not delete it; its `-wal` and `-shm` must not stay next to the restored file),
   then put the chosen backup in place, owned by the container user (`$IDS`), mode 0600. Encrypted backup:

   ```
   docker run --rm -u "$IDS" -v "$PWD/data:/d" --entrypoint sh caddy:2 -c '
     set -e; cd /d; ls -l backups                    # pick one
     mkdir -p broken-$(date +%F)
     for x in nzbd.sqlite nzbd.sqlite-wal nzbd.sqlite-shm; do [ ! -e $x ] || mv $x broken-$(date +%F)/; done'
   docker compose run --rm --no-deps nzbd backup decrypt /data/backups/nzbd-YYYYMMDDTHHMMSSZ.sqlite.enc --out /data/nzbd.sqlite
   ```

   Plaintext backup: in the tools container, `cp backups/nzbd-YYYYMMDDTHHMMSSZ.sqlite nzbd.sqlite && chmod 0600 nzbd.sqlite`.
3. Continue with "Check and finish" below.

#### Restore (PostgreSQL)

A restore loads the snapshot export into a **fresh, empty** database at the same schema version, with the owner role,
in the one-shot `setup` service. It never overwrites a live database.

1. Stop the app: `docker compose stop nzbd`
2. Replace the database volume (keep the old one until the restore is verified, by renaming it through a copy or by
   restoring into a new install directory; Docker cannot rename volumes):

   ```
   docker compose stop postgres && docker compose rm -f postgres
   docker volume rm nzbd_pg_data                      # only once you have a verified backup and, ideally, an off-host copy
   docker compose up -d postgres                      # a new cluster; roles from the existing password files
   docker compose --profile setup run --rm setup      # the schema (db migrate --yes)
   docker compose --profile setup run --rm setup db restore /data/backups/nzbd-YYYYMMDDTHHMMSSZ.nzbdpg.enc
   ```

   `nzbd` must stay stopped: `setup` refuses to migrate or restore while app-role sessions exist (`APP_SESSIONS_ACTIVE`;
   `--force` only if you know they are not a server). `setup` sees `backups/` read-only; an encrypted backup is
   decrypted into `data/tmp/.nzbd-restore.plain.tmp` (0600), which the restore removes before it starts and when it
   ends; after a crash (power loss) delete that file yourself or run the restore again.

   `db restore` verifies the whole file against its manifest first (table set, byte counts, digests; an encrypted file
   is authenticated with the configured backup key), sets `restore_pending` in its first transaction (an interrupted
   restore is never servable), loads every table in one transaction, recomputes the per-category totals and the identity
   sequences, and verifies the audit chain. It refuses a non-empty database or another schema version. The search index
   is not in the backup: it is rebuilt after the restore.
3. Continue with "Check and finish" below.

#### Check and finish (both backends)

1. Check the restored database against the NZB files (offline, nothing changes):
   `docker compose run --rm --no-deps nzbd store verify`
   - `N release(s), 0 blob(s) missing` and `store ok`: consistent.
   - `missing: <sha>` lines: the backup knows releases whose file is gone (restored from an older store?). Restore the
     files from your store copy; the entry stays but download and explorer fail with `BLOB_UNAVAILABLE` until then.
2. Check what the store has that the database does not know:
   `docker compose run --rm --no-deps nzbd store gc` (dry run, only prints). Files listed as candidates and "look
   suspicious" are NZBs ingested **after** the backup was taken: the store holds the only copy.
3. **Finish the restore, before the server starts** (mandatory: `serve` refuses the library until then). A restored
   database silently undoes everything done since the snapshot: **revoked API keys work again** (they have no idle
   expiry), re-enabled accounts, reverted roles, **password hashes and spent TOTP steps** (an old password works again,
   a code spent after the snapshot can be replayed), open invitations, recovery codes and sessions. One command does the
   part code can do, in one transaction and with one audit row:

   ```
   docker compose run --rm --no-deps nzbd db restore-finish --dry-run   # counts only, changes nothing
   docker compose run --rm --no-deps nzbd db restore-finish --yes
   ```

   It deletes every session, open invitation, MFA recovery code, staged credential and throttle row, clears every
   pending MFA enrollment token (re-issue with `user enroll-token`), **revokes ALL API keys**, rotates the search index
   epoch (the index is rebuilt), clears the restore mark, rewrites the restore anchor in `paths.state` from the restored
   database, then prints every account with role and enabled/disabled state, the audit chain anchor and the next steps.
   It is idempotent; run it again if in doubt. Then do what only you can: (a) compare the account list with what you
   expect: roles, disabled state and password hashes are exactly as the snapshot had them (`nzbd user set-role`,
   `disable`, `reset-password`, `reset-mfa` fix them; assume any password changed after the snapshot is the old one
   again); (b) re-issue the API keys you still need (`apikey create`); (c) re-invite accounts created after the
   snapshot; (d) compare the printed anchor with the `audit chain anchor` lines logged before the restore (section 9): a
   lower `rows` or a different head is expected after an older backup, an unexplained one is not.
   Stop `nzbd` first: with the server running the command fails with a "database is in use" hint.
4. Start: `docker compose up -d`, then `docker compose exec nzbd /nzbd health` and `... /nzbd audit verify`. The
   search index is rebuilt in the background (`nzbd search status`); lists are served in a degraded, bounded mode
   until it is ready.
5. Re-index the NZBs that were newer than the backup: copy each candidate file listed in step 2
   (`data/store/<sha[0:2]>/<sha[2:4]>/<sha>.nzb`) into `data/watch/`. The pipeline re-processes them normally; storing an
   identical file is idempotent (INGEST_SPEC crash table: "after store.put, before commit").

**The key must match the database.** A backup is only usable with the TOTP key that was current when its TOTP secret was
sealed. If the key is gone or different, login stops at the MFA step with a generic error: restore the key from
your offline copy (below), or install a new key and run `user reset-mfa` (section 3).

### Restores nzbd did not perform: `RESTORE_DETECTED` and its residuals

Not every rollback goes through an nzbd backup: a volume or NAS snapshot, a copy of `nzbd.sqlite` put back by hand, a
PostgreSQL point-in-time or `pg_basebackup` restore, an operator `pg_dump` load. `serve` keeps the restore anchor
`paths.state/db-anchor.json` (0600; on its own volume `nzbd_state`): the library identity (backend, instance id,
PostgreSQL `system_identifier`), the high-water marks of the audit, release and outbox sequences and the two audit class
heads. It is rewritten every 10 s while something changed and at shutdown. At startup (and before every CLI command but
`db check`, `search status`, `audit verify`, `backup` and `restore-finish`) a database **behind** the anchor is refused
with `RESTORE_DETECTED`; another library than the anchored one with `LIBRARY_MISMATCH`, an empty database where the
anchor names a library with `BACKEND_MISMATCH`. If the rollback was on purpose, run `db restore-finish --yes` (above);
it applies the same effects as after a backup restore and re-anchors.

**Residuals (honest):** (1) a rollback of the database **and** `paths.state` together is not detected: with SQLite that
is a snapshot of both the data directory and the `nzbd_state` volume (which is why the state is on its own
volume; health warns `ANCHOR_SAME_FILESYSTEM` if you moved it next to the database); with PostgreSQL a joint rollback
of `nzbd_pg_data` and `nzbd_state`. (2) Changes of the last ~10 s before the snapshot point. (3) PostgreSQL: a
point-in-time restore to fewer than ~32 audit rows before the anchor, with a retention purge in between. The external
control for all three is the `audit chain anchor` line you keep off-host (section 9).

### Why `store gc` must not be run right after a restore, and `gc-restore`

`store gc` quarantines blobs that no release row references. After restoring an older database, every blob ingested
since the backup is "unreferenced" yet is the only copy of the user's NZB. Protections: blobs younger than
`--grace-hours` (default 24, minimum 1) are never touched; without `--yes` it only prints a plan; with `--yes` it
**moves** blobs to `store/.gc-trash/` instead of unlinking; it refuses (needs `--force`) when the database has no
releases, when a candidate is newer than the newest release row, or when a candidate looks restored from a copy.

Rules: after any restore run `store verify` and a `store gc` dry run first, and never use `--force` until you
understand every candidate. If a gc run was a mistake, **`docker compose exec nzbd /nzbd store gc-restore`** puts all
quarantined blobs back (`restored N blob(s)`). Quarantined blobs older than 7 days are deleted for good by a *later*
`store gc --yes` run (never at startup), so restore within that window. Orphans caused by a crash mid-ingest are
harmless; reclaiming them is optional. The same applies to one narrow race in the upload path: when an API key is
revoked (or its owner disabled) in the instant between the early key check and the insert, the upload is discarded and
nothing is indexed, but the blob that was already stored stays as an orphan until `store gc` reclaims it.

### Restore the TOTP key

```
docker compose stop nzbd
docker run --rm -i -u "$IDS" -v nzbd_secrets:/s --entrypoint sh caddy:2 \
  -c 'umask 077 && cat > /s/nzbd_totp_key && chmod 0400 /s/nzbd_totp_key' < totp_key.backup
docker compose up -d
```

(If a key file already exists, move it aside first, section 3.) The file must be owned by the container user (`$IDS`) and mode 0400 or
the app refuses to start (SEC-042). On a brand-new host run `docker compose --profile setup run --rm keygen` first to
create the volume, then replace the file as shown. The backup encryption key is restored the same way (file
`nzbd_backup_key`).

### PostgreSQL maintenance

- **psql** (superuser, only from inside the container, peer authentication; the real server is on socket port 5432):
  `docker compose exec postgres psql -p 5432 -U postgres -d nzbd`. Never change grants, roles, triggers or functions by
  hand: the role design is what binds a compromised nzbd (OPERATOR_SECURITY "Choosing a backend").
- **Never mount `nzbd_pg_socket` into another container** that runs as uid 999 (it would be the superuser by peer
  authentication) or give it to other services: nzbd's own containers are the only clients.
- **Role bootstrap** (`migrations/v3/superuser/`) runs once when the cluster is created. It is idempotent; if a release
  note asks for it, re-run it: `docker compose exec postgres sh -c 'for f in /etc/nzbd-pg/superuser/*.sql; do psql -X -q -v ON_ERROR_STOP=1 -p 5432 -U postgres -d nzbd -f "$f"; done'`.
- **Schema migrations** run only from the `setup` service, **with nzbd stopped**: `docker compose stop nzbd`, then
  `docker compose --profile setup run --rm setup` (prints the plan and applies it; `... setup db migrate` without
  `--yes` only prints it), then `docker compose up -d`. A running `serve` would keep writing with the old semantics
  after the migration commits, so `setup` refuses while app-role sessions exist (`APP_SESSIONS_ACTIVE`). `serve` refuses a database with pending
  migrations (`MIGRATIONS_PENDING`).
- **Role passwords**: generated once by `dbsecrets` and read by the server only when the cluster is created. To rotate
  one: in `docker compose exec postgres psql -p 5432 -U postgres -d nzbd` run `\password nzbd_app` (psql asks twice
  without echo and sends only the SCRAM verifier: no plaintext in the server log or in `~/.psql_history`, which would
  live on the `pg_data` volume; never type `ALTER ROLE ... PASSWORD '...'` interactively), then write the same value to
  the 0400 file in its volume with a tools container (`umask 077 && cat > /s/nzbd_db_password` from stdin, as for the
  TOTP key), then restart nzbd. Rarely needed: nothing outside the socket can use them.
- **Major version upgrades** (e.g. 18 -> 19 when a release pins it): take an `nzbd backup`, create the new cluster in a
  new `nzbd_pg_data` volume and restore into it ("Restore (PostgreSQL)"); the snapshot export is portable across major
  versions. `pg_upgrade` is not supported by the shipped setup.
- **Physical backups** (`pg_basebackup`, PITR) are an expert option for very large installs: they contain the role
  password verifiers (`pg_authid`), must be encrypted by you, and a physical restore is detected as `RESTORE_DETECTED`
  and needs `db restore-finish` like any other.
- **Server settings** live in `deploy/postgres/postgresql.conf` (sizing for ~1M releases). Change the sizing block if
  you need to (and raise the container's `memory` limit with it); never the security block (logging, `listen_addresses`,
  `password_encryption`, `ssl`, `shared_preload_libraries`): the project's deployment check asserts it.

## 3. Key and credential rotation

### TOTP encryption key

**Rotation (the key is still available): `nzbd keys rotate-totp`.** All stored TOTP secrets are re-sealed under a new
key in one database transaction; nobody has to re-enroll, recovery codes and sessions are untouched. Stop the app
first (a running server holds the old key in memory).

```
docker compose stop nzbd
# 1. new key next to the old one (keygen refuses to overwrite; the secrets volume is the usual place)
docker compose --profile setup run --rm keygen keygen --out /run/secrets/nzbd_totp_key.new
# 2. rehearsal: checks that every secret opens under the current key, changes nothing
docker compose run --rm --no-deps nzbd keys rotate-totp --new-key-file /run/secrets/nzbd_totp_key.new --dry-run
# 3. the real run: takes a database backup first (encrypted if configured), then one transaction
docker compose run --rm --no-deps nzbd keys rotate-totp --new-key-file /run/secrets/nzbd_totp_key.new
# 4. swap the key files (keep the old one until a login worked), then start
docker run --rm -u "$IDS" -v nzbd_secrets:/s --entrypoint sh caddy:2 \
  -c 'cd /s && mv nzbd_totp_key nzbd_totp_key.old-$(date +%F) && mv nzbd_totp_key.new nzbd_totp_key'
docker compose up -d
```

(The `nzbd` service sees the secrets volume read-only at `/run/secrets`, which is all `rotate-totp` needs; only the
one-shot `keygen` service and the `docker run` of step 4 write to it.)

Crash safety: the old key file is never modified and the database changes in a single transaction, so an interrupted
run leaves the old state intact (re-run it). If step 3 completed but step 4 did not happen, the database is under
the new key while the app still has the old file: MFA fails closed (generic 500) until the files are swapped; re-running
step 3 is harmless ("already under the new key"). A secret that opens under neither key aborts the run with the
user id and changes nothing: restore the right key, or use `user reset-mfa` for that user. The command writes an audit
row `totp_key_rotated` (counts only) and prints counts, never key material. Afterwards back up the new key (section 2).
**An old backup of the database needs the OLD key** (its secrets are sealed under it): keep the old key file with
that backup generation until those backups have rotated out.

**Key lost and not recoverable: reset.** Without the old key the secrets cannot be re-sealed, so MFA must be
enrolled again. Do it only if the key is really gone, or was exposed and you also distrust every stored secret.

```
docker compose stop nzbd
docker run --rm -u "$IDS" -v nzbd_secrets:/s --entrypoint sh caddy:2 \
  -c 'mv /s/nzbd_totp_key /s/nzbd_totp_key.old-$(date +%F)'      # keep the old one until you have verified the new setup
docker compose --profile setup run --rm keygen                    # refuses to overwrite; makes the new key
docker compose up -d
docker compose exec -it nzbd /nzbd user reset-mfa                 # clears TOTP, recovery codes and all sessions; prints a token
```

Hand the token to the owner out of band; the owner signs in (proxy, then password) and re-enrolls with the new token
(INSTALL step 7), saves the new recovery codes. Then back up the new key (section 2). Until `reset-mfa` is run, the
MFA steps fail closed with a generic 500 error. API keys keep working.

### Backup encryption key

Rotate it by generating a new key file, pointing `maintenance.backup_encryption_key_file` at it and restarting; new
backups use the new key and **old encrypted backups still need the old key**, so keep the old key file with them
(or `nzbd backup decrypt` them with `--key-file OLD` into new plain files, then take a fresh backup, and retire both).
There is nothing to re-seal in the database.

### Proxy credentials

1. New password and hash (INSTALL step 2); edit `NZBD_PROXY_HASH` (and `NZBD_PROXY_USER`) in `deploy/.env`, hash in
   single quotes. (Traefik login generated by the installer: `NZBD_TRAEFIK_AUTH_USERS='user:hash'`. Simpler: re-run
   `./install.sh` without keeping the `.env`; the old one is saved as `.env.bak.<date>`.)
2. `./install.sh`, answer 2 (generate only) and keep the `.env`: `compose.yaml` holds the resolved values, so it must be
   regenerated after every `.env` change. Then `docker compose up -d` (recreates the containers whose configuration
   changed). Test with `curl -u user:pw`.
3. Update API clients (`-u` credentials) and any saved browser credentials.

The proxy has no rate limit and each bcrypt check is expensive: use 20+ random characters.

### Your own reverse proxy: header audit

With an existing proxy (Traefik, nginx, Caddy ...) its middlewares can replace the security headers nzbd sets
(OPERATOR_SECURITY.md, "Existing reverse proxy"). Check after installing, after every change of the proxy's
middlewares and after an upgrade:

```
cd deploy && ./audit-headers.sh https://nzbd.example.org --user admin   # --user only with an outer login; curl prompts
```

The reference is `docker compose exec -T nzbd /nzbd security-headers` (or `--expected FILE`); the page checked is
`/login`, fetched once over HTTPS without following redirects. Output, one line per header: `OK`, `CHANGED` (both
values printed), `MISSING`; `Strict-Transport-Security` `OK`/`WEAK`/`MISSING` (needs `max-age` >= 15552000); `INFO`
for `Server`/`X-Powered-By`. Exit 0 all OK, 1 findings, 2 usage error or the page could not be checked (DNS, TLS, the
proxy's own 401 page, a redirect). A `CHANGED` header is your proxy's decision, not an error of nzbd: keep it if you
want it, otherwise remove that header from the middleware.

### Application password, lockout

- Forgot the password, or you are locked out by failed attempts. The lock is per account **and client address
  (/64)**: 5 failures from one address lock the account for that address only, 1 min doubling up to 1 hour (5 minutes
  for an administrator); it resets after a completed login, after 24 h without failures, or with this command. Separately,
  20 failures in an hour from any addresses switch the account into *unknown-address throttling* (one attempt a minute
  from addresses that never completed a login; known addresses are unaffected; health WARN, audit `account_throttled`);
  `nzbd user unlock <name>` clears every lock and that state (AUTH_SPEC "Throttling"):
  `docker compose exec -it nzbd /nzbd user reset-password`
  It sets the new password, clears the lock, revokes all sessions **and all API keys**: recreate the keys afterwards.
- Lost authenticator and recovery codes: `docker compose exec -it nzbd /nzbd user reset-mfa` (prints a new token,
  clears TOTP, recovery codes and sessions). Run it only when the owner can enroll right away: until MFA is enrolled,
  whoever knows the password and the token can become the MFA holder.
- Token expired before enrolling (24 h): `docker compose exec -it nzbd /nzbd user enroll-token` (refused once MFA is
  enabled).
- Used up recovery codes: Account page, "regenerate recovery codes" (needs password and a current TOTP code).
- The enrollment token is printed once on stdout: do not run these commands in a terminal that is logged.
- There is no HTTP password-reset or registration endpoint, by design.

### Several accounts (v2)

One shared library, three roles (`viewer`, `uploader`, `admin`; D40: an uploader adds NZBs but edits no metadata, only admins change category and source label), invite-only. Everything below is off until
`security.multi_user = true` (restart); `security.registration_enabled = false` additionally removes the invitation
surface and leaves only recovery codes and `nzbd user create` (D28).

```
docker compose exec -it nzbd /nzbd user create <name> --role admin|uploader|viewer # prints a one-time enrollment token
docker compose exec nzbd /nzbd user invite <name> --role uploader|viewer           # prints a one-time invitation code + the page
docker compose exec nzbd /nzbd user list                                           # no secrets
docker compose exec nzbd /nzbd user set-role <name> <role>      # the ONLY way to grant or change admin
docker compose exec nzbd /nzbd user disable|enable|delete|unlock|revoke-sessions <name>
docker compose exec nzbd /nzbd user set-display-name <name> "Text"                 # empty text restores user-<id>
docker compose exec -it nzbd /nzbd user reset-password|reset-mfa|enroll-token [<name>]
```

- **Where invitees go (T135).** The invitation page is at `security.invite_path` (default `/invite`; installs made by
  `install.sh` since T135 get a random `/join-...` path in `config/nzbd.toml`). `nzbd config check`, `nzbd user invite` and the
  admin result pages print it, as the full address when `server.public_url` (or `server.allowed_hosts`) is set. With a
  custom path `/invite` is a plain 404, and the login page never links to the invitation page: hand the address over
  together with the code. `config check` warns `INVITE_PATH_DEFAULT` while multi-user mode still uses `/invite`. To move it, edit the key and `docker compose restart nzbd`; open codes stay valid (only the page moves).
  A refused value stops startup with `INVITE_PATH_INVALID` (one segment, 6-64 of `A-Z a-z 0-9 _ -`, not a built-in
  route or a prefix of one). It only hides the page from scanners; keep the proxy login in front of it.
- **Admins are never invited and never recovered over HTTP.** An admin account is created on the host
  (`user create --role admin`, hand the printed enrollment token over out of band). Recover an admin with
  `user reset-password <name>` and `user reset-mfa <name>` (or `user enroll-token <name>` while MFA is not enabled). The
  Users page can only revoke an admin's sessions, with password and a fresh code. Uploaders and viewers are recovered with
  *Issue recovery code* on the Users page: the code is single use (valid `security.recover_ttl_hours`, default 2), and the
  account's password and authenticator are replaced only when the person confirms the new authenticator, so an
  abandoned or cancelled recovery changes nothing.
- **"Username unavailable" for a name nobody uses as a login.** Invitees choose their own display name (D32), and a
  live display name blocks the same string (NOCASE) as a future login name for `user create`, `user invite` and the
  invitation form. If you need that login name, give the account holding it as a display name another one with
  *Set display name* on the Users page (or `user set-display-name <name> "Other"`); the string is then free.
- **Keep two enrolled admins.** The last enabled admin cannot be demoted, disabled or deleted (also not by the CLI), and
  a second admin must have MFA enrolled before the first can be disabled (the "last usable admin" rule).
- **A user reports a 404 on a page that should exist.** A refused role is the same 404 as an unknown path by design (no
  hint that the page exists). Look for an `authz_denied` audit row (Admin page; at most one per account per minute: it
  names the account, the role and the route class, never the path or any input). The usual cause is a viewer or uploader
  opening an admin page from a bookmark or an old link.
- **Throttle state.** `user list` and the Users page show *Locked* while a hard lock (5 failures per account and client
  address, 1 min doubling, 5 min cap for admins) or the account-wide throttle is in force. Health shows a WARN with the
  number of throttled accounts, and the audit has `account_throttled`. `user unlock <name>` (Users page: *Clear
  lockout*, uploaders and viewers only) clears every lock and the persisted counters at once. The counters survive a
  restart. A login from one of the account's last five completed-login addresses is never refused by the
  account-wide throttle, so after any `account_throttled` WARN sign in once from the trusted network (or run
  `user unlock <name>` and then sign in from there). An attacker who only knows a login name can keep a user
  signing in from a *new* address waiting this way; that is the accepted residual of D27.
- **NAT and proxies.** Locks and the login budget are keyed on the client address (IPv6: /64, plus a /48 bucket).
  Configure `server.trusted_proxies` so the app sees the real address; otherwise every user shares one key.
- **After a restore** the database is exactly as of the backup: revoked API keys are valid again, disabled accounts are
  enabled, roles and password hashes are the old ones, spent TOTP steps are forgotten, and open invitations, recovery
  codes and sessions are back. Run `nzbd db restore-finish --yes` (section 2, restore step 5) before starting the
  server: it revokes every API key and clears sessions, invitations, recovery codes and throttle state in one
  transaction, then lists the accounts so you can check roles and disabled state against what you expect. Re-issue the
  keys you still need. Open invitations are also revoked at startup while `multi_user` or
  `registration_enabled` is off, so flipping a switch back on never revives an old code.

### API keys

```
docker compose exec nzbd /nzbd apikey list                  # ID, prefix, label, owner, scope, rate, created, last used, status
docker compose exec -it nzbd /nzbd apikey create "label"    # prints the key once; owner = the oldest enabled admin
docker compose exec -it nzbd /nzbd apikey create "label" --user alice --rate 5   # owned by alice, 5 uploads/min
docker compose exec nzbd /nzbd apikey revoke <id>
```

Keys created on the command line without `--user` belong to the oldest enabled admin and therefore share that admin's single API upload budget (30/min) with the admin's other keys; use `--user` to give a script its own account and budget. Rotate: create the new key, switch the client, check `last used` on the old one, revoke it. At most 10 unrevoked keys
per owner (500 per instance). Every key belongs to one account and its uploads are attributed to that account; an owner
who is disabled or deleted loses the key's use at once (the key is refused like an unknown one); a demotion to viewer revokes the account's keys (the `role_change` audit row says how many), and promoting it back does not revive them.
Uploaders make and revoke their own keys on the Account page (needs a fresh TOTP code); an admin sees every key there and
can revoke any of them (the audit row names the admin and the owner). Keys are only accepted in the
`X-Api-Key` header, never in a URL.

## 4. Failed files, retention, duplicates, disk full

### Triage `failed/`

```
docker compose exec nzbd /nzbd failed list                       # NAME CODE TIME SIZE
docker compose exec nzbd /nzbd failed retry <name>               # one file, name exactly as listed
docker compose exec nzbd /nzbd failed retry --all
```

Retry moves the file back into `watch/` as `retry-<stem>.nzb` and removes its sidecar; it is re-processed like any new
file (exit 0 ok, 2 = some failed). Retry is only useful when the cause is fixed: a malformed file stays malformed.
The sidecar `<name>.reason.json` (mode 0600) holds `{version, writer, file, error_code, message, source, source_name,
sha256, size, at, retry_count}`. Read it with a tools container:
`docker run --rm -u "$IDS" -v "$PWD/data:/d:ro" --entrypoint sh caddy:2 -c 'cat /d/failed/*.reason.json'`.
A file without a sidecar is listed with code `-`, can still be retried and is never touched by retention. The Admin page
lists the newest 50 failures.

| Code | Meaning | What to do |
|---|---|---|
| `NZB_DOCTYPE_FORBIDDEN` | Contains a DTD, entity declaration or a DOCTYPE other than plain `<!DOCTYPE nzb ...>` (XXE and entity-expansion defence). | Almost always a crafted or non-NZB file. Inspect it before deciding. Do not try to "fix" the parser setting. |
| `NZB_NOT_UTF8` | Not valid UTF-8 (other encodings are not supported). | Re-save the NZB as UTF-8. |
| `NZB_EMPTY` | No `<nzb>` root or no `<file>` elements, or an empty document. | The file is not a usable NZB. |
| `NZB_MALFORMED` | Not well-formed XML or not NZB structure (missing attributes, bad numbers). | Get a fresh copy. |
| `NZB_LIMIT_*` | A parser limit was exceeded: `FILE_BYTES` (64 MiB), `XML_DEPTH` (8), `FILES` (10 000), `SEGMENTS_PER_FILE` (100 000), `TOTAL_SEGMENTS` (2 000 000), `SEGMENT_BYTES`, `TOTAL_BYTES`, `SUBJECT_BYTES`, `POSTER_BYTES`, `GROUP_BYTES`, `GROUPS_PER_FILE`, `MESSAGE_ID_BYTES`, `META_ENTRIES`, `META_VALUE_BYTES`. | Limits can only be lowered in config, not raised. A real NZB hitting one is unusual; the file is probably hostile or damaged. |
| `NZB_TIMEOUT` | Parsing exceeded `limits.parse_deadline_secs` (max 20 s). | Retry once (a loaded host can trip it); repeated timeouts mean a hostile file. |
| `FILE_TOO_LARGE` | Larger than `limits.max_file_bytes` (max 64 MiB). | Not an NZB you want, or lower-than-ceiling limit configured. |
| `INVALID_CATEGORY` | An upload carried a category that is not in the taxonomy. | `nzbd categories` lists valid slugs; re-upload with one. |
| `SOURCE_CHANGED` | The file changed while being read. | Transient: left in `watch/` and retried; finish writing it (write under a hidden/temp name, then rename). |
| `SOURCE_UNREADABLE` | Not a regular file, hard-linked (`nlink > 1`), or unreadable. | Replace by a plain copy. |
| `STORAGE_ERROR` | Database or blob store failure (disk full, permissions, I/O). | Check `nzbd health`, free disk, ownership of `data/`; the file is left for retry. |
| `INTERNAL` | Unexpected internal failure; after three panics a file is quarantined. | Keep the file and the log lines (`docker compose logs nzbd`) and report it. |

The same codes appear in the Admin ingest log and in API responses (`422` for `NZB_*`, `413` for `FILE_TOO_LARGE`,
`400` for `INVALID_CATEGORY`).

### Retention

`ingest.failed_retention_days = 0` (default) keeps failed files forever. With N > 0 (set `NZBD__ingest__failed_retention_days`)
files whose sidecar is older than N days are **moved** to `failed/expired/` (about 30 s after start and every 6 h);
nothing is ever deleted automatically. Reclaiming the disk space of `failed/` and `failed/expired/` is your decision:
use **Admin > Cleanup** (below). Rejected *uploads* are additionally rotated oldest-first beyond `ingest.failed_uploads_max_files`
(1000) / `failed_uploads_max_bytes` (1 GiB); watch-folder failures are never rotated.

### Cleanup: trash, blocked and failed (Admin > Cleanup)

Nothing is deleted automatically; the Cleanup page (`/admin/cleanup`, sidebar Manage > Cleanup) is where you reclaim space,
and it counts three buckets with their sizes:

| Bucket | What is in it | What a purge removes |
|---|---|---|
| Trash | releases you deleted in the UI (their NZB sits in `store/.trash/`), the garbage collector's `store/.gc-trash/` quarantine, and `.nzbd-trash.*` crash leftovers in `failed/` | the trash blobs and records; quarantine files **older than 7 days**; leftovers only when they are provably copies of something still indexed |
| Blocked | `failed/` and `failed/expired/` files rejected as hostile or against policy: `NZB_DOCTYPE_FORBIDDEN`, `NZB_NOT_UTF8`, `NZB_LIMIT_*`, `FILE_TOO_LARGE`, `INVALID_CATEGORY` | those files and their `.reason.json` |
| Failed | every other file there: `NZB_EMPTY`, `NZB_MALFORMED`, `NZB_TIMEOUT`, read/storage errors, unknown codes | the same, but only files that have a reason record |

How a purge works: the Purge button opens a confirmation page showing the counts; you type the bucket name, your password
and an authenticator code. Only files nzbd itself wrote are removed (valid reason record for exactly that file, content still
matching it); anything else, plus symlinks, hard-linked files and anything in `watch/`, `duplicates/`, `tmp/`, `backups/` or
the live store, is counted as skipped and left alone. The result page says how many were removed and skipped; the audit log
(`cleanup_purge bucket=... count=... bytes=... skipped=...`) records it without names. One purge runs at a time (30 s
cooldown, 120 s deadline per run; run it again if "not processed" is non-zero). **A purge is irreversible**; look in
`nzbd failed list` first if unsure, and `nzbd failed retry` anything you still want.

Headless equivalent (dry run unless `--yes`; exit 0 ok, 1 error, 2 something was refused or not processed):

```
docker compose exec nzbd /nzbd cleanup status
docker compose exec nzbd /nzbd cleanup purge --bucket blocked            # dry run: counts only
docker compose exec nzbd /nzbd cleanup purge --bucket blocked --yes
```

#### Deleting a release and restoring it

The **Delete release** button on a release page asks for the word `DELETE`, your password and an authenticator code. The
release disappears from the index at once; its NZB is moved to `store/.trash/`, where it stays until you purge the Trash
bucket. To bring one back:

```
docker compose exec nzbd /nzbd trash list              # ID, DELETED, SIZE, SHA, TITLE
docker compose exec nzbd /nzbd trash restore <id>      # writes restored-<sha8>.nzb into watch/; re-ingested as a new release
```

A restored release gets a new id and the category the rules decide (a manual category override is not kept). Restore
refuses if the same content is indexed again (then just purge the trash copy). Re-uploading the same file after a delete
simply creates a new release. Deleting does not free disk space until the Trash bucket is purged. If the NZB is no longer
in the trash (purged), restore says so.

**Bulk delete (T119, admins).** Tick several rows on the index or a search result and press *Delete selected...* (up to
100 per request). The confirmation page lists the titles and asks for `DELETE`, your password and a fresh authenticator
code, like a single delete (wrong attempts count toward the same lockout). Each release is moved to the trash separately,
so a release that fails (the result page says which, and the server log says why) stays in the index while the others are
done; `nzbd trash list` shows what was moved. The audit log has one `release_delete` row per release plus one
`bulk_delete` row (counts only). If a selection contains an id that no longer exists or is hidden, nothing is changed and
the answer is a plain "not found": reload the list and select again. Error codes of the selection form: `NO_SELECTION`,
`TOO_MANY_IDS`, `INVALID_ID`, `BAD_ACTION`, `INVALID_CATEGORY`. The request timeout (15 s) applies to the page, not to the
work: if a very large or slow bulk delete answers `504`, or the error page says `BULK_RESULT_UNKNOWN`, the moves still run
to completion and the `bulk_delete` row is written. Check `nzbd trash list` / Admin > Cleanup and the audit log instead of
repeating the request (a repeat is a plain "not found" because the ids are gone). A release whose id was reused by a
different NZB is never deleted: if it happened after the confirmation page was opened, submitting it shows the page
again ("The selection changed since you opened this page; review it again." / "This release changed ...") without
using up your code, so review the list and confirm again; if it happens during the delete itself the release is
reported as "Kept" (single delete: "not found"). Scripts that post the delete forms must send the `sel` (bulk) or `sha`
(single) field from the confirmation page. Admins may send at most 10 bulk edit requests per minute
(`429 RATE_LIMITED` with `Retry-After` beyond); a repeated single-value form field is `400 BAD_REQUEST`. A `bulk_delete` row with `aborted=1` means the acting admin was disabled, demoted or
deleted during the run: the remaining releases were left alone. Bulk category and source edits (admins only, D40)
write the usual `category_override` / `source_label_edit` row per release (old and new value, so an edit can be undone)
plus one `bulk_edit_category` / `bulk_edit_source` row.

**Bulk download (T130, every role).** *Download selected (.zip)* under the result list sends up to 100 ticked releases
as one uncompressed zip (`nzbd-<n>-releases-<UTC time>.zip`). Releases deleted meanwhile or hidden from the account are
left out silently; if none is left the answer is "not found". Limits: 1 GiB of stored NZB data per zip
(`413 BULK_DOWNLOAD_TOO_LARGE`), one bulk download at a time for the whole instance and one per account (`503 BUSY`,
`Retry-After: 30`, which does not use up the per-minute budget; it also holds one of the two download slots, so one
single download can still run next to it), two per minute per address and per account on top of the download limits
(`429 RATE_LIMITED`; behind a shared NAT the per-address two are shared by everyone there), a send deadline of 60 s
plus 1 s per MiB (at most 4 min 30 s, below the shipped Caddy's 5-minute write timeout) and a minimum speed (after 30 s,
at least 256 KiB per 30 s). A very large zip on a slow link can be cut off (the log says `bulk download deadline
exceeded` or `reader too slow`): tick fewer releases; do not raise Caddy's `write` timeout. A release deleted while
its zip streams is left out (info log `release gone during bulk download, entry skipped`).
The audit log gets one `download_bulk count=<n>` row. If a stored NZB is missing or corrupt the download breaks off in
the browser (no complete-looking zip) and the server log has `stored NZB unavailable, bulk download aborted` with the
release id and `missing`/`corrupt`/`io`: check the store as for a single download (`nzbd store verify`).

### Duplicates

A file whose SHA-256 is already indexed is moved to `duplicates/` (default; `ingest.duplicates_action = "delete"`
removes the extra copy instead). Nothing in `duplicates/` is read again; the content is identical to an indexed NZB,
so removing old files there by hand is safe. Duplicate *uploads* are acknowledged (`200 duplicate`) and not kept.

### Watch-folder rules (3.2)

`[[ingest.rules]]` (CONFIGURATION §Watch-folder rules) give watch files a category and/or a source label by first-level
sub-folder or file-name pattern. After editing them:

```sh
docker compose exec nzbd /nzbd watch rules     # validates the rules, then a dry run over data/watch/
# watch rules: 2 (ingest.recursive = true, ingest.category_from_subfolder = false)
#   #1 subfolder = "From Seedbox" -> label "seedbox"
#   #2 filename = "(?i)\\.s\\d{2}e\\d{2}\\." -> category tv.hd
#
# watch folder /data/watch: 2 file(s), 0 other entr(ies) ignored. Dry run: nothing is moved or ingested.
#   "From Seedbox/x.nzb": rule #1: label "seedbox" (new releases only)
#   "Show.S01E02.nzb": rule #2: category tv.hd
docker compose restart nzbd                     # rules are read at startup
```

An invalid rule stops `serve` (and `config check`) with `RULE_BAD_SUBFOLDER`, `RULE_BAD_REGEX`, `RULE_UNKNOWN_CATEGORY`,
`RULE_NO_ACTION`, `RULE_TWO_MATCHERS`, `RULE_NO_MATCHER` or `RULE_TOO_MANY` and the rule number: fix that rule, check
again. Which rule matched is in the ingest log (Admin, `detail` `rule=N`) and the container log (`watch rule matched`).
A rule category is a hint: a recognised Scene name still decides (`hint_disagreement` in the detail). Labels are set only
when a release is created; to relabel existing releases use the bulk source edit. Uploads and `nzbd import` ignore rules.

### Disk full

- Uploads (UI and API) answer `507 INSUFFICIENT_STORAGE` with `Retry-After: 60` when `tmp/` or `store/` has less free
  space than max(1 GiB, 5 % of the volume). Nothing is staged. The watch folder is not guarded by this: a flood of
  files can still fill the disk.
- Health shows WARN below 10 % or 1 GiB and FAIL below 2 % or 64 MiB.
- To recover: free space (move `failed/expired/`, `duplicates/`, old `backups/`, or grow the volume), then watch the
  health page return to OK. Failed ingests that hit `STORAGE_ERROR` are retried automatically; nothing is lost because the
  source stays in `watch/` until the database commit.
- Prevent: size the volume for the library plus headroom, and alert on the weekly check.

## 5. Upgrade and rollback

**Coming from nzbd 2.x (or older): there is no upgrade.** nzbd 3 starts a new library (D37). A 2.x database is refused
with `LEGACY_DATABASE` and left byte-identical; nothing migrates it. Install v3 next to it with a **new data
directory** (the installer detects the 2.x `.env`, keeps it as `.env.bak.<time>` and refuses the old data directory),
create your accounts again, and bring the NZB files over with `nzbd import` (below; or copy them into the new watch
folder). Keep the 2.x data directory and a 2.x backup until you no longer need them; the 2.x images and tags still run
it.

### Refill a new library from 2.x NZB files (`nzbd import`)

`nzbd import <dir>` re-ingests every `*.nzb` below a directory through the normal pipeline (same parser, limits and
categories as the watch folder). The directory is **read only** for nzbd: files are copied into the new store, never
moved, renamed or deleted, whatever happens. A 2.x `data/store/` (`aa/bb/<sha256>.nzb`) works as it is; its hidden
`.trash/`, `.tmp/` and `.gc-trash/` folders are not imported (releases deleted in 2.x are not brought back). A 2.x install with the
`db` blob backend must first export its files with 2.x's own `nzbd store migrate --to fs`. What does **not** come
across: accounts, API keys, sessions, the audit and ingest history, manual category changes and source labels.

1. Mount the old files read-only into a one-off container and make them readable for the container user (`$IDS`) (or copy them
   somewhere first). Never point the import at the new library's own `data/` or any directory nzbd manages: it is
   refused with `IMPORT_DIR_OVERLAP`, decided on the directory's identity (device and inode of it and its parents), so
   a symlink, a `..` spelling or a bind mount of e.g. `data/tmp/` is refused too. `docker compose run` already runs as
   the service user (the container user); the command refuses to run as root (its files would be unreadable for `serve`)
   unless `--allow-root`.
2. **SQLite:** stop the server first (`SERVE_RUNNING` otherwise: SQLite has one writer, and a bulk import next to a
   running server could make logins wait). **PostgreSQL:** the server can keep running; it indexes the new releases
   as they arrive, and the import waits whenever the server's watch-folder scanner pauses for the index lag
   (`search.lag_pause_rows`), with a progress line "waiting for the search index to catch up".

```
docker compose stop nzbd                                              # SQLite only
docker compose run --rm --no-deps -v /srv/nzbd-2x/data/store:/import:ro nzbd import /import
docker compose start nzbd                                             # SQLite only
```

Progress lines go to stderr every 5 s; the summary lists files, imported, duplicates (already in the library),
trashed (releases deleted from this library: their digest is in the trash, so a re-run does not bring them back; add
`--include-deleted` to restore them on purpose), failed (by error code), skipped (symbolic links, FIFOs/sockets/devices, too large, too deep: the walk never follows a
link) and ignored entries, plus the first 50 problem names (escaped). Exit 0 = everything is in the library, 2 =
something was skipped, trashed, failed, cut by `--max-entries` or interrupted, 1 = refused. **Run it again** whenever
it stops or you add files: files already in the library are recognised by their SHA-256 and skipped without a log
line, so nothing is imported twice, and releases an administrator deleted since stay deleted (`TRASHED`). Options: `--max-depth N` (default 8, at most 32; a 2.x store needs 2) and
`--max-entries N` (default 5,000,000 directory entries). Rejected files are not copied to `failed/`; fix or remove them
in the source and run again. The run is audited as `library_import` (actor `cli`, counts only); its ingest log rows say `import` in the detail
column (they are recorded with source `watch`, unattributed).
On PostgreSQL the import opens its own connection pools next to the server's; with the shipped `max_connections = 30`
another CLI command or `psql` during a large import can be refused for lack of connections (try again after it). On SQLite the new
releases are indexed when `serve` starts again: until the backlog is done the **Search index lag** health line is WARN
and new lists fill up gradually (the browse still works). Speed depends on the disk (each file is written with an
fsync) and on NZB size; nothing was benchmarked yet (T117).

**Within 3.x.** Migrations are **forward-only**: an older binary must not be started on a database that a newer one
migrated. The pre-upgrade backup is your rollback. SQLite migrates on start (behind the `503 STARTING` page);
PostgreSQL is migrated by the one-shot `setup` service (the installer runs it), never by `serve`.

```
cd nzbd && git fetch && git log --oneline HEAD..origin/main          # read what changes; see docs/CHANGELOG.md
cd deploy
docker compose exec nzbd /nzbd backup                                 # 1. backup (note the anchor line it prints)
docker run --rm -u "$IDS" -v "$PWD/data/backups:/b:ro" --entrypoint tar caddy:2 -C /b -cf - . > pre-upgrade.tar   # off-host copy
docker tag nzbd:local nzbd:previous                                   # 2. keep the old image for rollback
git pull --ff-only                                                    # 3. new code
./install.sh                                                          # 4. answer 1 (deploy), keep the existing .env
docker compose ps && docker compose exec nzbd /nzbd health            # 5. verify (healthy, exit 0)
```

Step 4 regenerates `deploy/compose.yaml` from the new templates in `compose-example/` and your `.env`, rebuilds the
images, (PostgreSQL: starts `postgres` and runs `setup`, which applies new migrations) recreates the changed containers
and waits until nzbd is healthy; it never touches the keys or database passwords, never switches the backend and deletes
nothing. Answer no when it offers to create a user. If you prefer to build and start by hand: answer 2 (generate only),
then `docker compose build`, PostgreSQL: `docker compose stop nzbd && docker compose up -d postgres && docker compose
--profile setup run --rm setup`, then `docker compose up -d`. (The installer stops nzbd before `setup` itself.) With your own reverse proxy, re-run the header audit afterwards (section 3).

Roll back (only when the new version misbehaves):

1. `docker compose stop nzbd`
2. `git checkout <old tag/commit>` and `docker tag nzbd:previous nzbd:local`.
3. Restore the pre-upgrade backup (section 2, "Restore (SQLite)" or "Restore (PostgreSQL)", then "Check and finish"):
   the new version may have migrated the schema, and an older binary must never start on it.
4. Re-run the old version's `./install.sh`, keep the existing `.env` (answer 1): it writes that version's compose setup
   again and starts it. Then `docker compose exec nzbd /nzbd health`.

Data ingested since the upgrade appears as store-only files (section 2, "Check and finish" steps 2 and 5 re-index them).

**3.1 -> 3.2 (saved searches, D38 d).** 3.2 adds one table (`saved_search`: PostgreSQL migration `0008`, SQLite
migration `0002`), so **3.2 is not database-compatible with 3.1**: once 3.2 has started (SQLite) or `setup` has
migrated (PostgreSQL), a 3.1 binary refuses the database (SQLite: `migration failed ... VersionMissing(2)` before any
check or change; PostgreSQL: readiness `SCHEMA_NEWER`). That refusal is the safety net, not a fault: **rollback = the
steps above with the pre-upgrade backup** (taken in step 1 of the upgrade). Like any rollback it loses what the
database recorded after that backup, here including every saved search (new NZBs come back as store-only files, as
above). Saved searches are included in every later backup and
restore (SQLite: the whole file; PostgreSQL: the snapshot exports `saved_search` like `user_pref`). The upgrade itself is tested on both backends by
`upgrade_3_1_to_3_2_keeps_data_and_adds_saved_search` / `pg_upgrade_3_1_to_3_2_keeps_data_and_adds_saved_search`
(`crates/nzb-store/src/upgrade_tests.rs`, in `scripts/dev ci`).

Base images are pinned by digest in `deploy/Dockerfile`, `deploy/Dockerfile.proxy` and
`deploy/compose-example/compose.postgres.yaml`. A rebuild does not change them; bump digests deliberately.

### Restore drill (practice it before you need it)

A backup you never restored is a hope, not a backup. Practise this drill; it never touches production:

- **By hand, on a copy of your own data** (recommended after any change to your backup routine): restore your latest
  backup into a scratch install directory (a second checkout with its own `NZBD_DATA_DIR`, and for PostgreSQL its own
  compose project name, e.g. `docker compose -p nzbdtest ...`) following section 2, then run `store verify`,
  `audit verify` and `health` there. Delete the scratch install afterwards (it contains your TOTP-sealed secrets).

## 6. Troubleshooting

### Production

| Symptom | Likely cause | Fix |
|---|---|---|
| `nzbd` refuses to start with `DB_FILE_MODE` (3.x, SQLite backend) | SEC-102: the database directory is writable by group/other (a NAS bind mount often reports 0777), or the database file (or `-wal`/`-shm`) is a symbolic link, not a regular file, has a second name (hard link) or belongs to another uid. A file of the service uid that is merely group/other-readable is fixed to 0600 with a warning instead. | `chmod 0750` the data directory (`chmod -R u=rwX,go= data/` on a bind mount), replace a link with the real file, remove the extra hard link, `chown -h "$IDS"` the files (the container user). |
| `nzbd` refuses to start with `LEGACY_DATABASE` (3.x) | `paths.db` points at a 2.x (or older) database. 3.x starts from a fresh library and never upgrades or modifies a 2.x file (D37). | Point `paths.db` at a new file (or an empty directory) and bring the NZB files in with `nzbd import <dir>`; keep the 2.x data directory as it is. |
| Every page returns `400 BAD_HOST` | Browser uses a name that is not `localhost`, an IP literal or in `server.allowed_hosts`; compose derives it from `NZBD_SITE`. | Browse to exactly `https://<NZBD_SITE>/`, or set `NZBD_SITE` in `deploy/.env` to the name you use (lowercase, no port) and `docker compose up -d`. Several names: add them in `compose.override.yaml` with `NZBD__server__allowed_hosts='["a.lan","b.lan"]'`. |
| Login or any form POST shows `CSRF_REJECTED` | The app requires the browser's `Sec-Fetch-Site` header and an `Origin` equal to the host. Missing on Safari < 16.4, some very old browsers and privacy tools that strip headers; or the page was opened under another name/scheme than the form posts to; or the session/token expired. | Use a current browser, one stable URL (`https://<NZBD_SITE>/`), reload the page and retry. There is intentionally no weaker fallback. |
| `429` / "Rate limited" | Per-IP throttles (login 10 POST/min, UI 300/min, downloads 30/min, uploads 60/min/IP and 30/min per API key or per account, 20 per hour failures per account) or lockout after failed logins. Behind Docker Desktop all LAN clients share one IP. | Wait `Retry-After` seconds. Throttle batch API uploads below 30/min. Lockout: wait, finish a login, or `user reset-password`. |
| Browser asks for a password and rejects it (`401` from the proxy) | Wrong proxy user/password; `NZBD_PROXY_HASH` not single-quoted (`$` mangled); `.env` changed without `docker compose up -d`; API client without `-u`. | Regenerate the hash (INSTALL step 2), single-quote it, `docker compose up -d`. `docker compose logs proxy` shows Caddy configuration errors. |
| Browser warns about the certificate | The proxy CA is not trusted on this device, or you browse by IP instead of `NZBD_SITE`. | Install the root (INSTALL step 6) and use the site name. |
| `docker compose up` fails: "Address already in use" / "Pool overlaps" | The fixed proxy address or subnet collides with another Docker network. | Set `NZBD_BACK_SUBNET`, `NZBD_PROXY_IP`, `NZBD_BACK_RANGE` in `.env` to an unused /24 (proxy IP inside the subnet, outside the range). |
| Port 443 already in use | Another service on the host. | Set `NZBD_HTTPS_PORT` (and browse with `:port`), or `NZBD_BIND` to a different address. |
| nzbd log: `LEGACY_DATABASE` | The data directory holds a 2.x (or older) database. v3 starts a new library and never touches it. | Point `NZBD_DATA_DIR` at a new directory (section 5, "Coming from nzbd 2.x"). |
| nzbd log: `MIGRATIONS_PENDING` (PostgreSQL) | The schema is older than the binary; `serve` never migrates. | `docker compose stop nzbd`, `docker compose --profile setup run --rm setup`, then `docker compose up -d`. |
| `setup` says `APP_SESSIONS_ACTIVE` | nzbd (or another app-role client) is connected; a migration or restore under a live server is refused. | `docker compose stop nzbd` and run it again. |
| nzbd log: `RESTORE_PENDING` | A restored backup (every nzbd backup carries the mark) has not been finished. | Section 2, "Check and finish" step 3 (`db restore-finish --yes`). |
| nzbd log: `RESTORE_DETECTED` / `LIBRARY_MISMATCH` / `BACKEND_MISMATCH` | The database is behind the restore anchor in `paths.state`, is another library, or is empty while the anchor names one: a rollback or restore nzbd did not perform, a changed `paths.db`, or a switched `NZBD_DB_BACKEND`. | If the rollback was intended: `db restore-finish --yes` (section 2). Otherwise find out what replaced the database before anything else; never switch `NZBD_DB_BACKEND` of an existing library. |
| nzbd log: `OWNER_SECRET_VISIBLE` | The PostgreSQL owner password is readable by `serve` (someone mounted `nzbd_setup_secrets` into `nzbd`). | Remove that mount; only the `setup` service may have it. |
| nzbd log: `DB_ENV_AMBIGUOUS` | A libpq `PG*` or `SSL_CERT_*` variable is set for `nzbd` (PostgreSQL backend). | Remove it from the environment / compose override; nzbd takes every database setting from its config. |
| install.sh: "the key volumes are not owned by UID:GID" (volperms: "holds files of another user") | The key volumes come from an earlier install that ran as another `NZBD_UID:NZBD_GID`. nzbd never re-owns or deletes them (fresh starts only, owner decision 2026-10-16). | Put the old UID:GID back into `.env` and re-run, or start fresh: back up what you still need (section 2: key, backups), then `docker compose --profile setup down -v` (deletes the TOTP key, the state and, with PostgreSQL, the database volumes; the data directory stays) and re-run `./install.sh`. |
| `keygen` or `serve`: permission denied on `/run/secrets` or `/state` | The volumes were created without the `volperms` step for a custom `NZBD_UID` (Docker hands an empty volume to the image's uid 10001). | `docker compose --profile setup run --rm volperms`, then repeat the step (`./install.sh` does it in order). |
| nzbd log: `DB_FILE_MODE` (SQLite) | The database file is not owned by the container user (`$IDS`), is a symlink, or its directory is writable by group/other. | `chown -h "$IDS"` the file (as root in a tools container: `docker run --rm -u 0 -v "$PWD/data:/d" --entrypoint chown caddy:2 -h "$IDS" /d/nzbd.sqlite`), `chmod 0750` the directory (section 2). |
| `postgres` unhealthy / restarting | First start without the password files (`dbsecrets` not run), a full disk, or a hand-edited `postgresql.conf`. | `docker compose logs postgres`; run `docker compose --profile setup run --rm dbsecrets`; check `docker system df -v`. |
| `nzbd` container `unhealthy` / restarting | Startup validation failed. `docker compose logs nzbd` and `docker compose run --rm --no-deps nzbd config check` print the reason: a missing directory under `data/`, wrong ownership (not the container user, `NZBD_UID:NZBD_GID`), key file missing or not 0400 / not owned by the container user (`$IDS`), overlapping paths, bad config key. | Fix the named item (INSTALL steps 3-4); `docker compose up -d`. |
| `nzbd` reports `starting` (health log `starting: ...`, browsers and the proxy see a `503` "Starting" page with `Retry-After`) for a while after a start or upgrade, no errors in the log | The listener is up from the first moment (T088) but the database is still being opened: with pending migrations nzbd first runs the full integrity and foreign-key check (so a damaged file fails before anything modifies it) and then applies them; the log shows `database check started`, `migration started` / `migration still running` (every 15 s) / `migration finished` per migration. Measured (`docs/BENCHMARK.md`): a 1,000,000-release database at migration 0009 opens in about 23 s on the test host; on a 1 M library of real NZBs the full check alone is about 2 minutes cold, plus about 2 minutes once for the five indexes of migration 0010. Without pending migrations the default `fast` startup check takes milliseconds, so this window is only seen on upgrades. | Wait; `docker compose logs nzbd` shows progress and then `ready`. It is not a restart loop unless the process exits; do not delete `nzbd.sqlite`. `docker compose stop` during the window is safe (an interrupted migration is rolled back and re-run). The image's `HEALTHCHECK` has `--start-period=600s`, so this window does not count as failing; `nzbd healthcheck` prints `starting:` (exit 1, container still `starting`) instead of `unhealthy:`. A log line `migration failed: while executing migration 10 ... database or disk is full` means the build predates the `temp_store=MEMORY` fix (T087-H1): the 16 MiB `/tmp` tmpfs overflowed; upgrade to the fixed image (data is untouched). |
| `nzbd` `unhealthy` (not `starting`) right after a start | The process is up but `/healthz` answers an ordinary `503` (the ingest scan loop's heartbeat is stale) or nothing listens (it exited; check `docker compose logs nzbd` for `database: database integrity check failed` and restore from a backup, section 2). | `nzbd healthcheck` output is in `docker inspect --format '{{json .State.Health}}' <container>`. Run `nzbd db check --full` on a copy if a damaged file is suspected: the default startup check is bounded and does not read the bulk tables. |
| Container healthy, but files are not picked up or nothing appears in the index | The file must be a regular file named `*.nzb` (case-insensitive), not hidden (leading `.`), not a temp name (`~`, `.part`, `.tmp`, `.crdownload`), not a symlink, not hard-linked, not larger than `max_file_bytes`, and unchanged (size and mtime) for `stable_secs` (5 s); the scan interval is 5 s. Sub-folders are ignored unless `ingest.recursive = true`. Files must be readable by the container user (`NZBD_UID`). Hidden files and symlinks are skipped silently. | Check name and type; wait 10-15 s; make files readable; look at `failed list` and the ingest log. On network shares the periodic scan (not inotify) does the work, so allow for the interval. |
| Segment counts shown as `N/N`, completeness 100 %, no "Incomplete" badge | By design: nzbd has no news-server check, and gaps in an NZB's own numbering are not availability. The switch `SEGMENT_HEALTH_CHECK_AVAILABLE` in `nzb-web` is `false` until a real health check exists (`docs/UI_NOTES.md`). | Nothing to fix. The explorer and the Missing column still show gaps in the NZB's structure. |
| `nzbd health` exits 2 with only "Liveness probe (/healthz): no 200 answer" failing | The CLI ran in a one-off container (`docker run`, `compose run`) where no server runs, so the probe has nothing to reach. | Use `docker compose exec nzbd /nzbd health` against the running container. |
| Health WARN "Database backups" | No backup yet, older than 3 days, or unreadable `backups/`. | Scheduler disabled (`maintenance.backup_interval_hours = 0`) or failing: read `docker compose logs nzbd` and run `nzbd backup` (section 2). |
| Upload returns `507` | Free space below the floor (section 4). | Free disk. |
| Upload returns `503 BUSY` | Ingest queue full or all 4 upload slots busy. | Retry after `Retry-After`. |
| Download or explorer returns `BLOB_UNAVAILABLE` | The store file is missing or unreadable (restore from older store, manual deletion, permissions). | `store verify` lists the missing digests; restore the blobs. |
| Sessions end after 30 minutes idle | By design (`security.session_idle_mins`, absolute `session_max_hours` 12). | Adjust only downward for safety. |
| `docker compose exec nzbd nzbd ...` says executable not found | The binary is `/nzbd`, not on PATH. | Use `/nzbd`. |
| Startup or `config check` says `INVITE_PATH_INVALID` | `security.invite_path` (or `NZBD__security__invite_path`) is not `/` + one segment of 6-64 `A-Z a-z 0-9 _ -`, or it equals, starts with or is a prefix of a built-in route (`/login`, `/admin`, `/static`, ...); the message names the rule. | Pick another value (e.g. `/join-` + random letters) and restart. |
| An invitee gets a 404 at `/invite` | `security.invite_path` moves the page; `/invite` is then a plain 404 by design. | Hand out the address `nzbd config check` (or the invitation page) prints. |
| `user create` says `MULTI_USER_OFF` (or, on 1.x, that a user already exists) | A second account needs `security.multi_user = true`; invitations also need `security.registration_enabled = true` (`INVITES_DISABLED`). | Set the key, restart, retry; or use `reset-password` / `reset-mfa` for the existing account. |
| A signed-in user gets `404` on a page you know exists, or the Users page is missing for an uploader, or an uploader cannot change a category | The page needs a higher role; a refused role is indistinguishable from an unknown path by design. | Check the role with `user list`; see `authz_denied` in the audit list; change the role with the Users page (uploader <-> viewer) or `user set-role`. Only admins edit metadata (D40). |

## 7. Command reference (`nzbd`)

**Never as root.** Every command that can write to the database, the NZB store, backups, the search index or
`paths.state` refuses to run as root (effective uid 0), because the files it creates would be root-owned and refused
or unusable for `serve`: run it as the service user (`docker compose exec nzbd /nzbd ...` does). If you really must,
`nzbd --allow-root <command>` (before the subcommand); `db check|migrate|restore|restore-finish`, `audit` and `import`
take their own `--allow-root` after the subcommand. Exempt: `healthcheck`, `categories`, `security-headers`, `keygen`.
`watch rules` is read-only but not exempt (review 41 L1): its walk is path-based, so run as root a writer racing a
sub-folder swap could make it list directories the service user cannot read; as the service user it sees only what
`serve` sees.

| Command | Purpose |
|---|---|
| `serve` | Run the server (the container default). `--config FILE` is global; env `NZBD__section__key` overrides. |
| `config check` | Validate configuration and the filesystem; prints warnings. |
| `healthcheck` | Loopback `GET /healthz` probe (container `HEALTHCHECK`). Exit 0 healthy; exit 1 with `starting: ...` while the database is being checked or migrated (the listener already answers 503 `STARTING`), or `unhealthy: ...` otherwise. |
| `db check [--quick\|--full] [--allow-root]` | Read-only database check, safe next to a running server. Run it as the service user: `docker compose exec nzbd /nzbd db check`. It refuses to run as root unless `--allow-root` (a read-only open can create `-wal`/`-shm` files owned by the caller, which the service user could then not write). No flag = the bounded startup check (milliseconds); `--quick` = `PRAGMA quick_check` over the whole file; `--full` = `integrity_check` + `foreign_key_check` (reads everything: about 2 minutes on a cold 1,000,000-release library). Exit 0 ok, 2 damaged (message printed), 1 could not run. |
| `health` | Full text health table, exit 0/1/2, read-only. |
| `audit export [--since T] [--verify]` / `audit verify` | JSON Lines (ASCII only) of the audit log on stdout, hash chain verification on stderr. Exit 0 ok, 2 chain broken (`first_broken_id=N kind=edited\|gap\|unchained\|tail_removed`), 1 error. Read-only; run as the service user (section 9). |
| `metrics` | Print `GET /metrics` of the running server's internal listener (needs `[metrics] listen`). |
| `user create <name> [--role R]` / `list` / `set-role <name> <role>` / `disable` / `enable` / `delete` / `unlock` / `revoke-sessions <name>` / `set-display-name <name> <text>` / `invite <name> --role uploader\|viewer` / `reset-password` / `reset-mfa` / `enroll-token [<name>]` | Account management (CLI only, host only). `--role` is required for every account but the first, which becomes `admin`; the name argument is optional only while exactly one account exists. Secrets are printed once on stdout. Second accounts and `invite` need `security.multi_user`. |
| `apikey create <label>` / `list` / `revoke <id>` | Upload-only API keys. |
| `backup [--keep N]` | SQLite: stripped `VACUUM INTO` copy; PostgreSQL: snapshot export (both restore-pending, encrypted when `maintenance.backup_encryption_key_file` is set); rotate, purge sessions/logs/revoked keys, print the audit anchor. |
| `backup decrypt FILE --out PATH [--key-file KEY]` | Decrypt an encrypted backup into a new plain 0600 SQLite file (authenticated first; never overwrites). |
| `db restore-finish [--dry-run] [--yes] [--allow-root]` | After restoring a backup (or a detected rollback), before `serve`: one transaction deletes sessions, open invitations, MFA recovery codes, staged credentials, enrollment tokens and throttle rows, revokes ALL API keys, rotates the search index epoch and clears the restore mark, writes one audit row, re-anchors `paths.state`, and prints accounts (role, state), the audit anchor and next steps. Idempotent; host only, never HTTP; `--yes` or a typed confirmation on a terminal. |
| `db migrate [--yes] [--force] [--allow-root] [--owner-user U] [--owner-password-file F]` | PostgreSQL: print the pending schema migrations; with `--yes` apply them with the owner role (default `nzbd_owner`, password file `/run/setup-secrets/nzbd_db_owner_password`). Only in the `setup` service (`docker compose --profile setup run --rm setup`). SQLite: opens (creates) the library, which migrates itself. |
| `db restore FILE [--allow-unencrypted] [--force] [--allow-root] [--owner-user U] [--owner-password-file F]` | PostgreSQL: load an `nzbd backup` snapshot (verified first; decrypted with the configured backup key; a plaintext file, `--allow-unencrypted`, is not authenticated: restore only files you produced) into an empty, migrated database with the owner role; leaves it restore-pending. `setup` service only. SQLite is restored by a file copy (section 2). |
| `search status` / `search verify` / `search rebuild` | The search index: state and backlog; compare with the database (read-only); ask the running server to rebuild it. |
| `keys rotate-totp --new-key-file FILE [--dry-run] [--no-backup]` | Re-seal every TOTP secret under a new key in one transaction (offline; section 3). |
| `import <dir> [--max-depth N] [--max-entries N] [--include-deleted] [--allow-root]` | Copy every `.nzb` below `<dir>` into the library through the ingest pipeline (read only, no symbolic links followed, re-runs import nothing twice, releases deleted from the library are skipped as `TRASHED` unless `--include-deleted`; refuses root unless `--allow-root`). SQLite: stop `serve` first. Exit 0 / 1 refused / 2 something skipped, failed or interrupted (section 5). |
| `failed list` / `failed retry <name>\|--all` | Inspect and re-queue quarantined files. |
| `cleanup status` | Items and bytes of the Trash / Blocked / Failed buckets. Read-only. |
| `cleanup purge --bucket trash\|blocked\|failed [--yes]` | Permanently delete one bucket (dry run without `--yes`; exit 2 = some items refused or not processed). |
| `trash list` / `trash restore <id>` / `trash purge [--yes]` | Deleted releases: list, put one back into the watch folder, purge the trash. |
| `store verify [--quick]` | Releases have their NZB files (and with full mode every file re-hashes). Exit 2 = problems. |
| `store gc [--dry-run] [--yes] [--force] [--grace-hours N]` | Quarantine unreferenced files (prints plan without `--yes`). |
| `store gc-restore` | Put quarantined files back. |
| `categories` | Print the category taxonomy (id, slug, name). |
| `watch rules` | Print the `[[ingest.rules]]` (refused with the same `RULE_*` code as `serve` when one is invalid) and a dry run: for each file now in the watch folder, the rule that would apply and its effect (category, label). Read-only: no symlink followed, nothing opened, moved or ingested, no database access; hidden and non-UTF-8 sub-folders are listed as "directory not scanned". Run it as the service user (`docker compose exec nzbd /nzbd watch rules`); it refuses root without `--allow-root`, which keeps a symlink race during the walk contained to what the service user can read (section 4, Watch-folder rules). |
| `security-headers` | Print the security response headers nzbd sets on its HTML pages, `Name: value` per line (no config, database or network). The reference of `deploy/audit-headers.sh`. |
| `keygen [--out FILE]` | New 32-byte key (base64; TOTP or backup encryption key) to stdout or a new 0400 file; refuses to overwrite. |

## 8. NZB files (`paths.store`)

v3 keeps the NZB files on the filesystem only, for both database backends (D36 a, D37): `data/store/<sha[0:2]>/<sha[2:4]>/<sha>.nzb`,
immutable and named by SHA-256. The 2.x database blob backend (`store.backend = "db"`, `nzbd store migrate`) does not
exist in v3; the setting is refused with `STORE_DB_BACKEND_REMOVED`. Back up `data/store/` next to every database
backup (section 2).

## 9. Audit export, chain verification and metrics (T105)

**Verify and export** (read-only, safe next to the server; run as the service user, the command refuses root):

```
docker compose exec nzbd /nzbd audit verify                       # exit 0 / 2 / 1, summary on stderr
docker compose exec nzbd /nzbd audit export --verify > audit.jsonl   # rows on stdout, summary on stderr
docker compose exec nzbd /nzbd audit export --since 2026-10-01     # unix seconds, YYYY-MM-DD or ...THH:MM:SSZ (UTC)
```

`audit chain OK: rows=N head_log=<hex> head_account=<hex>`. **What `OK` means.** The chain is unkeyed: anyone who can
write the SQLite file (or, on PostgreSQL, the database superuser) can remove the newest rows (or the oldest ones) and fix the recorded state, or recompute the rest
of a class, and `audit verify` then still says OK. It catches everything done without that care (a bug, an SQL tool, a
mixed restore, a forged insert). The defence is a head recorded elsewhere. The server logs
`audit chain anchor when=startup|after_backup|after_purge head_log=... head_account=... rows=...` at startup and after
every backup and purge, and `nzbd backup` prints the same line. **The anchors are ordinary log lines.** They live in the
container log, which the shipped compose file rotates (json-file driver, 10 MB x 5 files, next to one line per request),
so on a busy install they are gone within hours to days: nothing keeps them for you. An anchor only protects what you
copied off the host: ship the container log to a collector (or copy the `audit chain anchor` line from the log, or
the one `nzbd backup` prints, next to each off-host backup). To check: the head you recorded earlier must still be the `chain_hash` of a surviving row
in `audit export` (or, for the newest anchor, equal the current head). Keyed hashing is an open owner decision
(DECISIONS D30).
`audit chain BROKEN: first_broken_id=N kind=...` (exit 2):

| kind | Meaning | What to do |
|---|---|---|
| `edited` | Row N's content or hash was changed. | Treat as tampering; compare with the newest backup (`backup decrypt`, `audit verify` on the copy). |
| `gap` | Row N does not link to the row before it: a row between them was deleted, or a forged one inserted. | Same. Do not delete audit rows by hand: the retention job is the only safe remover. |
| `unchained` | Row N was inserted without going through the application. | Same. |
| `tail_removed` | The newest rows of a class are gone (count/head differ from the recorded state); N is the last surviving id. | Same; also check for a restored older file. |

Two things to know. The export is **escaped and redacted** (long token-shaped runs, 32+ characters, become
`[redacted]`; secrets shorter than that, or split by separators, are not caught: audit rows hold no secrets by
construction, redaction is belt and braces), while the hash covers the raw stored row, so an exported file cannot be
re-verified offline: verification always runs against the database (or a backup copy of it). And **stop the old
container before the first start of the new version**: a still-running pre-0013 process keeps inserting rows without
chain columns after the migration; they are flagged `unchained` forever and `audit verify` exits 2.

Normal causes of a broken chain are restoring a mix of files (a database file with another one's WAL) and editing
the database with an SQL tool; a plain restore of one backup file is consistent. After an upgrade from 1.x/2.0-rc the
first start chains the existing rows; `audit verify` before that first start exits 1 ("not chained yet").
`nzbd health` shows the cheap check ("Audit log chain") and the deep check the full walk. The first start after the
upgrade chains the existing rows (about 20 s per 300,000 rows) and logs `audit log hash chain created for the existing
rows` behind the starting page.

**Metrics** are off by default. Set `NZBD__metrics__listen=127.0.0.1:9100` and read them from inside the container
with `docker compose exec nzbd /nzbd metrics`. A scraper on the internal `back` network needs
`NZBD__metrics__listen=0.0.0.0:9100` plus `NZBD__metrics__allow_back_network=true`; never publish that port and never add
a proxy route for it (the shipped Caddyfile has none). Output is plain
`nzbd_*` counters and gauges: ingest outcomes since start, library totals, log sizes, sessions/keys/accounts counts,
failed logins in 24 h, `nzbd_audit_chain_consistent` (alert on 0), database and WAL sizes, memory and descriptors.
