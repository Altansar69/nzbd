-- v3-sqlite/0004_roles.sql (T134, D40; docs/v3/DATA_MODEL.md). Forward-only, never edit after release.
-- The role set becomes `viewer`, `uploader`, `admin` (the former `member` is renamed `uploader` and no longer edits
-- metadata, an application rule). Same rules as Postgres `migrations/v3/0010_roles.sql`.
--
-- SQLite cannot alter a CHECK, so `account`, `invite` and `audit_log` are rebuilt (new table, copy, drop, rename) with
-- their indexes and triggers recreated exactly as in `0001_v3_baseline.sql`. Fresh data (owner rule): the rebuild runs
-- inside the migration transaction where foreign keys cannot be switched off, and dropping a referenced table that
-- still has rows would cascade into or be refused by its children, so the migration refuses a library that already
-- holds accounts, invitations, audit rows or an audit chain head (`CHECK constraint failed: FRESH_DATA_REQUIRED`):
-- recreate it. The chain state counts too (T134 review I3): an audit log purged down to zero rows still has a chain
-- head, and rebuilding the table would restart the AUTOINCREMENT ids under that head. There is no conversion of
-- `member` rows and no upgrade path. Postgres `0010_roles.sql` refuses the same libraries. A 3.4 binary refuses a
-- database with this migration (unknown ledger version).
CREATE TEMP TABLE t134_fresh_data_guard (
  rows INTEGER NOT NULL,
  CONSTRAINT FRESH_DATA_REQUIRED CHECK (rows = 0)
);
INSERT INTO t134_fresh_data_guard (rows)
SELECT (SELECT count(*) FROM account) + (SELECT count(*) FROM invite) + (SELECT count(*) FROM audit_log)
     + (SELECT count(*) FROM audit_chain_state
        WHERE rows <> 0 OR head_hash <> zeroblob(32) OR floor_hash <> zeroblob(32));
DROP TABLE t134_fresh_data_guard;

-- Accounts. The CHECKs mirror Postgres `0002_core.sql` + `0010_roles.sql`.
CREATE TABLE account_t134 (
  id                      INTEGER PRIMARY KEY AUTOINCREMENT,
  username                TEXT    NOT NULL UNIQUE COLLATE NOCASE
                            CHECK ((length(username) BETWEEN 1 AND 64 AND username NOT GLOB '*[^A-Za-z0-9._-]*')
                                OR (deleted_at IS NOT NULL AND username GLOB '~deleted~[0-9]*'
                                    AND substr(username, 10) NOT GLOB '*[^0-9]*')),
  password_hash           TEXT    NOT NULL CHECK (length(CAST(password_hash AS BLOB)) BETWEEN 1 AND 256),   -- PHC
  role                    TEXT    NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin','uploader','viewer')),
  totp_secret_enc         BLOB    CHECK (totp_secret_enc IS NULL OR length(totp_secret_enc) <= 256),   -- sealed
  totp_enabled            INTEGER NOT NULL DEFAULT 0,
  totp_last_step          INTEGER,
  failed_logins           INTEGER NOT NULL DEFAULT 0,
  locked_until            INTEGER,
  last_failed_at          INTEGER,
  enroll_token_hash       BLOB    CHECK (enroll_token_hash IS NULL OR length(enroll_token_hash) = 32),
  enroll_token_expires    INTEGER,
  created_at              INTEGER NOT NULL,
  password_changed_at     INTEGER NOT NULL,
  disabled_at             INTEGER,                                -- NULL = enabled
  deleted_at              INTEGER,                                -- NULL = live; set = tombstone
  created_by              INTEGER REFERENCES account(id),         -- NULL = CLI / invite redeemed
  last_login_at           INTEGER,                                -- completed logins only
  -- Non-login label shown to every role in attribution (D26 d); NULL renders as 'user-<id>'.
  display_name            TEXT    CHECK (display_name IS NULL OR (length(display_name) BETWEEN 1 AND 32
                                         AND display_name NOT GLOB '*[^A-Za-z0-9 ._-]*'
                                         AND display_name NOT GLOB ' *' AND display_name NOT GLOB '* ')),
  credentials_replaced_at INTEGER,
  credentials_replaced_by INTEGER,
  -- D32: normalised email, never unique (no oracle), never used to contact anyone.
  email                   TEXT    CHECK (email IS NULL OR (length(email) BETWEEN 6 AND 254 AND email = lower(email)
                                         AND instr(email, '@') > 1 AND email NOT GLOB '*[^a-z0-9.@_%+-]*'))
) STRICT;
DROP TABLE account;
ALTER TABLE account_t134 RENAME TO account;
CREATE UNIQUE INDEX account_display_name ON account(display_name COLLATE NOCASE) WHERE deleted_at IS NULL;
CREATE INDEX account_active_admin ON account(id) WHERE role = 'admin' AND disabled_at IS NULL AND deleted_at IS NULL;
-- ^user-[0-9]+$ is reserved for display handles (N5).
CREATE TRIGGER account_reserved_handle BEFORE INSERT ON account
WHEN lower(NEW.username) GLOB 'user-[0-9]*' AND lower(NEW.username) NOT GLOB 'user-*[^0-9]*'
BEGIN SELECT RAISE(ABORT, 'RESERVED_LOGIN_NAME'); END;
-- SEC-062 backstop: never zero enabled, live admins (one writer, so no write skew).
CREATE TRIGGER account_keep_one_admin BEFORE UPDATE OF role, disabled_at, deleted_at ON account
WHEN OLD.role = 'admin' AND OLD.disabled_at IS NULL AND OLD.deleted_at IS NULL
 AND (NEW.role <> 'admin' OR NEW.disabled_at IS NOT NULL OR NEW.deleted_at IS NOT NULL)
 AND NOT EXISTS (SELECT 1 FROM account WHERE id <> OLD.id AND role = 'admin' AND disabled_at IS NULL AND deleted_at IS NULL)
BEGIN SELECT RAISE(ABORT, 'LAST_ADMIN'); END;
-- With `recursive_triggers = ON` (every connection) these also fire for INSERT OR REPLACE.
CREATE TRIGGER account_no_row_delete BEFORE DELETE ON account
BEGIN SELECT RAISE(ABORT, 'ACCOUNT_ROWS_ARE_TOMBSTONED'); END;
CREATE TRIGGER account_no_replace BEFORE INSERT ON account
WHEN EXISTS (SELECT 1 FROM account WHERE id = NEW.id OR username = NEW.username COLLATE NOCASE)
BEGIN SELECT RAISE(ABORT, 'ACCOUNT_ROWS_ARE_NEVER_REPLACED'); END;
CREATE TRIGGER staging_dies_with_credential_change AFTER UPDATE OF password_hash, role, disabled_at, deleted_at ON account
BEGIN DELETE FROM credential_staging WHERE account_id = OLD.id; END;

-- One-time tokens: invitations and admin-issued recovery codes. Only a hash is stored.
CREATE TABLE invite_t134 (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  purpose       TEXT    NOT NULL CHECK (purpose IN ('invite','recover')),
  token_hash    BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  username      TEXT    COLLATE NOCASE               -- invite: the reserved name; recover: NULL
                  CHECK (username IS NULL OR (length(username) BETWEEN 1 AND 64 AND username NOT GLOB '*[^A-Za-z0-9._-]*')),
  role          TEXT    CHECK (role IN ('uploader','viewer')),          -- NEVER 'admin' (D27)
  account_id    INTEGER REFERENCES account(id),      -- recover only
  created_by    INTEGER REFERENCES account(id),      -- NULL = operator via CLI
  created_via   TEXT    NOT NULL CHECK (created_via IN ('ui','cli')),
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  used_at       INTEGER,
  used_by       INTEGER REFERENCES account(id),
  revoked_at    INTEGER,
  name_refusals INTEGER NOT NULL DEFAULT 0 CHECK (name_refusals BETWEEN 0 AND 3),
  CHECK (expires_at > created_at),
  CHECK (expires_at - created_at <= CASE purpose WHEN 'recover' THEN 86400 ELSE 604800 END),
  CHECK ((purpose = 'invite'  AND username IS NOT NULL AND role IS NOT NULL AND account_id IS NULL)
      OR (purpose = 'recover' AND account_id IS NOT NULL AND username IS NULL AND role IS NULL))
) STRICT;
DROP TABLE invite;
ALTER TABLE invite_t134 RENAME TO invite;
CREATE UNIQUE INDEX invite_open_username ON invite(username)   WHERE purpose = 'invite'  AND used_at IS NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX invite_open_account  ON invite(account_id) WHERE purpose = 'recover' AND used_at IS NULL AND revoked_at IS NULL;
CREATE INDEX invite_expiry ON invite(expires_at);

-- Audit log with the tamper-evident hash chain (`audit_chain_state` is untouched: the table is empty).
CREATE TABLE audit_log_t134 (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          INTEGER NOT NULL,
  actor       TEXT    CHECK (actor IS NULL OR length(CAST(actor AS BLOB)) <= 512),
  event       TEXT    NOT NULL CHECK (length(CAST(event AS BLOB)) BETWEEN 1 AND 64),
  detail      TEXT    CHECK (detail IS NULL OR length(CAST(detail AS BLOB)) <= 8192),
  ip          TEXT    CHECK (ip IS NULL OR length(CAST(ip AS BLOB)) <= 128),
  actor_id    INTEGER,                              -- no FK: audit rows outlive everything
  actor_kind  TEXT    CHECK (actor_kind IS NULL OR actor_kind IN ('user','cli','system','api_key','anonymous')),
  actor_role  TEXT    CHECK (actor_role IS NULL OR actor_role IN ('admin','uploader','viewer')),
  target_id   INTEGER,                              -- account the event acted on
  chain_class INTEGER CHECK (chain_class IS NULL OR chain_class IN (0, 1)),   -- 0 log, 1 account lifecycle
  chain_prev  BLOB    CHECK (chain_prev IS NULL OR length(chain_prev) = 32),
  chain_hash  BLOB    CHECK (chain_hash IS NULL OR length(chain_hash) = 32)
) STRICT;
DROP TABLE audit_log;
ALTER TABLE audit_log_t134 RENAME TO audit_log;
CREATE INDEX audit_ts             ON audit_log(ts DESC);
CREATE INDEX audit_actor          ON audit_log(actor_id, ts DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX audit_account_events ON audit_log(ts DESC) WHERE target_id IS NOT NULL;
CREATE INDEX audit_chain          ON audit_log(chain_class, id);
-- Every column, the chain columns included: a row is never updated.
CREATE TRIGGER audit_log_immutable BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log rows are immutable'); END;
-- A row stamped more than a day ahead of the clock counts as aged, like in the purge.
CREATE TRIGGER audit_log_floor BEFORE DELETE ON audit_log
WHEN OLD.ts <= unixepoch() + 86400 AND OLD.ts > unixepoch() - 86400 * (
  SELECT CASE WHEN OLD.chain_class = 1 THEN max(account_days, 365) ELSE max(log_days, 90) END
  FROM retention_policy WHERE id = 1)
BEGIN SELECT RAISE(ABORT, 'AUDIT_RETENTION_FLOOR'); END;
