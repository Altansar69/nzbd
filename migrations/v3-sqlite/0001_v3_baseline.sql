-- v3-sqlite/0001_v3_baseline.sql (T122; docs/v3/DATA_MODEL.md section 8, ARCHITECTURE v3 13). Forward-only.
-- The 3.x SQLite backend starts from this clean baseline: there is no upgrade path from a 2.x database (owner decision
-- 2026-10-15, fresh start; a 2.x file is refused with LEGACY_DATABASE and never modified). Rules and names mirror the
-- Postgres v3 schema (`migrations/v3`): `account` (not `user`) and `account_id` columns, ids never reused
-- (AUTOINCREMENT), the transactional outbox and search state for the Tantivy indexer (no FTS5), exact per-category
-- totals, the database state with the library identity, the retention policy with its floors, per-account
-- preferences. On SQLite the triggers and CHECKs guard against application bugs and careless tools, not against
-- someone who can run SQL on the file (SEC-103; the logged audit anchors are the external control).

-- Taxonomy (seeded and kept in sync by `SqliteDb::open` from nzb-core's embedded taxonomy).
CREATE TABLE category (
  id        INTEGER PRIMARY KEY CHECK (id BETWEEN 1 AND 99999),   -- Newznab-style id, e.g. 5040
  parent_id INTEGER REFERENCES category(id),
  name      TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 64)
) STRICT;

-- Accounts (2.x `user`). Rows are tombstoned, never deleted or replaced. The CHECKs mirror Postgres `0002_core.sql`
-- (review 35 L1; GLOB character classes stand in for the Postgres regular expressions).
CREATE TABLE account (
  id                      INTEGER PRIMARY KEY AUTOINCREMENT,
  username                TEXT    NOT NULL UNIQUE COLLATE NOCASE
                            CHECK ((length(username) BETWEEN 1 AND 64 AND username NOT GLOB '*[^A-Za-z0-9._-]*')
                                OR (deleted_at IS NOT NULL AND username GLOB '~deleted~[0-9]*'
                                    AND substr(username, 10) NOT GLOB '*[^0-9]*')),
  password_hash           TEXT    NOT NULL CHECK (length(CAST(password_hash AS BLOB)) BETWEEN 1 AND 256),   -- PHC
  role                    TEXT    NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin','member','viewer')),
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

-- Library. AUTOINCREMENT: a release id is never handed out twice (the T119 digest binding stays the control against
-- acting on a different release). `index_version` is bumped by every update (trigger below), like on Postgres.
CREATE TABLE release (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  sha256                BLOB    NOT NULL UNIQUE CHECK (length(sha256) = 32),   -- also the public GUID (hex)
  -- Review 35 L1: the byte length and the NUL test use the stored bytes (no hex() GLOB, which matches across byte
  -- boundaries); the parser never produces either, this is the database's own refusal like Postgres's.
  title                 TEXT    NOT NULL CHECK (length(CAST(title AS BLOB)) BETWEEN 1 AND 512 AND instr(title, char(0)) = 0),
  category_id           INTEGER NOT NULL REFERENCES category(id),
  category_overridden   INTEGER NOT NULL DEFAULT 0 CHECK (category_overridden IN (0,1)),
  category_source       TEXT    NOT NULL DEFAULT 'fallback'
                          CHECK (category_source IN ('scene','upload','meta','fallback','manual')),
  posted_at             INTEGER,                    -- max file date, NULL if unknown
  ingested_at           INTEGER NOT NULL,
  total_bytes           INTEGER NOT NULL CHECK (total_bytes >= 0),
  poster                TEXT    CHECK (poster IS NULL OR length(CAST(poster AS BLOB)) <= 1024),
  file_count            INTEGER NOT NULL CHECK (file_count >= 0),
  segment_count         INTEGER NOT NULL CHECK (segment_count >= 0),
  missing_segment_count INTEGER NOT NULL DEFAULT 0 CHECK (missing_segment_count >= 0),
  par2_blocks           INTEGER NOT NULL DEFAULT 0 CHECK (par2_blocks >= 0),
  flags                 INTEGER NOT NULL DEFAULT 0 CHECK (flags >= 0),   -- ReleaseFlags bitmask
  nzb_size_bytes        INTEGER NOT NULL CHECK (nzb_size_bytes >= 0),
  source_name           TEXT    CHECK (source_name IS NULL OR length(CAST(source_name AS BLOB)) <= 1024),   -- display only
  source_label          TEXT    CHECK (source_label IS NULL OR length(CAST(source_label AS BLOB)) BETWEEN 1 AND 64),
  origin                TEXT    CHECK (origin IS NULL OR origin IN ('watch','upload','api')),
  -- JSON shape checks: `json_type` raises on invalid JSON, so it is only reached through the CASE.
  meta_json             TEXT    CHECK (meta_json IS NULL OR CASE WHEN json_valid(meta_json) THEN json_type(meta_json) = 'object' ELSE 0 END),
  scene_family          TEXT    CHECK (scene_family IS NULL OR scene_family IN ('tv','anime','movie','music')),
  scene_year            INTEGER CHECK (scene_year IS NULL OR scene_year BETWEEN 1900 AND 2100),
  scene_season          INTEGER CHECK (scene_season IS NULL OR scene_season >= 0),
  scene_episode         INTEGER CHECK (scene_episode IS NULL OR scene_episode >= 0),
  scene_resolution      TEXT    CHECK (scene_resolution IS NULL OR length(CAST(scene_resolution AS BLOB)) <= 512),
  scene_source          TEXT    CHECK (scene_source IS NULL OR length(CAST(scene_source AS BLOB)) <= 512),
  scene_codec           TEXT    CHECK (scene_codec IS NULL OR length(CAST(scene_codec AS BLOB)) <= 512),
  scene_group           TEXT    CHECK (scene_group IS NULL OR length(CAST(scene_group AS BLOB)) <= 512),
  scene_languages       TEXT    CHECK (scene_languages IS NULL OR CASE WHEN json_valid(scene_languages) THEN json_type(scene_languages) = 'array' ELSE 0 END),
  scene_json            TEXT    CHECK (scene_json IS NULL OR CASE WHEN json_valid(scene_json) THEN json_type(scene_json) = 'object' ELSE 0 END),
  added_by              INTEGER REFERENCES account(id),   -- from the session / key owner, never input
  index_version         INTEGER NOT NULL DEFAULT 1 CHECK (index_version >= 1)
) STRICT;
CREATE INDEX release_ingest   ON release(ingested_at DESC);
CREATE INDEX release_added_by ON release(added_by, id) WHERE added_by IS NOT NULL;

CREATE TABLE nzb_file (
  id                INTEGER PRIMARY KEY,
  release_id        INTEGER NOT NULL REFERENCES release(id) ON DELETE CASCADE,
  idx               INTEGER NOT NULL CHECK (idx >= 0),   -- position in the NZB (0-based)
  subject           TEXT    NOT NULL CHECK (length(CAST(subject AS BLOB)) <= 4096),
  filename          TEXT    CHECK (filename IS NULL OR length(CAST(filename AS BLOB)) <= 255),
  kind              TEXT    NOT NULL CHECK (kind IN ('video','audio','archive','par2','nfo','sfv','subtitle',
                                                     'image','nzb','executable','other')),   -- FileKind
  poster            TEXT    CHECK (poster IS NULL OR length(CAST(poster AS BLOB)) <= 1024),
  posted_at         INTEGER,
  bytes             INTEGER NOT NULL CHECK (bytes >= 0),
  segment_count     INTEGER NOT NULL CHECK (segment_count >= 0),
  declared_segments INTEGER CHECK (declared_segments IS NULL OR declared_segments >= 0),
  missing_ranges    TEXT    CHECK (missing_ranges IS NULL OR json_valid(missing_ranges)),   -- JSON [[a,b],...]
  groups            TEXT    CHECK (groups IS NULL OR CASE WHEN json_valid(groups) THEN json_type(groups) = 'array' ELSE 0 END),
  UNIQUE (release_id, idx)
) STRICT;

-- Deleted releases are MOVED here in one transaction (display essentials only).
CREATE TABLE release_trash (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  original_id    INTEGER NOT NULL,
  sha256         BLOB    NOT NULL UNIQUE CHECK (length(sha256) = 32),
  title          TEXT    NOT NULL,
  category_id    INTEGER NOT NULL,
  total_bytes    INTEGER NOT NULL CHECK (total_bytes >= 0),
  nzb_size_bytes INTEGER NOT NULL CHECK (nzb_size_bytes >= 0),
  file_count     INTEGER NOT NULL CHECK (file_count >= 0),
  source_name    TEXT,
  ingested_at    INTEGER NOT NULL,
  deleted_at     INTEGER NOT NULL,
  added_by       INTEGER,
  deleted_by     INTEGER
) STRICT;
CREATE INDEX release_trash_deleted ON release_trash(deleted_at DESC);

-- Exact per-category totals (tiles, library totals, degraded mode), maintained by the release triggers below in the
-- transaction of every change. One row per category (inserted by the taxonomy seed).
CREATE TABLE category_stats (
  category_id INTEGER PRIMARY KEY REFERENCES category(id),
  releases    INTEGER NOT NULL DEFAULT 0 CHECK (releases >= 0),
  files       INTEGER NOT NULL DEFAULT 0 CHECK (files >= 0),
  segments    INTEGER NOT NULL DEFAULT 0 CHECK (segments >= 0),
  bytes       INTEGER NOT NULL DEFAULT 0 CHECK (bytes >= 0)
) STRICT;

-- The transactional outbox (ARCHITECTURE v3 3.1): one payload-free row per created, changed or removed release (SEC-092),
-- AUTOINCREMENT so a sequence number is never reused (index ahead of the database, review 30 M2 a). No foreign key: a
-- removal is an outbox row for a vanished id.
CREATE TABLE search_outbox (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  release_id  INTEGER NOT NULL,
  enqueued_at INTEGER NOT NULL
) STRICT;
CREATE TABLE search_replay (release_id INTEGER PRIMARY KEY) STRICT;
CREATE TABLE search_quarantine (
  release_id INTEGER PRIMARY KEY,
  error_code TEXT    NOT NULL CHECK (length(CAST(error_code AS BLOB)) BETWEEN 1 AND 64),
  at         INTEGER NOT NULL
) STRICT;
CREATE TABLE search_state (
  id                   INTEGER PRIMARY KEY CHECK (id = 1),
  epoch                BLOB    NOT NULL CHECK (length(epoch) = 16),   -- rotated by db restore / restore-finish
  replay               INTEGER NOT NULL DEFAULT 0 CHECK (replay IN (0, 1)),
  rebuild_requested_at INTEGER,
  rebuild_generation   INTEGER NOT NULL DEFAULT 0 CHECK (rebuild_generation >= 0)
) STRICT;
INSERT INTO search_state (id, epoch) VALUES (1, randomblob(16));

-- Outbox, totals and `index_version` in the transaction of every release change, so no write path can forget them.
-- The update trigger fires once per statement row: its own `index_version` bump is filtered by the WHEN clause.
CREATE TRIGGER release_v3_insert AFTER INSERT ON release
BEGIN
  INSERT INTO search_outbox (release_id, enqueued_at) VALUES (NEW.id, unixepoch());
  UPDATE category_stats SET releases = releases + 1, files = files + NEW.file_count,
         segments = segments + NEW.segment_count, bytes = bytes + NEW.total_bytes
   WHERE category_id = NEW.category_id;
END;
CREATE TRIGGER release_v3_delete AFTER DELETE ON release
BEGIN
  INSERT INTO search_outbox (release_id, enqueued_at) VALUES (OLD.id, unixepoch());
  UPDATE category_stats SET releases = releases - 1, files = files - OLD.file_count,
         segments = segments - OLD.segment_count, bytes = bytes - OLD.total_bytes
   WHERE category_id = OLD.category_id;
END;
CREATE TRIGGER release_v3_update AFTER UPDATE ON release
WHEN NEW.index_version = OLD.index_version
BEGIN
  INSERT INTO search_outbox (release_id, enqueued_at) VALUES (NEW.id, unixepoch());
  UPDATE category_stats SET releases = releases - 1, files = files - OLD.file_count,
         segments = segments - OLD.segment_count, bytes = bytes - OLD.total_bytes
   WHERE category_id = OLD.category_id;
  UPDATE category_stats SET releases = releases + 1, files = files + NEW.file_count,
         segments = segments + NEW.segment_count, bytes = bytes + NEW.total_bytes
   WHERE category_id = NEW.category_id;
  UPDATE release SET index_version = OLD.index_version + 1 WHERE id = NEW.id;
END;

-- Authentication state.
CREATE TABLE recovery_code (
  id         INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  code_hash  BLOB    NOT NULL CHECK (length(code_hash) = 32),
  used_at    INTEGER
) STRICT;
CREATE TABLE session (
  id_hash       BLOB    PRIMARY KEY CHECK (length(id_hash) = 32),
  account_id    INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  stage         TEXT    NOT NULL CHECK (stage IN ('pending_mfa','active')),
  csrf_token    BLOB    NOT NULL CHECK (length(csrf_token) BETWEEN 16 AND 64),
  created_at    INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  ip            TEXT    CHECK (ip IS NULL OR length(CAST(ip AS BLOB)) <= 64),
  user_agent    TEXT    CHECK (user_agent IS NULL OR length(CAST(user_agent AS BLOB)) <= 512),
  enroll_proven INTEGER NOT NULL DEFAULT 0 CHECK (enroll_proven IN (0,1)),
  mfa_failures  INTEGER NOT NULL DEFAULT 0 CHECK (mfa_failures BETWEEN 0 AND 5)
) STRICT;
-- AUTOINCREMENT (review 35 I1): a purged key's id is never handed out again, like the Postgres identity.
CREATE TABLE api_key (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  name         TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
  prefix       TEXT    NOT NULL CHECK (length(CAST(prefix AS BLOB)) <= 16),   -- first 6 chars, display only
  key_hash     BLOB    NOT NULL UNIQUE CHECK (length(key_hash) = 32),
  scope        TEXT    NOT NULL DEFAULT 'upload' CHECK (scope IN ('upload')),
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at   INTEGER,
  owner_id     INTEGER REFERENCES account(id),
  rate_per_min INTEGER CHECK (rate_per_min IS NULL OR rate_per_min BETWEEN 1 AND 30),
  revoked_by   INTEGER
) STRICT;
CREATE INDEX api_key_owner ON api_key(owner_id) WHERE revoked_at IS NULL;

-- One-time tokens: invitations and admin-issued recovery codes. Only a hash is stored.
CREATE TABLE invite (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  purpose       TEXT    NOT NULL CHECK (purpose IN ('invite','recover')),
  token_hash    BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  username      TEXT    COLLATE NOCASE               -- invite: the reserved name; recover: NULL
                  CHECK (username IS NULL OR (length(username) BETWEEN 1 AND 64 AND username NOT GLOB '*[^A-Za-z0-9._-]*')),
  role          TEXT    CHECK (role IN ('member','viewer')),            -- NEVER 'admin' (D27)
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
CREATE UNIQUE INDEX invite_open_username ON invite(username)   WHERE purpose = 'invite'  AND used_at IS NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX invite_open_account  ON invite(account_id) WHERE purpose = 'recover' AND used_at IS NULL AND revoked_at IS NULL;
CREATE INDEX invite_expiry ON invite(expires_at);

CREATE TABLE credential_staging (
  account_id      INTEGER PRIMARY KEY REFERENCES account(id),
  session_hash    BLOB    NOT NULL UNIQUE CHECK (length(session_hash) = 32),   -- the redeeming pending_mfa session
  invite_id       INTEGER NOT NULL REFERENCES invite(id),
  issued_by       INTEGER,                                                     -- admin id, NULL = operator
  password_hash   TEXT    NOT NULL CHECK (length(CAST(password_hash AS BLOB)) BETWEEN 1 AND 256),
  totp_secret_enc BLOB    CHECK (totp_secret_enc IS NULL OR length(totp_secret_enc) <= 256),
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL CHECK (expires_at > created_at AND expires_at - created_at <= 3600)
) STRICT;
CREATE TRIGGER staging_dies_with_session AFTER DELETE ON session
BEGIN DELETE FROM credential_staging WHERE session_hash = OLD.id_hash; END;
CREATE TRIGGER staging_dies_with_credential_change AFTER UPDATE OF password_hash, role, disabled_at, deleted_at ON account
BEGIN DELETE FROM credential_staging WHERE account_id = OLD.id; END;

CREATE TABLE account_throttle (
  account_id        INTEGER PRIMARY KEY REFERENCES account(id),
  hour_start        INTEGER NOT NULL,
  hour_failures     INTEGER NOT NULL CHECK (hour_failures >= 0),
  throttled_until   INTEGER,
  day_start         INTEGER NOT NULL,
  day_mfa_failures  INTEGER NOT NULL CHECK (day_mfa_failures >= 0),
  mfa_refused_until INTEGER
) STRICT;
CREATE TABLE login_lock (
  account_id   INTEGER NOT NULL REFERENCES account(id),
  ip_key       TEXT    NOT NULL CHECK (length(CAST(ip_key AS BLOB)) <= 64),   -- IPv4 address or IPv6 /64 prefix
  failures     INTEGER NOT NULL CHECK (failures >= 0),
  locked_until INTEGER,
  last_failure INTEGER NOT NULL,
  PRIMARY KEY (account_id, ip_key)
) STRICT, WITHOUT ROWID;
CREATE TABLE user_known_ip (
  account_id INTEGER NOT NULL REFERENCES account(id),
  ip_key     TEXT    NOT NULL CHECK (length(CAST(ip_key AS BLOB)) <= 64),
  last_seen  INTEGER NOT NULL,
  PRIMARY KEY (account_id, ip_key)
) STRICT, WITHOUT ROWID;

-- Per-account preferences (T120; same shape as Postgres).
CREATE TABLE user_pref (
  account_id INTEGER PRIMARY KEY REFERENCES account(id),
  hide_xxx   INTEGER NOT NULL DEFAULT 0 CHECK (hide_xxx IN (0, 1)),
  theme      TEXT    NOT NULL DEFAULT 'auto' CHECK (theme IN ('auto', 'light', 'dark')),
  updated_at INTEGER NOT NULL
) STRICT;

-- Logs.
CREATE TABLE ingest_log (
  id          INTEGER PRIMARY KEY,
  ts          INTEGER NOT NULL,
  source      TEXT    NOT NULL CHECK (source IN ('watch','upload_ui','upload_api')),
  api_key_id  INTEGER REFERENCES api_key(id) ON DELETE SET NULL,
  source_name TEXT    CHECK (source_name IS NULL OR length(CAST(source_name AS BLOB)) <= 1024),
  sha256      BLOB    CHECK (sha256 IS NULL OR length(sha256) = 32),
  outcome     TEXT    NOT NULL CHECK (outcome IN ('ok','duplicate','failed')),
  error_code  TEXT    CHECK (error_code IS NULL OR length(CAST(error_code AS BLOB)) <= 64),
  detail      TEXT    CHECK (detail IS NULL OR length(CAST(detail AS BLOB)) <= 4096),
  release_id  INTEGER REFERENCES release(id) ON DELETE SET NULL,
  account_id  INTEGER REFERENCES account(id)      -- uploading account (UI) / key owner (API)
) STRICT;
CREATE INDEX ingest_ts ON ingest_log(ts DESC);

-- Audit log with the tamper-evident hash chain (two classes; a purge removes only a PREFIX of a class).
CREATE TABLE audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          INTEGER NOT NULL,
  actor       TEXT    CHECK (actor IS NULL OR length(CAST(actor AS BLOB)) <= 512),
  event       TEXT    NOT NULL CHECK (length(CAST(event AS BLOB)) BETWEEN 1 AND 64),
  detail      TEXT    CHECK (detail IS NULL OR length(CAST(detail AS BLOB)) <= 8192),
  ip          TEXT    CHECK (ip IS NULL OR length(CAST(ip AS BLOB)) <= 128),
  actor_id    INTEGER,                              -- no FK: audit rows outlive everything
  actor_kind  TEXT    CHECK (actor_kind IS NULL OR actor_kind IN ('user','cli','system','api_key','anonymous')),
  actor_role  TEXT    CHECK (actor_role IS NULL OR actor_role IN ('admin','member','viewer')),
  target_id   INTEGER,                              -- account the event acted on
  chain_class INTEGER CHECK (chain_class IS NULL OR chain_class IN (0, 1)),   -- 0 log, 1 account lifecycle
  chain_prev  BLOB    CHECK (chain_prev IS NULL OR length(chain_prev) = 32),
  chain_hash  BLOB    CHECK (chain_hash IS NULL OR length(chain_hash) = 32)
) STRICT;
CREATE INDEX audit_ts             ON audit_log(ts DESC);
CREATE INDEX audit_actor          ON audit_log(actor_id, ts DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX audit_account_events ON audit_log(ts DESC) WHERE target_id IS NOT NULL;
CREATE INDEX audit_chain          ON audit_log(chain_class, id);
CREATE TABLE audit_chain_state (
  class      INTEGER PRIMARY KEY CHECK (class IN (0, 1)),
  floor_hash BLOB    NOT NULL CHECK (length(floor_hash) = 32),
  head_hash  BLOB    NOT NULL CHECK (length(head_hash) = 32),
  rows       INTEGER NOT NULL DEFAULT 0 CHECK (rows >= 0)
) STRICT;
INSERT INTO audit_chain_state (class, floor_hash, head_hash, rows)
VALUES (0, zeroblob(32), zeroblob(32), 0), (1, zeroblob(32), zeroblob(32), 0);
-- Every column, the chain columns included (review 35 L2, like Postgres `0004_ops.sql`): a row is never updated, so its
-- class (and with it the retention floor below) and its hashes cannot be rewritten by the application either.
CREATE TRIGGER audit_log_immutable BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log rows are immutable'); END;

-- Retention (D35 d, review 30 M3): the floors are CHECKs. The application computes the prefix cutoffs from this row;
-- the trigger below refuses deleting an audit row younger than its class floor by the database clock.
CREATE TABLE retention_policy (
  id               INTEGER PRIMARY KEY CHECK (id = 1),
  log_days         INTEGER NOT NULL DEFAULT 90  CHECK (log_days     >= 90),    -- audit class 0
  account_days     INTEGER NOT NULL DEFAULT 365 CHECK (account_days >= 365),   -- audit class 1 (D26 M6)
  ingest_days      INTEGER NOT NULL DEFAULT 90  CHECK (ingest_days  >= 1),
  keep_all         INTEGER NOT NULL DEFAULT 0   CHECK (keep_all IN (0, 1)),
  account_keep_all INTEGER NOT NULL DEFAULT 0   CHECK (account_keep_all IN (0, 1))
) STRICT;
INSERT INTO retention_policy (id) VALUES (1);
-- A row stamped more than a day ahead of the clock counts as aged, like in the purge: it must not pin the chain
-- prefix behind it forever.
CREATE TRIGGER audit_log_floor BEFORE DELETE ON audit_log
WHEN OLD.ts <= unixepoch() + 86400 AND OLD.ts > unixepoch() - 86400 * (
  SELECT CASE WHEN OLD.chain_class = 1 THEN max(account_days, 365) ELSE max(log_days, 90) END
  FROM retention_policy WHERE id = 1)
BEGIN SELECT RAISE(ABORT, 'AUDIT_RETENTION_FLOOR'); END;

-- Database state (one row). `restore_pending` is set in every nzbd backup copy and by `nzbd db restore` (review 34 M3);
-- `serve` refuses while it is set. Library identity (review 34 M2): `backend` and a random `instance_id`, repeated by
-- the anchor in `paths.state`; a database whose identity does not match is refused (`LIBRARY_MISMATCH`).
CREATE TABLE db_state (
  id                  INTEGER PRIMARY KEY CHECK (id = 1),
  restore_pending     INTEGER NOT NULL DEFAULT 0 CHECK (restore_pending IN (0, 1)),
  restored_at         INTEGER,
  restore_finished_at INTEGER,
  backend             TEXT    NOT NULL DEFAULT 'sqlite' CHECK (backend = 'sqlite'),
  instance_id         BLOB    NOT NULL CHECK (length(instance_id) = 16)
) STRICT;
INSERT INTO db_state (id, instance_id) VALUES (1, randomblob(16));
