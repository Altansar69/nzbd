-- 0011_multi_user.sql (T101a; docs/DATA_MODEL.md "Migration 0011", AUTH_SPEC "Multi-user", SEC-060..070).
-- Forward-only, never edit after release. Everything on the big tables (`release`, `release_trash`, `ingest_log`) is a
-- nullable ADD COLUMN (O(1) in SQLite: the table is not rewritten, no index is built). `audit_log` is bounded by the
-- 90-day purge; its CHECK columns cost one scan of that table, measured by `migration_0011_*` tests.

-- Roles. The DEFAULT is the LEAST privileged role, so an INSERT that forgets the column can never create an admin; the
-- UPDATE then promotes the owner: 1.x has at most one row, a hand-edited database with several gets only the oldest
-- account promoted (the others stay viewers) instead of every row becoming an admin.
ALTER TABLE user ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin','member','viewer'));
UPDATE user SET role = 'admin' WHERE id = (SELECT min(id) FROM user);
ALTER TABLE user ADD COLUMN disabled_at   INTEGER;          -- NULL = enabled
ALTER TABLE user ADD COLUMN deleted_at    INTEGER;          -- NULL = live; set = tombstone (the row is never deleted)
ALTER TABLE user ADD COLUMN created_by    INTEGER REFERENCES user(id);   -- NULL = CLI / pre-2.0 / invite redeemed
ALTER TABLE user ADD COLUMN last_login_at INTEGER;          -- completed logins only (second factor verified)
-- Non-login label shown to every role in attribution (D26 d). Login names are shown to admins only.
ALTER TABLE user ADD COLUMN display_name  TEXT CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 32);
-- Default handle 'user-<id>'; 'acct-<id>' (then 'acct-<id>-1', 'acct-<id>-2') when the candidate equals any existing
-- login name (N5): the migration must never publish a login name as a handle. NULL stays legal in the schema; the
-- application renders NULL as 'user-<id>'.
UPDATE user SET display_name = CASE
    WHEN NOT EXISTS (SELECT 1 FROM user o WHERE o.username = ('user-' || user.id) COLLATE NOCASE)
        THEN 'user-' || user.id
    WHEN NOT EXISTS (SELECT 1 FROM user o WHERE o.username = ('acct-' || user.id) COLLATE NOCASE)
        THEN 'acct-' || user.id
    WHEN NOT EXISTS (SELECT 1 FROM user o WHERE o.username = ('acct-' || user.id || '-1') COLLATE NOCASE)
        THEN 'acct-' || user.id || '-1'
    ELSE 'acct-' || user.id || '-2' END;
CREATE UNIQUE INDEX user_display_name ON user(display_name COLLATE NOCASE) WHERE deleted_at IS NULL;
-- N5: ^user-[0-9]+$ is reserved for display handles. New rows only (1.x names are flagged, never renamed); the trigger
-- is the backstop for the CLI/invite checks. lower() because GLOB is case-sensitive.
CREATE TRIGGER user_reserved_handle BEFORE INSERT ON user
WHEN lower(NEW.username) GLOB 'user-[0-9]*' AND lower(NEW.username) NOT GLOB 'user-*[^0-9]*'
BEGIN SELECT RAISE(ABORT, 'RESERVED_LOGIN_NAME'); END;
-- Set by the staged recovery commit (M3): when and by whom (admin id, NULL = operator) credentials were replaced.
ALTER TABLE user ADD COLUMN credentials_replaced_at INTEGER;
ALTER TABLE user ADD COLUMN credentials_replaced_by INTEGER;
CREATE INDEX user_active_admin ON user(id) WHERE role = 'admin' AND disabled_at IS NULL AND deleted_at IS NULL;

-- Last-admin invariant, enforced by the database in addition to the application transaction (SEC-062).
-- (The application additionally requires another admin with totp_enabled=1, L3b; a trigger cannot express "usable"
-- without breaking operator recovery, so that rule lives in the writer transaction.)
CREATE TRIGGER user_keep_one_admin BEFORE UPDATE OF role, disabled_at, deleted_at ON user
WHEN OLD.role = 'admin' AND OLD.disabled_at IS NULL AND OLD.deleted_at IS NULL
 AND (NEW.role <> 'admin' OR NEW.disabled_at IS NOT NULL OR NEW.deleted_at IS NOT NULL)
 AND NOT EXISTS (SELECT 1 FROM user WHERE id <> OLD.id AND role = 'admin' AND disabled_at IS NULL AND deleted_at IS NULL)
BEGIN SELECT RAISE(ABORT, 'LAST_ADMIN'); END;
-- Accounts are tombstoned, never deleted: ids stay unique forever (audit_log.actor_id, release.added_by stay truthful)
-- and a plain INTEGER PRIMARY KEY would otherwise reuse the highest id.
CREATE TRIGGER user_no_row_delete BEFORE DELETE ON user
BEGIN SELECT RAISE(ABORT, 'USER_ROWS_ARE_TOMBSTONED'); END;
-- L3a: INSERT OR REPLACE / ON CONFLICT REPLACE would delete the old row. BEFORE INSERT triggers fire before conflict
-- resolution, so refuse any insert that would collide (the delete trigger above also fires for REPLACE because every
-- connection sets PRAGMA recursive_triggers=ON; the code-review rule forbids REPLACE on `user` outright).
CREATE TRIGGER user_no_replace BEFORE INSERT ON user
WHEN EXISTS (SELECT 1 FROM user WHERE id = NEW.id OR username = NEW.username COLLATE NOCASE)
BEGIN SELECT RAISE(ABORT, 'USER_ROWS_ARE_NEVER_REPLACED'); END;

-- One-time tokens: account invitations and admin-issued recovery codes. Only a hash is stored, ever.
CREATE TABLE invite (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  purpose     TEXT NOT NULL CHECK (purpose IN ('invite','recover')),
  token_hash  BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),  -- SHA-256("nzbd/invite/v1\0" || canonical code)
  username    TEXT COLLATE NOCASE,                 -- invite: the reserved name; recover: NULL
  role        TEXT CHECK (role IN ('member','viewer')),              -- invite only; NEVER 'admin' (N3/D27)
  user_id     INTEGER REFERENCES user(id),         -- recover only: the account whose password/MFA the code replaces
  created_by  INTEGER REFERENCES user(id),         -- NULL = operator via CLI
  created_via TEXT NOT NULL CHECK (created_via IN ('ui','cli')),
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,                    -- invite: <= 7 d (default 48 h); recover: <= 24 h (default 2 h)
  used_at     INTEGER, used_by INTEGER REFERENCES user(id),  -- used_by = the account created (invite) or recovered
  revoked_at  INTEGER,
  CHECK (expires_at > created_at),
  CHECK (expires_at - created_at <= CASE purpose WHEN 'recover' THEN 86400 ELSE 604800 END),   -- M3
  CHECK ((purpose = 'invite'  AND username IS NOT NULL AND role IS NOT NULL AND user_id IS NULL)
      OR (purpose = 'recover' AND user_id IS NOT NULL AND username IS NULL AND role IS NULL))
) STRICT;
CREATE UNIQUE INDEX invite_open_username ON invite(username) WHERE purpose = 'invite'  AND used_at IS NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX invite_open_user     ON invite(user_id)  WHERE purpose = 'recover' AND used_at IS NULL AND revoked_at IS NULL;
CREATE INDEX invite_expiry ON invite(expires_at);

-- Pending-MFA sessions created by an invite/recovery redemption have already proven possession of the out-of-band code.
ALTER TABLE session ADD COLUMN enroll_proven INTEGER NOT NULL DEFAULT 0 CHECK (enroll_proven IN (0,1));
-- Second-factor attempt cap per pending session (N1): the 5th failed attempt, from any address, destroys the session.
ALTER TABLE session ADD COLUMN mfa_failures INTEGER NOT NULL DEFAULT 0 CHECK (mfa_failures BETWEEN 0 AND 5);

-- Staged recovery (M3): redeeming a recovery code changes NOTHING about the account. The new password hash and the new
-- sealed TOTP secret wait here until the enrollment confirmation commits them atomically (and re-checks the target).
-- One row per user, bound to the pending session that redeemed the code, valid <= 60 minutes. No INSERT OR REPLACE:
-- the application deletes then inserts in one transaction.
CREATE TABLE credential_staging (
  user_id         INTEGER PRIMARY KEY REFERENCES user(id),
  session_hash    BLOB NOT NULL UNIQUE CHECK (length(session_hash) = 32),   -- the redeeming pending_mfa session
  invite_id       INTEGER NOT NULL REFERENCES invite(id),
  issued_by       INTEGER,                                                  -- admin id, NULL = operator
  password_hash   TEXT NOT NULL,                                            -- PHC string (argon2id)
  totp_secret_enc BLOB,                                                     -- sealed, AAD = user id
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL CHECK (expires_at > created_at AND expires_at - created_at <= 3600)
) STRICT;
-- N4 backstops (the application also deletes explicitly at each event; the commit never relies on these).
CREATE TRIGGER staging_dies_with_session AFTER DELETE ON session
BEGIN DELETE FROM credential_staging WHERE session_hash = OLD.id_hash; END;
CREATE TRIGGER staging_dies_with_credential_change AFTER UPDATE OF password_hash, role, disabled_at, deleted_at ON user
BEGIN DELETE FROM credential_staging WHERE user_id = OLD.id; END;

-- Persisted per-account aggregate throttle (N1/N2). One row per account at most; rows idle > 48 h are purged.
CREATE TABLE account_throttle (
  user_id           INTEGER PRIMARY KEY REFERENCES user(id),
  hour_start        INTEGER NOT NULL,                -- rolling-hour window of the aggregate
  hour_failures     INTEGER NOT NULL CHECK (hour_failures >= 0),
  throttled_until   INTEGER,                         -- unknown-IP throttling in force until
  day_start         INTEGER NOT NULL,                -- 24 h window of the second-factor daily cap
  day_mfa_failures  INTEGER NOT NULL CHECK (day_mfa_failures >= 0),
  mfa_refused_until INTEGER                          -- second-factor refusal for unknown addresses (1 h per trip)
) STRICT;

-- Hard lock keyed on (account, client IP /64) (M1). Replaces user.failed_logins/locked_until for refusal (those columns
-- stay, unused, for restore compatibility). Bounded: at most 64 rows per user (oldest evicted), idle > 24 h purged.
CREATE TABLE login_lock (
  user_id       INTEGER NOT NULL REFERENCES user(id),
  ip_key        TEXT NOT NULL,                     -- IPv4 address or IPv6 /64 prefix, as the rate limiter keys it
  failures      INTEGER NOT NULL CHECK (failures >= 0),
  locked_until  INTEGER,
  last_failure  INTEGER NOT NULL,
  PRIMARY KEY (user_id, ip_key)
) STRICT, WITHOUT ROWID;
-- The 5 most recent addresses of COMPLETED logins (N8): exempt from unknown-IP throttling. At most 5 rows per user.
CREATE TABLE user_known_ip (
  user_id   INTEGER NOT NULL REFERENCES user(id),
  ip_key    TEXT NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (user_id, ip_key)
) STRICT, WITHOUT ROWID;

-- Attribution on the shared library. NULL = unknown/not applicable (watch folder, pre-2.0 data, operator CLI).
ALTER TABLE release       ADD COLUMN added_by   INTEGER REFERENCES user(id);   -- from the SESSION/key owner, never input
ALTER TABLE release_trash ADD COLUMN added_by   INTEGER;                       -- plain integers like the rest of the trash row
ALTER TABLE release_trash ADD COLUMN deleted_by INTEGER;
ALTER TABLE ingest_log    ADD COLUMN user_id    INTEGER REFERENCES user(id);   -- uploading account (UI) / key owner (API)

-- API key ownership (M4). Existing (instance) keys become the oldest admin's and keep working.
ALTER TABLE api_key ADD COLUMN owner_id INTEGER REFERENCES user(id);
UPDATE api_key SET owner_id = (SELECT min(id) FROM user WHERE role = 'admin');
CREATE INDEX api_key_owner ON api_key(owner_id) WHERE revoked_at IS NULL;

-- Audit actor. `actor` stays the display snapshot; actor_id is the stable identity; legacy 1.x rows have actor_kind NULL.
ALTER TABLE audit_log ADD COLUMN actor_id   INTEGER;                           -- no FK: audit rows outlive everything
ALTER TABLE audit_log ADD COLUMN actor_kind TEXT CHECK (actor_kind IS NULL OR actor_kind IN ('user','cli','system','api_key','anonymous'));
ALTER TABLE audit_log ADD COLUMN actor_role TEXT CHECK (actor_role IS NULL OR actor_role IN ('admin','member','viewer'));
ALTER TABLE audit_log ADD COLUMN target_id  INTEGER;                           -- account the event acted on
-- M5/N7 backfill by ALLOWLIST, verified against what the 1.x code actually writes (T101a):
--   * the 1.x CLI writes the literal actor 'cli' (cleanup_purge, release_restore, user.create, user.reset_password,
--     user.reset_mfa, user.enroll_token_issued, totp_key_rotated, apikey.create/revoke); it does NOT write the
--     target's name there (the spec text assumed it did);
--   * the 1.x web layer writes `user:<id>` as actor for category_override, source_label_edit, download, release_delete,
--     cleanup_purge, apikey.create and apikey.revoke, and the username snapshot for mfa.*, user.password_changed,
--     session.revoked, session.revoked_others; `logout` is written with a NULL actor (stays unattributed);
--   * failures write the (caller-supplied) username, or NULL for an unknown one.
-- (0) CLI rows first, keyed on the actor text, so an account named cli/system/api/anonymous is never credited with
-- them. 1.x had at most one account, so the account targeted by `user.*` CLI events is min(id).
UPDATE audit_log SET actor_kind = 'cli'
 WHERE actor = 'cli' AND actor_kind IS NULL
   AND event IN ('cleanup_purge','release_delete','release_restore','totp_key_rotated','apikey.create','apikey.revoke',
                 'user.create','user.reset_password','user.reset_mfa','user.enroll_token_issued');
UPDATE audit_log SET target_id = (SELECT min(id) FROM user)
 WHERE actor_kind = 'cli' AND target_id IS NULL
   AND event IN ('user.create','user.reset_password','user.reset_mfa','user.enroll_token_issued');
-- (1a) events that exist only after a completed authentication, written with the web id form `user:<id>`: credited to
-- the oldest account (now the admin) only when the id in the text is that account.
UPDATE audit_log SET actor_id = (SELECT min(id) FROM user), actor_kind = 'user', actor_role = 'admin'
 WHERE actor_kind IS NULL
   AND event IN ('category_override','source_label_edit','download','release_delete','cleanup_purge',
                 'apikey.create','apikey.revoke')
   AND actor = 'user:' || (SELECT min(id) FROM user);
-- (1b) completed-authentication events that carry the username snapshot; never for a reserved actor name.
UPDATE audit_log SET actor_id = (SELECT min(id) FROM user), actor_kind = 'user', actor_role = 'admin'
 WHERE actor_kind IS NULL
   AND event IN ('mfa.ok','mfa.enrolled','mfa.recovery_used','mfa.recovery_regenerated',
                 'user.password_changed','session.revoked','session.revoked_others')
   AND actor IS NOT NULL
   AND lower(actor) NOT IN ('cli','system','api','anonymous')
   AND EXISTS (SELECT 1 FROM user u WHERE u.id = (SELECT min(id) FROM user) AND u.username = audit_log.actor COLLATE NOCASE);
-- (2) failures and pre-authentication rows: caller-supplied identity, never an actor; the targeted account is target_id.
UPDATE audit_log SET actor_kind = 'anonymous',
       target_id = (SELECT u.id FROM user u WHERE u.username = audit_log.actor COLLATE NOCASE)
 WHERE actor_kind IS NULL AND event IN ('login.fail','login.password_ok','mfa.fail','mfa.enroll_token_ok');
-- apikey.use_failure: the actor text is the constant 'api', never an account (no target).
UPDATE audit_log SET actor_kind = 'anonymous'
 WHERE actor_kind IS NULL AND event = 'apikey.use_failure';
-- Every other legacy row keeps actor_kind NULL ("unknown"): better unattributed than misattributed.
CREATE INDEX audit_actor ON audit_log(actor_id, ts DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX audit_account_events ON audit_log(ts DESC) WHERE target_id IS NOT NULL;   -- M6 retention + Users page
-- I-6: retention is decided by EVENT NAME, never by "target_id IS NOT NULL" (failure rows carry target_id too).
