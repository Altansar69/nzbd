-- 0002_auth.sql (from docs/DATA_MODEL.md; forward-only, never edit after release)
CREATE TABLE user (
  id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,                      -- PHC string (argon2id)
  totp_secret_enc BLOB, totp_enabled INTEGER NOT NULL DEFAULT 0, totp_last_step INTEGER,
  failed_logins INTEGER NOT NULL DEFAULT 0, locked_until INTEGER,
  created_at INTEGER NOT NULL, password_changed_at INTEGER NOT NULL
) STRICT;
CREATE TABLE recovery_code (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  code_hash BLOB NOT NULL, used_at INTEGER
) STRICT;
CREATE TABLE session (
  id_hash BLOB PRIMARY KEY CHECK (length(id_hash) = 32),
  user_id INTEGER NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  stage TEXT NOT NULL CHECK (stage IN ('pending_mfa','active')),
  csrf_token BLOB NOT NULL,
  created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  ip TEXT, user_agent TEXT
) STRICT;

CREATE TABLE api_key (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, prefix TEXT NOT NULL,        -- first 6 chars, display only
  key_hash BLOB NOT NULL UNIQUE CHECK (length(key_hash) = 32),
  scope TEXT NOT NULL DEFAULT 'upload' CHECK (scope IN ('upload')),        -- only scope in v1
  created_at INTEGER NOT NULL, last_used_at INTEGER, revoked_at INTEGER
) STRICT;
