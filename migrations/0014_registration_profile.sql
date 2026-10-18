-- 0014_registration_profile.sql (T109; docs/DATA_MODEL.md "Migration 0014", DECISIONS D32).
-- Forward-only, never edit after release. Two ADD COLUMNs, no rewrite, no backfill: existing and CLI-created accounts
-- have no email (NULL) until one is set, and every existing invitation starts with zero refusals.

-- The account's email (PII). Stored normalised by the application (`normalize_email`: ASCII, trimmed, lower case,
-- 6..=254 characters). NOT unique on purpose: a uniqueness answer would be an oracle on other users' addresses.
-- Nothing ever sends to it or resolves its domain (D3). A tombstone sets it back to NULL.
-- The GLOB keeps the column to the charset `normalize_email` can produce, so a direct SQL write or a future code path
-- cannot store a control character or a space that `nzbd user list` would print raw (SECURITY_REVIEW 26 I2; added
-- before 0014 was ever released).
ALTER TABLE user ADD COLUMN email TEXT
  CHECK (email IS NULL OR (length(email) BETWEEN 6 AND 254 AND email = lower(email) AND instr(email, '@') > 1
         AND email NOT GLOB '*[^a-z0-9.@_%+-]*'));

-- "Display name not available" answers given at redemption of this invitation (D32). The application revokes the
-- invitation in the same transaction as the 3rd one, so 3 is the ceiling; the CHECK is the backstop.
ALTER TABLE invite ADD COLUMN name_refusals INTEGER NOT NULL DEFAULT 0
  CHECK (name_refusals BETWEEN 0 AND 3);
