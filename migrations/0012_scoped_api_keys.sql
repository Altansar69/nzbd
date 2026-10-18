-- 0012 (T103): per-user scoped API keys. `api_key.scope` (CHECK 'upload') exists since 0001 and
-- `owner_id` since 0011; this adds the per-key upload budget and who revoked a key.
-- Both are nullable ADD COLUMNs: no rewrite, existing keys keep working with the instance defaults.

-- Uploads per minute for this key; NULL = the instance budget (`limits.upload_per_key_per_min`). The effective
-- budget is the LOWER of the two, so a key can be throttled harder than the instance default, never softer.
ALTER TABLE api_key ADD COLUMN rate_per_min INTEGER
  CHECK (rate_per_min IS NULL OR rate_per_min BETWEEN 1 AND 30);

-- Account that revoked the key through the web UI (the owner or an admin); NULL = active, or revoked by the
-- operator CLI / a lifecycle event (disable, delete, reset-password). Plain integer like release_trash.deleted_by.
ALTER TABLE api_key ADD COLUMN revoked_by INTEGER;
