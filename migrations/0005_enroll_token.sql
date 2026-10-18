-- 0005_enroll_token.sql: one-time MFA enrollment token (printed by `nzbd user create|reset-mfa|enroll-token`).
-- Only a domain-separated SHA-256 and an expiry are stored; the token is consumed when enrollment is confirmed.
ALTER TABLE user ADD COLUMN enroll_token_hash BLOB CHECK (enroll_token_hash IS NULL OR length(enroll_token_hash) = 32);
ALTER TABLE user ADD COLUMN enroll_token_expires INTEGER;
