-- 0004_login_decay.sql: remember when the last failed login happened so the failure counter can
-- decay after a quiet period (an attacker must not be able to keep the owner locked out forever).
ALTER TABLE user ADD COLUMN last_failed_at INTEGER;
