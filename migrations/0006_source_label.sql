-- 0006_source_label.sql: free-text, user-specified origin of a release ("torrent", "personal archive", ...).
-- Display data only: sanitized (nzb_core::sanitize_text) and capped at 64 bytes by nzb-store before insert;
-- NULL for watch-folder files and when the submitter gave none. Never used in SQL fragments, paths or classes.
ALTER TABLE release ADD COLUMN source_label TEXT CHECK (source_label IS NULL OR length(CAST(source_label AS BLOB)) <= 64);
