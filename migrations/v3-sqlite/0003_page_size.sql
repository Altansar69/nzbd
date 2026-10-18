-- v3-sqlite/0003_page_size.sql (T133, after 3.3.0; docs/v3/DATA_MODEL.md 3.2). Forward-only.
-- Same columns and rules as Postgres `migrations/v3/0009_page_size.sql`: per-account page sizes of the release list
-- and of a release's files table, CHECKed against the web layer's allowlists. Development rule ("fresh data
-- each release"): no upgrade path is promised for this change; rollback = restore the pre-upgrade backup.
ALTER TABLE user_pref ADD COLUMN page_size_releases INTEGER NOT NULL DEFAULT 50
  CHECK (page_size_releases IN (25, 50, 100));
ALTER TABLE user_pref ADD COLUMN page_size_files INTEGER NOT NULL DEFAULT 100
  CHECK (page_size_files IN (50, 100, 250, 500));
