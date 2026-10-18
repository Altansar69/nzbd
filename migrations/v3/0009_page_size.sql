-- v3/0009_page_size.sql (T133, after 3.3.0; docs/v3/DATA_MODEL.md 3.2). Forward-only.
-- Per-account page sizes of the release list and of a release's files table. The CHECKs are the allowlists of the web
-- layer (`nzb_store::ReleasePageSize` / `FilePageSize`); the defaults keep an absent choice at 50 and 100. Development
-- rule ("fresh data each release"): no upgrade path is promised for this change; rollback = restore the
-- pre-upgrade backup. The table-level grants of 0003 cover the new columns.
ALTER TABLE user_pref
  ADD COLUMN page_size_releases bigint  NOT NULL DEFAULT 50 CHECK (page_size_releases IN (25, 50, 100)),
  ADD COLUMN page_size_files    bigint  NOT NULL DEFAULT 100 CHECK (page_size_files IN (50, 100, 250, 500));
