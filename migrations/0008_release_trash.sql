-- 0008_release_trash.sql (T081): deleted releases. A deleted release is MOVED out of
-- `release`/`nzb_file`/`release_fts` into this table in one transaction, so every list, search,
-- tile, explorer and download query is correct without a `deleted` filter. Only display
-- essentials are kept; the NZB itself stays restorable as a blob in the store's trash area until
-- the owner purges it. `sha256` is UNIQUE here, not in `release`: re-ingesting the same bytes
-- creates a fresh release (the sha is free again). `category_id` is a plain integer (no FK):
-- the trash must outlive taxonomy changes.
CREATE TABLE release_trash (
  id             INTEGER PRIMARY KEY,
  original_id    INTEGER NOT NULL,                 -- the id the release had (audit correlation only)
  sha256         BLOB NOT NULL UNIQUE CHECK (length(sha256) = 32),
  title          TEXT NOT NULL,
  category_id    INTEGER NOT NULL,
  total_bytes    INTEGER NOT NULL CHECK (total_bytes >= 0),
  nzb_size_bytes INTEGER NOT NULL CHECK (nzb_size_bytes >= 0),
  file_count     INTEGER NOT NULL CHECK (file_count >= 0),
  source_name    TEXT,
  ingested_at    INTEGER NOT NULL,
  deleted_at     INTEGER NOT NULL
) STRICT;
CREATE INDEX release_trash_deleted ON release_trash(deleted_at DESC);

-- Trash blobs of deleted releases for `store.backend = "db"`. A separate table, not a new reason
-- in `nzb_blob_trash` (0007 is released; its CHECK allows only 'gc' and 'migrated'). One row per
-- digest; the filesystem backend keeps the same thing as `store/.trash/<sha>.nzb`.
CREATE TABLE release_trash_blob (
  sha256     BLOB    NOT NULL PRIMARY KEY CHECK (length(sha256) = 32),
  size_raw   INTEGER NOT NULL CHECK (size_raw >= 0),
  size_comp  INTEGER NOT NULL CHECK (size_comp >= 0),
  codec      TEXT    NOT NULL CHECK (codec IN ('raw', 'zstd')),
  data       BLOB    NOT NULL,
  created_at INTEGER NOT NULL,
  trashed_at INTEGER NOT NULL
) STRICT;
