-- 0007: database-backed NZB blob store (T080, D6).
--
-- `nzb_blob` holds the raw NZB bytes (zstd-compressed unless that does not help) addressed by
-- their SHA-256, exactly like the files of the filesystem store. It is unused while
-- `store.backend = "fs"`. `nzb_blob_trash` is the quarantine of `store gc` (reason 'gc') and of
-- `store migrate --finalize` (reason 'migrated'): rows are moved, never deleted, and only 'gc'
-- rows are ever purged. `store_migration` is the resumable progress record of
-- `nzbd store migrate`; it is an optimisation, never the source of truth (finalize re-reads and
-- re-hashes every blob).

CREATE TABLE nzb_blob (
  sha256     BLOB    NOT NULL PRIMARY KEY CHECK (length(sha256) = 32),
  size_raw   INTEGER NOT NULL CHECK (size_raw >= 0),   -- length of the NZB bytes
  size_comp  INTEGER NOT NULL CHECK (size_comp >= 0),  -- length of `data`
  codec      TEXT    NOT NULL CHECK (codec IN ('raw', 'zstd')),
  data       BLOB    NOT NULL,
  created_at INTEGER NOT NULL                          -- unix secs; refreshed by a dedup `put` (GC grace)
) STRICT;

CREATE INDEX nzb_blob_created ON nzb_blob(created_at);

CREATE TABLE nzb_blob_trash (
  id         INTEGER PRIMARY KEY,
  sha256     BLOB    NOT NULL CHECK (length(sha256) = 32),
  size_raw   INTEGER NOT NULL CHECK (size_raw >= 0),
  size_comp  INTEGER NOT NULL CHECK (size_comp >= 0),
  codec      TEXT    NOT NULL CHECK (codec IN ('raw', 'zstd')),
  data       BLOB    NOT NULL,
  created_at INTEGER NOT NULL,
  trashed_at INTEGER NOT NULL,
  reason     TEXT    NOT NULL CHECK (reason IN ('gc', 'migrated'))
) STRICT;

CREATE INDEX nzb_blob_trash_sha ON nzb_blob_trash(sha256);

CREATE TABLE store_migration (
  sha256     BLOB    NOT NULL CHECK (length(sha256) = 32),
  target     TEXT    NOT NULL CHECK (target IN ('fs', 'db')),
  state      TEXT    NOT NULL CHECK (state IN ('verified')),
  size_raw   INTEGER NOT NULL CHECK (size_raw >= 0),
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (sha256, target)
) STRICT, WITHOUT ROWID;
