-- 0001_core.sql (from docs/DATA_MODEL.md; forward-only, never edit after release)
CREATE TABLE category (
  id        INTEGER PRIMARY KEY,                 -- Newznab-style id, e.g. 5040
  parent_id INTEGER REFERENCES category(id),
  name      TEXT NOT NULL
) STRICT;

CREATE TABLE release (
  id                    INTEGER PRIMARY KEY,
  sha256                BLOB NOT NULL UNIQUE CHECK (length(sha256) = 32),   -- also the public GUID (hex)
  title                 TEXT NOT NULL,
  category_id           INTEGER NOT NULL REFERENCES category(id),
  category_overridden   INTEGER NOT NULL DEFAULT 0 CHECK (category_overridden IN (0,1)),
  posted_at             INTEGER,                    -- max file date, NULL if unknown
  ingested_at           INTEGER NOT NULL,
  total_bytes           INTEGER NOT NULL CHECK (total_bytes >= 0),
  poster                TEXT,
  file_count            INTEGER NOT NULL CHECK (file_count >= 0),
  segment_count         INTEGER NOT NULL CHECK (segment_count >= 0),
  missing_segment_count INTEGER NOT NULL DEFAULT 0,
  par2_blocks           INTEGER NOT NULL DEFAULT 0,
  flags                 INTEGER NOT NULL DEFAULT 0, -- ReleaseFlags bitmask
  nzb_size_bytes        INTEGER NOT NULL,
  source_name           TEXT,                       -- original filename, display only
  meta_json             TEXT,                       -- head/meta entries (sanitized), capped
  category_source       TEXT NOT NULL DEFAULT 'fallback' CHECK (category_source IN ('scene','upload','meta','fallback','manual')),
  scene_family          TEXT,                       -- tv|anime|movie|music|NULL
  scene_year            INTEGER, scene_season INTEGER, scene_episode INTEGER,
  scene_resolution      TEXT, scene_source TEXT, scene_codec TEXT, scene_group TEXT,
  scene_languages       TEXT,                       -- JSON array
  scene_json            TEXT,                       -- full SceneInfo (sanitized)
  storage               TEXT NOT NULL DEFAULT 'fs' CHECK (storage IN ('fs','db'))
) STRICT;
CREATE INDEX release_posted  ON release(posted_at DESC);
CREATE INDEX release_cat     ON release(category_id, posted_at DESC);
CREATE INDEX release_ingest  ON release(ingested_at DESC);
CREATE INDEX release_scene   ON release(scene_family, scene_year);

CREATE TABLE nzb_file (
  id                INTEGER PRIMARY KEY,
  release_id        INTEGER NOT NULL REFERENCES release(id) ON DELETE CASCADE,
  idx               INTEGER NOT NULL,               -- position in the NZB (0-based)
  subject           TEXT NOT NULL,
  filename          TEXT,
  kind              TEXT NOT NULL,                  -- FileKind
  poster            TEXT,
  posted_at         INTEGER,
  bytes             INTEGER NOT NULL CHECK (bytes >= 0),
  segment_count     INTEGER NOT NULL,
  declared_segments INTEGER,
  missing_ranges    TEXT,                           -- JSON [[a,b],...] (+ "more": true)
  groups            TEXT,                           -- JSON array
  UNIQUE (release_id, idx)
) STRICT;

CREATE VIRTUAL TABLE release_fts USING fts5(
  title, filenames, poster,
  tokenize = 'unicode61 remove_diacritics 2'
);  -- rowid = release.id, maintained in the same tx as inserts/updates/deletes
