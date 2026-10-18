-- 0003_ops.sql (from docs/DATA_MODEL.md; forward-only, never edit after release)
CREATE TABLE ingest_log (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, source TEXT NOT NULL CHECK (source IN ('watch','upload_ui','upload_api')),
  api_key_id INTEGER REFERENCES api_key(id) ON DELETE SET NULL, source_name TEXT, sha256 BLOB,
  outcome TEXT NOT NULL CHECK (outcome IN ('ok','duplicate','failed')),
  error_code TEXT, detail TEXT, release_id INTEGER REFERENCES release(id) ON DELETE SET NULL
) STRICT;
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, actor TEXT, event TEXT NOT NULL, detail TEXT, ip TEXT
) STRICT;
CREATE INDEX audit_ts ON audit_log(ts DESC);
CREATE INDEX ingest_ts ON ingest_log(ts DESC);
