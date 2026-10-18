-- 0009_release_origin.sql (T084): how a release entered the index: 'watch' (watch folder),
-- 'upload' (UI form) or 'api' (POST /api/v1/nzb). Display data for the Source column; NULL when
-- unknown (rows created by tools that do not record it). Existing rows are backfilled from the
-- ingest log (the 'ok' row that created the release), which still has them unless it was pruned.
ALTER TABLE release ADD COLUMN origin TEXT CHECK (origin IS NULL OR origin IN ('watch','upload','api'));

UPDATE release SET origin = l.origin
FROM (
  SELECT release_id,
         CASE source WHEN 'watch' THEN 'watch' WHEN 'upload_ui' THEN 'upload' ELSE 'api' END AS origin
  FROM ingest_log
  WHERE outcome = 'ok' AND release_id IS NOT NULL
) AS l
WHERE l.release_id = release.id;
