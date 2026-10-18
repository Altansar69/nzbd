-- 0010_sort_indexes.sql (T087, docs/BENCHMARK.md): one index per index-page sort order, so that a page,
-- a deep page and the "last page" link are an index walk instead of a sort of the whole library.
--
-- Measured with 1,000,000 releases: `ORDER BY posted_at IS NULL, posted_at DESC, id DESC` could not use any
-- index (the IS NULL term) and sorted every row: 0.3 s for page 1, 11 s at offset 400,000, past the 15 s
-- request timeout at the last page; the same for size and title. With these indexes every sort order is
-- 0.3-50 ms at any offset.
--
-- Each index ends in `id, category_id`: the tie-break column the ORDER BY needs, and the category the
-- category filter and the hidden-category exclusion (ui.show_xxx = false) test. A walk therefore filters on
-- the index entry itself and touches the (large) release row only for the 50 rows it returns.
-- The size index also carries file_count/segment_count so the library totals tiles
-- (COUNT/SUM over all releases) are a scan of this index, not of the table.

-- date, newest first / oldest first with undated releases last (ORDER BY posted_at DESC, id DESC is a backward
-- walk: SQLite sorts NULL lowest, so undated rows come last without an IS NULL term).
CREATE INDEX release_sort_posted      ON release(posted_at, id, category_id);
-- date, oldest first, undated last: the ORDER BY has to say `posted_at IS NULL` first, hence the expression.
CREATE INDEX release_sort_posted_null ON release((posted_at IS NULL), posted_at, id, category_id);
CREATE INDEX release_sort_bytes       ON release(total_bytes, id, category_id, file_count, segment_count);
CREATE INDEX release_sort_title       ON release(title COLLATE NOCASE, id, category_id);

-- Structured filters of the index page ("More filters": family, year, resolution, source, group, size, date,
-- flags). Every column a filter tests is in this one index, so the count behind a filtered page is a scan of
-- a ~40 MB covering index (26-65 ms at 1 M releases) instead of a lookup of every candidate row in the
-- ~500 MB table (240-800 ms warm, 14 s cold). Leading with the scene columns keeps the equality seeks the old
-- (scene_family, scene_year) index gave.
CREATE INDEX release_filter ON release(
  scene_family, scene_year, scene_resolution, scene_source, scene_group COLLATE NOCASE,
  category_id, posted_at, total_bytes, flags
);

-- Superseded: release_posted by release_sort_posted (same leading column, now with the tie-break and
-- category), release_scene by the prefix of release_filter.
DROP INDEX release_posted;
DROP INDEX release_scene;
