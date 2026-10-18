-- v3-sqlite/0002_saved_search.sql (T127, D38; docs/v3/DATA_MODEL.md 3.2a and 8). Forward-only.
-- Same shape and rules as Postgres `migrations/v3/0008_saved_search.sql`: private per account, the validated filter
-- set as a JSON object (never Tantivy syntax, never a URL), names unique per account, at most 25 per account (store
-- rule, one writer transaction). A 3.1 binary refuses a database with this migration (unknown ledger version);
-- rollback = restore the pre-upgrade backup.
CREATE TABLE saved_search (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id   INTEGER NOT NULL REFERENCES account(id),
  name         TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 60),
  -- `json_type` raises on invalid JSON, so it is only reached through the CASE.
  filters      TEXT    NOT NULL CHECK (length(CAST(filters AS BLOB)) <= 2048
                 AND CASE WHEN json_valid(filters) THEN json_type(filters) = 'object' ELSE 0 END),
  created_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  CONSTRAINT saved_search_name_per_account UNIQUE (account_id, name)
) STRICT;
