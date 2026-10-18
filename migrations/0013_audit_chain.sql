-- 0013_audit_chain.sql (T105; docs/DATA_MODEL.md "Migration 0013", SEC-071..073).
-- Forward-only, never edit after release. Tamper-evident audit log: every audit row stores the hash of its own canonical
-- content and the hash of the previous row of the same chain class (two classes, because account-lifecycle rows are
-- retained longer than the rest and a purge must only ever remove a PREFIX of a chain). The hashing is done by the
-- application (SQLite has no SHA-256): new rows are chained in the transaction that writes them, rows that exist when
-- this migration runs are chained exactly once by `Db::open` (the "bootstrap", see audit_chain_meta). No row is rewritten
-- here; both ADD COLUMNs are O(1) and the only scan is the one index build, bounded by the 90-day audit purge.

ALTER TABLE audit_log ADD COLUMN chain_class INTEGER CHECK (chain_class IS NULL OR chain_class IN (0, 1));  -- 0 log, 1 account
ALTER TABLE audit_log ADD COLUMN chain_prev  BLOB    CHECK (chain_prev IS NULL OR length(chain_prev) = 32);
ALTER TABLE audit_log ADD COLUMN chain_hash  BLOB    CHECK (chain_hash IS NULL OR length(chain_hash) = 32);
CREATE INDEX audit_chain ON audit_log(chain_class, id);   -- per-class walk, purge boundary, cheap head check, NULL class = unchained

-- One row per chain class. `floor_hash` is the chain hash of the last PURGED row of the class (all zeros before any
-- purge): the first surviving row must link to it, which is what keeps the chain verifiable after retention. `head_hash`
-- is the hash of the newest row, `rows` the number of rows of the class currently stored: together they expose the
-- removal of the newest rows, which a chain alone cannot show.
CREATE TABLE audit_chain_state (
  class      INTEGER PRIMARY KEY CHECK (class IN (0, 1)),
  floor_hash BLOB NOT NULL CHECK (length(floor_hash) = 32),
  head_hash  BLOB NOT NULL CHECK (length(head_hash) = 32),
  rows       INTEGER NOT NULL DEFAULT 0 CHECK (rows >= 0)
) STRICT;
INSERT INTO audit_chain_state (class, floor_hash, head_hash, rows)
VALUES (0, zeroblob(32), zeroblob(32), 0), (1, zeroblob(32), zeroblob(32), 0);

-- Bootstrap bookkeeping. Rows with id <= legacy_max_id and no chain exist because they predate this migration: `Db::open`
-- chains them once, in id order, in one transaction, and sets bootstrapped = 1. A row WITHOUT a chain that appears
-- afterwards (an INSERT that bypassed the application) is never sealed silently: verification reports it. An empty
-- table needs no bootstrap.
CREATE TABLE audit_chain_meta (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  legacy_max_id INTEGER NOT NULL,
  bootstrapped  INTEGER NOT NULL CHECK (bootstrapped IN (0, 1))
) STRICT;
INSERT INTO audit_chain_meta (id, legacy_max_id, bootstrapped)
SELECT 1, COALESCE(MAX(id), 0), CASE WHEN COUNT(*) = 0 THEN 1 ELSE 0 END FROM audit_log;

-- Defence in depth: the content of an audit row is immutable at the SQL level (an application bug or an injected UPDATE
-- cannot rewrite history without first dropping this trigger, which needs schema rights the app never uses). The chain
-- columns stay writable for the one-off bootstrap. Retention uses DELETE, which the chain tolerates only as a prefix.
CREATE TRIGGER audit_log_immutable BEFORE UPDATE OF ts, actor, event, detail, ip, actor_id, actor_kind, actor_role, target_id
ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log rows are immutable');
END;
