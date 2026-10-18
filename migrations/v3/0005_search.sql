-- v3/0005_search.sql (T112; docs/v3/DATA_MODEL.md section 3.3, ARCHITECTURE v3 sections 3.1-3.3; SEC-091, SEC-092).
-- Forward-only. The transactional outbox between the store and the Tantivy indexer (T113). Rows carry NO payload: the
-- indexer always reads the current release state, so a replayed, duplicated or reordered row is harmless.

CREATE TABLE search_outbox (
  seq         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  release_id  bigint NOT NULL,          -- no FK: a removal is an outbox row for a vanished id
  enqueued_at bigint NOT NULL
) WITH (autovacuum_vacuum_scale_factor = 0, autovacuum_vacuum_threshold = 10000);

CREATE TABLE search_replay (release_id bigint PRIMARY KEY);
CREATE TABLE search_quarantine (
  release_id bigint PRIMARY KEY,
  error_code text   NOT NULL CHECK (octet_length(error_code) BETWEEN 1 AND 64),
  at         bigint NOT NULL
);
CREATE TABLE search_state (
  id                   smallint PRIMARY KEY CHECK (id = 1),
  epoch                bytea    NOT NULL CHECK (octet_length(epoch) = 16),  -- rotated by db restore / restore-finish
  replay               boolean  NOT NULL DEFAULT false,
  rebuild_requested_at bigint,
  rebuild_generation   integer  NOT NULL DEFAULT 0 CHECK (rebuild_generation >= 0)
);
INSERT INTO search_state (id, epoch) VALUES (1, uuid_send(gen_random_uuid()));

GRANT SELECT, INSERT, DELETE ON search_outbox TO nzbd_app;
GRANT SELECT, INSERT, DELETE ON search_replay, search_quarantine TO nzbd_app;
GRANT SELECT, UPDATE ON search_state TO nzbd_app;
