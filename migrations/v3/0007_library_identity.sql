-- v3/0007_library_identity.sql (T122; ARCHITECTURE v3 13.5, review 34 M2, SEC-101). Forward-only.
-- The library identity: the backend name and a random instance id, created with the database and repeated by the
-- anchor in `paths.state`. A database whose identity does not match the anchor is refused (`LIBRARY_MISMATCH`), so a
-- configuration change can never mix two libraries. Owner-written like the rest of `db_state`; the app role reads it.
ALTER TABLE db_state ADD COLUMN backend text NOT NULL DEFAULT 'postgres' CHECK (backend = 'postgres');
ALTER TABLE db_state ADD COLUMN instance_id bytea NOT NULL DEFAULT uuid_send(gen_random_uuid())
  CHECK (octet_length(instance_id) = 16);
