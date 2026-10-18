-- v3/0010_roles.sql (T134, D40; docs/v3/DATA_MODEL.md). Forward-only, never edit after release.
-- The role set becomes `viewer`, `uploader`, `admin`: the former `member` is renamed `uploader` and no longer edits
-- metadata (an application rule, not a schema one). Same shape as SQLite `migrations/v3-sqlite/0004_roles.sql`.
-- Fresh data (owner rule): there is no conversion of `member` rows and no upgrade path. Like the SQLite twin (which
-- has to rebuild the tables), the migration refuses a library that already holds accounts, invitations, audit rows or
-- an audit chain head, so both backends accept and refuse exactly the same libraries (T134 review I4); the error names
-- FRESH_DATA_REQUIRED. A 3.4 binary refuses a database with this migration (SCHEMA_NEWER).
DO $fresh$
BEGIN
  IF EXISTS (SELECT 1 FROM account) OR EXISTS (SELECT 1 FROM invite) OR EXISTS (SELECT 1 FROM audit_log)
     OR EXISTS (SELECT 1 FROM audit_chain_state
                WHERE rows <> 0 OR head_hash <> '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea
                   OR floor_hash <> '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea) THEN
    RAISE EXCEPTION 'FRESH_DATA_REQUIRED: the roles change (T134) needs a new library; this one already holds accounts, invitations or audit history';
  END IF;
END
$fresh$;

ALTER TABLE account DROP CONSTRAINT account_role_check;
ALTER TABLE account ADD CONSTRAINT account_role_check CHECK (role IN ('admin','uploader','viewer'));

-- An invitation never carries `admin` (D27).
ALTER TABLE invite DROP CONSTRAINT invite_role_check;
ALTER TABLE invite ADD CONSTRAINT invite_role_check CHECK (role IN ('uploader','viewer'));

ALTER TABLE audit_log DROP CONSTRAINT audit_log_actor_role_check;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_actor_role_check CHECK (actor_role IN ('admin','uploader','viewer'));
