-- v3/0006_upkeep.sql (T112; docs/v3/DATA_MODEL.md sections 2, 3.5; ARCHITECTURE v3 section 9; review L4, L7).
-- Forward-only. File partitions, the restore-finish mark, and the T115 migration bookkeeping.

-- Creates every missing nzb_file partition covering ids [0, upto + 10M). The argument is CLAMPED to the last value of
-- release_id_seq + 20M (review L4 b; SECURITY_REVIEW 31 L1: not max(release.id), which the app role can raise with an
-- explicit id, while the sequence it can only advance by inserting rows) and a partition index above 999999 is
-- refused (review L4 c: six-digit names would otherwise collide). Identifiers are built from integers computed here;
-- no text argument reaches EXECUTE (SEC-088).
--
-- Lock order (SECURITY_REVIEW 31 M1): when a partition is missing, `release` is locked SHARE ROW EXCLUSIVE BEFORE the
-- CREATE touches `nzb_file`. The CREATE needs that lock anyway (the cloned foreign key), and taking it first means the
-- creator only waits for in-flight ingests to commit (it holds nothing they need), instead of holding `nzb_file` while
-- they wait for it. The application calls this in its own short transaction, never after writing to `release`.
CREATE FUNCTION nzbd.ensure_file_partitions(p_upto bigint) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = nzbd, pg_temp AS $$
DECLARE
  span constant bigint := 10000000;
  seqlast bigint;
  upto bigint;
  last_n bigint;
  nm text;
  created integer := 0;
  locked boolean := false;
BEGIN
  PERFORM pg_advisory_xact_lock(nzbd.lock_namespace(), 4);
  SELECT CASE WHEN is_called THEN last_value ELSE 0 END INTO seqlast FROM nzbd.release_id_seq;
  upto := least(greatest(coalesce(p_upto, 0), 0), seqlast + 2 * span);
  last_n := (upto + span - 1) / span;
  IF last_n > 999999 THEN
    RAISE EXCEPTION 'PARTITION_INDEX_OUT_OF_RANGE';
  END IF;
  FOR n IN 0..last_n LOOP
    nm := 'nzb_file_p' || lpad(n::text, 6, '0');
    CONTINUE WHEN to_regclass(format('nzbd.%I', nm)) IS NOT NULL;
    IF NOT locked THEN
      LOCK TABLE nzbd.release IN SHARE ROW EXCLUSIVE MODE;
      locked := true;
    END IF;
    EXECUTE format('CREATE TABLE nzbd.%I PARTITION OF nzbd.nzb_file FOR VALUES FROM (%s) TO (%s)',
                   nm, n * span, (n + 1) * span);
    created := created + 1;
  END LOOP;
  RETURN created;
END $$;

-- `nzbd db restore-finish` (SEC-068, SEC-094; SECURITY_REVIEW 31 L2): the post-restore cleanup and the mark that makes
-- the database servable again are ONE definer function, so `restore_pending` can never be cleared without the cleanup
-- (sessions, staged credentials, open codes, MFA recovery codes, throttle state and enrollment tokens removed, every
-- active API key revoked, a new index epoch). The only app-role path that changes db_state. The caller writes the
-- audit row in the same transaction.
CREATE FUNCTION nzbd.restore_finish(
    OUT n_sessions bigint, OUT n_staging bigint, OUT n_invites bigint, OUT n_recovery_codes bigint,
    OUT n_login_locks bigint, OUT n_throttles bigint, OUT n_known_ips bigint, OUT n_enroll_tokens bigint,
    OUT n_keys bigint)
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = nzbd, pg_temp AS $$
DECLARE
  now_s bigint := nzbd.db_clock();
BEGIN
  PERFORM pg_advisory_xact_lock(nzbd.lock_namespace(), nzbd.account_domain_key());
  -- Staging first (it references the invite and the session), then its owners.
  DELETE FROM nzbd.credential_staging;
  GET DIAGNOSTICS n_staging = ROW_COUNT;
  DELETE FROM nzbd.session;
  GET DIAGNOSTICS n_sessions = ROW_COUNT;
  DELETE FROM nzbd.invite WHERE used_at IS NULL;
  GET DIAGNOSTICS n_invites = ROW_COUNT;
  DELETE FROM nzbd.recovery_code;
  GET DIAGNOSTICS n_recovery_codes = ROW_COUNT;
  DELETE FROM nzbd.login_lock;
  GET DIAGNOSTICS n_login_locks = ROW_COUNT;
  DELETE FROM nzbd.account_throttle;
  GET DIAGNOSTICS n_throttles = ROW_COUNT;
  DELETE FROM nzbd.user_known_ip;
  GET DIAGNOSTICS n_known_ips = ROW_COUNT;
  UPDATE nzbd.account SET enroll_token_hash = NULL, enroll_token_expires = NULL
   WHERE enroll_token_hash IS NOT NULL OR enroll_token_expires IS NOT NULL;
  GET DIAGNOSTICS n_enroll_tokens = ROW_COUNT;
  UPDATE nzbd.api_key SET revoked_at = now_s, revoked_by = NULL WHERE revoked_at IS NULL;
  GET DIAGNOSTICS n_keys = ROW_COUNT;
  UPDATE nzbd.search_state SET epoch = uuid_send(gen_random_uuid()) WHERE id = 1;
  UPDATE nzbd.db_state SET restore_pending = false, restore_finished_at = now_s WHERE id = 1;
END $$;

-- T115 bookkeeping (`nzbd migrate --from-sqlite`, owner role only).
CREATE TABLE migrate_progress (
  table_name text   PRIMARY KEY CHECK (octet_length(table_name) BETWEEN 1 AND 64),
  last_key   bigint NOT NULL,
  rows       bigint NOT NULL CHECK (rows >= 0),
  digest     bytea  NOT NULL CHECK (octet_length(digest) = 32),
  done       boolean NOT NULL DEFAULT false,
  updated_at bigint NOT NULL
);
CREATE TABLE migrate_source (
  id                    smallint PRIMARY KEY CHECK (id = 1),
  fingerprint           bytea   NOT NULL CHECK (octet_length(fingerprint) = 32),
  sqlite_schema_version integer NOT NULL,
  started_at            bigint  NOT NULL,
  finished_at           bigint
);

-- The first partition exists from the start.
SELECT nzbd.ensure_file_partitions(0);

GRANT SELECT ON migrate_progress, migrate_source TO nzbd_app;
-- Restore detection (review M2 b): the app role reads the last values of three identity sequences for the anchor
-- file (SELECT on a sequence allows reading it, not nextval/setval).
GRANT SELECT ON SEQUENCE audit_log_id_seq, release_id_seq, search_outbox_seq_seq TO nzbd_app;
-- `serve` refuses pending migrations (review M4): the app role reads the ledger, never writes it.
GRANT SELECT ON _sqlx_migrations TO nzbd_app;
REVOKE ALL ON FUNCTION nzbd.ensure_file_partitions(bigint), nzbd.restore_finish() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nzbd.ensure_file_partitions(bigint), nzbd.restore_finish() TO nzbd_app;
