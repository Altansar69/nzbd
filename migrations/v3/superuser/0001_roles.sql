-- v3/superuser/0001_roles.sql (T112; docs/v3/DATA_MODEL.md section 1 "Roles and privileges", review L4 a).
--
-- Run by the DATABASE SUPERUSER, connected to the nzbd database, once per database (installer, test harness). It is not
-- an sqlx migration (the owner role that runs those cannot create roles) and lives in a subdirectory the migrator does
-- not read. Idempotent: safe to run again (the test harness runs it on every per-test copy of the template, because
-- database-level privileges are not copied by CREATE DATABASE ... TEMPLATE).
--
-- Role passwords are NOT set here: the installer sets them from the secret files (`ALTER ROLE ... PASSWORD`), so no
-- credential ever lives in a migration file.

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nzbd_owner') THEN
    CREATE ROLE nzbd_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nzbd_app') THEN
    CREATE ROLE nzbd_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
  END IF;
  -- Re-assert the attributes on every run: a role created by hand with more rights is brought back down.
  ALTER ROLE nzbd_owner NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
  ALTER ROLE nzbd_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
END
$roles$;

-- The app role is a member of no role (SECURITY_REVIEW 31 L5): a membership in nzbd_owner would let it `SET ROLE` to
-- the owner. Memberships granted by hand are removed on every run.
DO $members$
DECLARE
  r record;
BEGIN
  FOR r IN SELECT g.rolname FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
           WHERE m.member = 'nzbd_app'::regrole LOOP
    EXECUTE format('REVOKE %I FROM nzbd_app', r.rolname);
  END LOOP;
END
$members$;

-- Database: no CONNECT and no TEMP for anyone else; the two nzbd roles may connect (no TEMP, no CREATE).
DO $db$
BEGIN
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO nzbd_owner, nzbd_app', current_database());
END
$db$;

-- Schema `public`: nobody may use or create anything in it (search-path hijack, review L4 a).
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- The application schema, owned by the owner role; the app role may only resolve names in it.
CREATE SCHEMA IF NOT EXISTS nzbd AUTHORIZATION nzbd_owner;
ALTER SCHEMA nzbd OWNER TO nzbd_owner;
REVOKE ALL ON SCHEMA nzbd FROM PUBLIC;
GRANT USAGE ON SCHEMA nzbd TO nzbd_app;

-- Postgres grants EXECUTE on every new function to PUBLIC; functions created by the owner get no such grant.
ALTER DEFAULT PRIVILEGES FOR ROLE nzbd_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE nzbd_owner IN SCHEMA nzbd REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE nzbd_owner IN SCHEMA nzbd REVOKE ALL ON SEQUENCES FROM PUBLIC;

-- Both roles always resolve unqualified names in `nzbd` first (connections also set it explicitly).
ALTER ROLE nzbd_owner SET search_path = nzbd, pg_temp;
ALTER ROLE nzbd_app SET search_path = nzbd, pg_temp;
