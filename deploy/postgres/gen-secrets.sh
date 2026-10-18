#!/bin/bash
# nzbd (T116): generates the PostgreSQL role passwords once, in the one-shot `dbsecrets` compose service
# (`docker compose --profile setup run --rm dbsecrets`; deploy/install.sh does it). Never prints a password.
#
#   /out/app/nzbd_db_password         app role, for nzbd serve      volume nzbd_secrets       nzbd user, 0400
#   /out/setup/nzbd_db_owner_password owner role, for `setup` ONLY  volume nzbd_setup_secrets nzbd user, 0400
#   /out/pg/{nzbd_db_password,nzbd_db_owner_password,superuser}     volume pg_secrets         uid 999,   0400
#
# The postgres server reads its copies once, when it initializes an empty data directory (initdb/10-nzbd-roles.sh);
# the superuser password exists only because the image's entrypoint insists on one: pg_hba.conf allows the
# superuser by peer authentication on the socket only, never by password. Refuses to overwrite anything: existing
# secrets are kept (the server's roles already use them).
set -eu
umask 077
# The nzbd user ("nzbd user" above): NZBD_SECRETS_APP_UID / NZBD_SECRETS_APP_GID, set by the compose service from
# NZBD_UID / NZBD_GID in .env (T128; default 10001; the GID defaults to the UID, as scripts/browser_check.sh relies on).
# Never 0: nzbd does not run as root, and a root-owned secret would be refused by serve. Never 999 (this server's
# postgres user: the superuser by peer authentication), 65532 or 65534 (review 44 M2; same rule as install.sh).
APP_UID=${NZBD_SECRETS_APP_UID:-10001} PG_UID=999
APP_GID=${NZBD_SECRETS_APP_GID:-$APP_UID}
ok_id() { case "$1" in '' | *[!0-9]* | 0* | 999 | 65532 | 65534) return 1 ;; esac; [ "${#1}" -le 10 ] && [ "$1" -le 2147483646 ]; }
ok_id "$APP_UID" && ok_id "$APP_GID" || { echo "dbsecrets: invalid NZBD_SECRETS_APP_UID / NZBD_SECRETS_APP_GID (1-2147483646; not 0, 999 = the PostgreSQL superuser by peer authentication, 65532, 65534)" >&2; exit 1; }

gen() { head -c 32 /dev/urandom | base64 | tr -d '\n=' | tr '+/' '-_'; }

for d in /out/app /out/setup /out/pg; do [ -d "$d" ] || { echo "dbsecrets: $d is not mounted" >&2; exit 1; }; done
have=0; for f in /out/app/nzbd_db_password /out/setup/nzbd_db_owner_password /out/pg/superuser; do [ -e "$f" ] && have=$((have + 1)); done
if [ "$have" = 3 ]; then echo "dbsecrets: database secrets already exist; nothing changed"; exit 0; fi
if [ "$have" != 0 ]; then echo "dbsecrets: some database secrets exist and some do not; refusing to guess (docs/RUNBOOK.md)" >&2; exit 1; fi

# Directory ownership first: a volume that did not exist yet was created root-owned for this container.
chown "$APP_UID:$APP_GID" /out/app /out/setup && chmod 0700 /out/app /out/setup
chown "$PG_UID:$PG_UID" /out/pg && chmod 0700 /out/pg

put() { # put FILE UID:GID VALUE: new file, 0400, owned by UID:GID (value from a variable, never argv of another program)
  ( set -C; printf '%s' "$3" >"$1" )
  chmod 0400 "$1"
  chown "$2" "$1"
}
app=$(gen); owner=$(gen); su=$(gen)
[ "${#app}" -ge 40 ] && [ "${#owner}" -ge 40 ] && [ "${#su}" -ge 40 ] || { echo "dbsecrets: no randomness" >&2; exit 1; }
put /out/pg/nzbd_db_password "$PG_UID:$PG_UID" "$app"
put /out/pg/nzbd_db_owner_password "$PG_UID:$PG_UID" "$owner"
put /out/pg/superuser "$PG_UID:$PG_UID" "$su"
put /out/setup/nzbd_db_owner_password "$APP_UID:$APP_GID" "$owner"
put /out/app/nzbd_db_password "$APP_UID:$APP_GID" "$app"
unset app owner su
echo "dbsecrets: generated the app, owner and superuser passwords (files 0400; never printed)"
