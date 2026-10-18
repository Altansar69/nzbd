#!/bin/sh
# nzbd (T128): hands the NEW named volumes nzbd reads or writes to the container user NZBD_UID:NZBD_GID, in the one-shot
# `volperms` compose service (`docker compose --profile setup run --rm volperms`; deploy/install.sh runs it on every
# deploy, before keygen). Every volume is mounted under /v: <prefix>_secrets (TOTP key, backup key, PostgreSQL app
# password), <prefix>_state (serve.lock, db-anchor.json) and, with PostgreSQL, <prefix>_setup_secrets (owner password).
#
# Fresh starts only (owner decision 2026-10-16): a volume that already holds files of ANOTHER user (an earlier install
# with another NZBD_UID:NZBD_GID) is refused and nothing is changed in any volume; it is never re-owned, emptied or
# deleted. For the current user's own volumes (a re-run) and new, empty ones, only the volume root is set (owner, 0700)
# and a marker is added. No file is read, moved, deleted or regenerated.
#
# Why the marker file: Docker re-applies the ownership of the image's mount point (/run/secrets and /state are
# 10001:10001 in the nzbd image) to an EMPTY named volume every time a container mounts it. A fresh volume handed to
# another UID would therefore fall back to 10001 at the next mount, before keygen or serve could write into it. A
# volume that holds a file is left as it is, so each volume gets an empty, read-only `.nzbd-volume` file. nzbd never
# reads it.
set -eu

# ok_id N: a decimal id from 1 to 2147483646, no sign, no leading zero, no blank. 0 (root) is refused: nzbd never runs
# as root (SEC-040); 999 (PostgreSQL's user = the database superuser by peer authentication), 65532 (the proxy) and
# 65534 (nobody) are reserved (review 44 M2). The length test comes first so the numeric test never sees an
# overflowing value. Same rule as deploy/install.sh valid_id.
ok_id() {
  case "$1" in '' | *[!0-9]* | 0* | 999 | 65532 | 65534) return 1 ;; esac
  [ "${#1}" -le 10 ] && [ "$1" -le 2147483646 ]
}
uid=${NZBD_UID:-}
gid=${NZBD_GID:-}
if ! ok_id "$uid" || ! ok_id "$gid"; then
  echo "volperms: NZBD_UID and NZBD_GID must be numbers from 1 to 2147483646, not 0 (root), 999 (PostgreSQL's superuser by peer authentication), 65532 (the proxy) or 65534 (nobody); nothing changed" >&2
  exit 1
fi

# Pass 1, check every volume before changing any: files of another user (the marker aside, which only says "volume
# prepared") mean an earlier install.
n=0
for d in /v/*; do
  [ -d "$d" ] && [ ! -L "$d" ] || continue
  n=$((n + 1))
  # Only the top-level marker is exempt (a directory of that name deeper down is judged like anything else), and a
  # find error is a failure, never "nothing foreign" (review 44 L3).
  if ! found=$(find "$d" -mindepth 1 ! -path "$d/.nzbd-volume" \( ! -user "$uid" -o ! -group "$gid" \) -print); then
    echo "volperms: cannot inspect the volume mounted at $d; nothing was changed" >&2
    exit 1
  fi
  other=$(printf '%s\n' "$found" | head -n 1)
  if [ -n "$other" ]; then
    echo "volperms: the volume mounted at $d holds files of another user (${other#"$d"/}), not $uid:$gid: it belongs to" >&2
    echo "volperms: an earlier install. Nothing was changed; volumes are never re-owned or deleted (fresh start: RUNBOOK)." >&2
    exit 1
  fi
done
[ "$n" -gt 0 ] || { echo "volperms: no volume is mounted under /v" >&2; exit 1; }

# Pass 2: the volume roots and the markers.
for d in /v/*; do
  [ -d "$d" ] && [ ! -L "$d" ] || continue
  chown -h "$uid:$gid" "$d"
  chmod 0700 "$d"
  m="$d/.nzbd-volume"
  if [ -L "$m" ]; then echo "volperms: $m is a symbolic link; refusing" >&2; exit 1; fi
  # Created without ever overwriting (noclobber: O_EXCL), re-owned without following a link, and chmod-ed only as a
  # regular file (review 44 L3).
  [ -e "$m" ] || (set -C && umask 077 && : >"$m")
  chown -h "$uid:$gid" "$m"
  find "$m" -maxdepth 0 -type f -exec chmod 0400 {} +
done
echo "volperms: $n volume(s) owned by $uid:$gid"
