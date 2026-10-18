#!/bin/sh
# nzbd (T128): hands the host directories nzbd reads or writes to their owners, in the one-shot `volperms` compose
# service (`docker compose --profile setup run --rm volperms`; deploy/install.sh runs it on every deploy, before
# keygen). The directories are bind mounts under NZBD_VOLUMES_DIR, mounted here as:
#   /v/<name>        the container user NZBD_UID:NZBD_GID: secrets (TOTP key, backup key, PostgreSQL app password),
#                    state (serve.lock, db-anchor.json) and, with PostgreSQL, setup_secrets (owner password)
#   /as/<uid>/<name> a fixed service user: 65532/caddy (the proxy's CA and certificates), 999/pg_data (PostgreSQL)
#
# Fresh starts only (owner decision 2026-10-16): a /v directory that already holds files of ANOTHER user (an earlier
# install with another NZBD_UID:NZBD_GID) is refused and nothing is changed in any directory; it is never re-owned,
# emptied or deleted. For the current user's own directories (a re-run) and new, empty ones, only the directory root is
# set (owner, 0700) and a marker is added. No file is read, moved, deleted or regenerated. The /as directories only get
# their root owner and mode.
#
# The marker is an empty, read-only `.nzbd-volume` file in each /v directory. nzbd never reads it.
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
    echo "volperms: cannot inspect the directory mounted at $d; nothing was changed" >&2
    exit 1
  fi
  other=$(printf '%s\n' "$found" | head -n 1)
  if [ -n "$other" ]; then
    echo "volperms: the directory mounted at $d holds files of another user (${other#"$d"/}), not $uid:$gid: it belongs to" >&2
    echo "volperms: an earlier install. Nothing was changed; directories are never re-owned or deleted (fresh start: RUNBOOK)." >&2
    exit 1
  fi
done
[ "$n" -gt 0 ] || { echo "volperms: no directory is mounted under /v" >&2; exit 1; }

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

# Pass 3: the directories of the fixed service users (only the root of each; whatever is inside is theirs already).
m=0
for u in /as/*; do
  [ -d "$u" ] && [ ! -L "$u" ] || continue
  su=${u#/as/}
  case "$su" in 999 | 65532) ;; *) echo "volperms: unexpected owner $su under /as" >&2; exit 1 ;; esac
  for d in "$u"/*; do
    [ -d "$d" ] && [ ! -L "$d" ] || continue
    chown -h "$su:$su" "$d"
    chmod 0700 "$d"
    m=$((m + 1))
  done
done
echo "volperms: $n directory(ies) owned by $uid:$gid, $m owned by their service user"
