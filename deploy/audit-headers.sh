#!/bin/sh
# Header audit: compares the security headers your reverse proxy delivers for nzbd's login page with the ones nzbd
# itself sets (docs/OPERATOR_SECURITY.md, "Existing reverse proxy"). Run it after changing the proxy's middlewares.
#
#   ./audit-headers.sh https://nzbd.example.org                 # from deploy/ on the nzbd host
#   ./audit-headers.sh https://nzbd.example.org --user admin    # proxy with basic auth: curl asks for the password
#   ./audit-headers.sh https://nzbd.example.org --expected FILE # reference from FILE instead of the running container
#
# Reference: 'docker compose exec -T nzbd /nzbd security-headers' (run in this directory), one 'Name: value' per
# line. Fetch: one HTTPS GET of <url>/login with curl, redirects never followed, 15 s timeout. With --user, curl
# prompts for the password itself (it never appears in argv or on disk). Without it, a proxy with an outer login
# answers 401 with ITS OWN page, which does not carry nzbd's headers: the audit stops there.
#
# Per header: OK (same value), CHANGED (another value: both are printed), MISSING. Values are compared after
# trimming, ignoring case. HSTS: OK when max-age >= 15552000 (180 days), else WEAK, or MISSING. Server and
# X-Powered-By are reported as INFO. A CHANGED header is your proxy's decision, not an error of nzbd: decide whether
# you want it.
# Exit: 0 all OK, 1 any CHANGED/MISSING/WEAK, 2 usage or fetch error.
set -eu

usage() {
  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}
err() { printf 'audit-headers: %s\n' "$*" >&2; exit 2; }

URL=""; USER_NAME=""; EXPECTED=""; FROM_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --user) [ $# -ge 2 ] || usage; USER_NAME=$2; shift 2 ;;
    --expected) [ $# -ge 2 ] || usage; EXPECTED=$2; shift 2 ;;
    # Hidden self-test mode (scripts/deploy_check.sh static): response headers from FILE, nothing is fetched.
    --from-file) [ $# -ge 2 ] || usage; FROM_FILE=$2; shift 2 ;;
    -h | --help) usage ;;
    -*) usage ;;
    *) [ -z "$URL" ] || usage; URL=$1; shift ;;
  esac
done
[ -n "$URL" ] || usage

# https://host[:port] with an optional trailing slash; no path, query, user info or IPv6 literal. The value goes
# to curl as a URL only, but a strict shape keeps option-like or surprising input out.
case "$URL" in https://*) ;; *) err "the URL must start with https:// (got '$URL')." ;; esac
hp=${URL#https://}; hp=${hp%/}
host=${hp%%:*}
case "$hp" in
  *:*) port=${hp#*:} ;;
  *) port="" ;;
esac
case "$host" in '' | [.-]* | *[!A-Za-z0-9.-]*) err "invalid host in '$URL' (letters, digits, dots, dashes)." ;; esac
if [ -n "$port" ] || [ "$hp" != "$host" ]; then
  case "$port" in '' | *[!0-9]* | 0*) err "invalid port in '$URL'." ;; esac
  [ "$port" -le 65535 ] || err "invalid port in '$URL'."
fi
BASE="https://$hp"
if [ -n "$USER_NAME" ]; then
  # No ':' (curl would take the rest as the password) and nothing option-like.
  case "$USER_NAME" in -* | *[!A-Za-z0-9._@-]*) err "invalid user name '$USER_NAME'." ;; esac
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/nzbd-audit.XXXXXX") || err "cannot create a temporary directory."
trap 'rm -rf "$TMP"' EXIT
trap 'exit 2' INT TERM

# Control characters (escape sequences in a hostile header, CR of the HTTP line ends) are removed before anything
# is parsed or printed; tab and newline stay.
clean() { tr -d '\000-\010\013-\037\177'; }

# ---- reference ---------------------------------------------------------------------------------------
if [ -n "$EXPECTED" ]; then
  [ -f "$EXPECTED" ] || err "no such file: $EXPECTED"
  clean <"$EXPECTED" >"$TMP/expected"
else
  command -v docker >/dev/null 2>&1 || err "docker not found: run this on the nzbd host, or pass --expected FILE."
  DEPLOY_DIR=$(cd "$(dirname "$0")" && pwd)
  (cd "$DEPLOY_DIR" && docker compose exec -T nzbd /nzbd security-headers) >"$TMP/exec.out" 2>"$TMP/exec.err" ||
    err "could not run 'docker compose exec -T nzbd /nzbd security-headers' in $DEPLOY_DIR (is nzbd running?): $(head -n 1 "$TMP/exec.err" | clean)"
  clean <"$TMP/exec.out" >"$TMP/expected"
fi
grep -Eq '^[A-Za-z][A-Za-z0-9-]*: .' "$TMP/expected" || err "the reference list is empty or malformed."

# ---- response ----------------------------------------------------------------------------------------
if [ -n "$FROM_FILE" ]; then
  [ -f "$FROM_FILE" ] || err "no such file: $FROM_FILE"
  clean <"$FROM_FILE" >"$TMP/response"
else
  command -v curl >/dev/null 2>&1 || err "curl not found."
  set -- -sS -D "$TMP/raw" -o /dev/null --max-time 15 --proto =https --proto-redir =https --max-redirs 0
  [ -z "$USER_NAME" ] || set -- "$@" -u "$USER_NAME"
  curl "$@" "$BASE/login" || err "could not fetch $BASE/login (DNS, TLS certificate, or the proxy does not route it?)."
  clean <"$TMP/raw" >"$TMP/response"
fi

# ---- compare -----------------------------------------------------------------------------------------
# One awk program for the whole comparison: the last header block of the response wins (curl prints every block,
# e.g. after a 100 Continue). Repeated headers are joined with ", " like an HTTP list.
awk -v url="$BASE/login" -v user="$USER_NAME" '
  function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
  FNR == NR {
    i = index($0, ":"); if (i < 2) next
    n = substr($0, 1, i - 1); ln = tolower(n)
    if (!(ln in want)) { order[++ne] = ln; disp[ln] = n }
    want[ln] = trim(substr($0, i + 1))
    next
  }
  /^HTTP\// { split("", got); status = $2; next }
  {
    i = index($0, ":"); if (i < 2) next
    ln = tolower(substr($0, 1, i - 1)); v = trim(substr($0, i + 1))
    if (ln in got) got[ln] = got[ln] ", " v; else got[ln] = v
  }
  END {
    if (status == "") { print "audit-headers: no HTTP response read from " url > "/dev/stderr"; exit 2 }
    if (status == "401") {
      print "audit-headers: " url " answered 401: the proxy asks for its outer login, and its 401 page does not carry" > "/dev/stderr"
      print "nzbd'"'"'s headers. Re-run with --user NAME (curl then prompts for the password)." > "/dev/stderr"
      if (user != "") print "(--user was given: wrong password, or not the login this route expects.)" > "/dev/stderr"
      exit 2
    }
    if (status ~ /^3/) {
      print "audit-headers: " url " answered " status ", a redirect to " ("location" in got ? got["location"] : "?") > "/dev/stderr"
      print "(redirects are not followed: a forward-auth portal or another host is not nzbd). Audit the final nzbd URL." > "/dev/stderr"
      exit 2
    }
    if (status != "200") {
      print "audit-headers: " url " answered HTTP " status "; nzbd'"'"'s login page answers 200." > "/dev/stderr"
      exit 2
    }
    printf "Header audit of %s (HTTP %s)\n", url, status
    bad = 0; seen = 0
    for (k = 1; k <= ne; k++) {
      ln = order[k]
      if (!(ln in got)) { printf "MISSING  %s\n           nzbd sets: %s\n", disp[ln], want[ln]; bad++; continue }
      seen++
      if (tolower(got[ln]) == tolower(want[ln])) { printf "OK       %s\n", disp[ln]; continue }
      printf "CHANGED  %s\n           nzbd sets: %s\n           received:  %s\n", disp[ln], want[ln], got[ln]; bad++
    }
    h = "strict-transport-security"
    if (!(h in got)) { print "MISSING  Strict-Transport-Security (set it at the proxy, max-age >= 15552000)"; bad++ }
    else {
      v = tolower(got[h]); age = -1
      if (match(v, /max-age="?[0-9]+/)) { a = substr(v, RSTART, RLENGTH); gsub(/[^0-9]/, "", a); age = a + 0 }
      if (age >= 15552000) printf "OK       Strict-Transport-Security (%s)\n", got[h]
      else { printf "WEAK     Strict-Transport-Security (%s): use max-age >= 15552000 (180 days)\n", got[h]; bad++ }
    }
    if ("server" in got) printf "INFO     Server: %s (consider hiding it at the proxy)\n", got["server"]
    if ("x-powered-by" in got) printf "INFO     X-Powered-By: %s (consider removing it at the proxy)\n", got["x-powered-by"]
    if (seen == 0) print "NOTE     none of nzbd'"'"'s headers arrived: is this URL routed to nzbd at all?"
    if (bad == 0) { print "Result: all OK"; exit 0 }
    printf "Result: %d finding(s). A CHANGED header is your proxy'"'"'s decision, not an error of nzbd: keep it only if you\n", bad
    print "want it (docs/OPERATOR_SECURITY.md, \"Existing reverse proxy\")."
    exit 1
  }
' "$TMP/expected" "$TMP/response"
