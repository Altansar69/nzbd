# Install nzbd in production

From a bare Docker host to a running, secured instance. About 30 minutes. The guided way is [QUICK_INSTALL.md](QUICK_INSTALL.md) (`deploy/install.sh` does steps 1-8 below interactively, and can use your existing Traefik/nginx/Caddy instead of the bundled proxy). Upgrading an existing install: [RUNBOOK.md](RUNBOOK.md) section 5.

**nzbd 3 starts a new library.** It does not upgrade a 2.x (or older) database: such a file is refused
(`LEGACY_DATABASE`) and never modified. Install v3 into a **new data directory**; to bring NZB files over, copy them into
the new watch folder or use `nzbd import <dir>` ([RUNBOOK.md](RUNBOOK.md) section 5, "Refill a new library"). The installer detects a
2.x install next to it and never reuses its data directory.

**Choose the database once** (it cannot be switched later in 0.5):

| | SQLite (default) | PostgreSQL |
|---|---|---|
| Containers | `nzbd` + `proxy` | `nzbd` + `proxy` + `postgres` (+ the one-shot `dbsecrets` and `setup`) |
| Database | the file `data/nzbd.sqlite` | a PostgreSQL 18 cluster in the Docker volume `nzbd_pg_data`, no network, reached through a socket |
| Fits | a personal or family library, ~1M releases | the same scale; a **shared or internet-facing** install: the database also binds a compromised nzbd (it cannot rewrite the audit history or delete accounts), which SQLite cannot do ([OPERATOR_SECURITY.md](OPERATOR_SECURITY.md) "Choosing a backend") |
| Host | 2 cores, 4 GB RAM, SSD | 2-4 cores, 8 GB RAM, SSD |

The production stack (templates in `deploy/compose-example/`, rendered into `deploy/compose.yaml`): `nzbd` (non-root: the UID:GID you choose, `NZBD_UID`/`NZBD_GID`, read-only rootfs, all
capabilities dropped, internal network without egress, nothing published), `proxy` (Caddy: TLS with its own internal
CA, Basic auth in front of everything, the only published port) and, with PostgreSQL, `postgres` (non-root uid 999,
read-only rootfs, all capabilities dropped, **no network at all**, nothing published; details and the rules that keep it safe:
[OPERATOR_SECURITY.md](OPERATOR_SECURITY.md#choosing-a-backend) "Choosing a backend").

## 1. Prerequisites

- A Linux host (or Docker Desktop on macOS/Windows) with a current Docker Engine and Docker Compose v2 (`docker compose`),
  and git. The images are built locally from this repository (about 5-10 minutes the first time; needs internet for
  base images and crates.io during the build only; the running stack needs none).
- See the table above (container limits: `nzbd` 2 GiB, `postgres` 2 GiB, proxy 256 MiB; the limits are ceilings, not
  reservations). Disk: the NZB library plus about 5 GB (SQLite) or 8 GB (PostgreSQL) for database and search index at
  ~1M releases, plus backups (the app refuses uploads below 1 GiB / 5 % free).
- A host name that your browsers resolve to the host (LAN DNS or a `hosts` entry), for example `nzbd.lan`.
- The LAN IP of the host if other machines should reach it (the stack binds to `127.0.0.1` by default).

## 2. Clone and configure the proxy

```
git clone <this repository> nzbd && cd nzbd/deploy
cp .env.example .env && chmod 600 .env       # it will hold the bcrypt hash of the proxy password
```

Edit `deploy/.env`:

| Variable | Meaning | Default |
|---|---|---|
| `NZBD_SITE` | Host name browsers use, lowercase, no port. Also becomes `server.allowed_hosts` and the TLS certificate name. | `nzbd.lan` |
| `NZBD_PROXY_USER` | Proxy Basic-auth user (the ".htaccess" layer). | `admin` |
| `NZBD_PROXY_HASH` | bcrypt hash of the proxy password, **single-quoted** (it contains `$`). | none (required) |
| `NZBD_BIND` | Host address to publish on. Use the LAN IP of this host; never `0.0.0.0` on a host that faces the internet. | `127.0.0.1` |
| `NZBD_HTTPS_PORT` | Published HTTPS port. | `443` |
| `NZBD_DATA_DIR` | Host directory with the library, search index and (SQLite) database (bind mount). A **new** directory for v3: never the data directory of a 2.x install. | `deploy/data` (set an **absolute** path here: the template lives in `deploy/compose-example/`) |
| `NZBD_DB_BACKEND` | `sqlite` or `postgres`; chosen once, never switched for an existing library. | `sqlite` |
| `NZBD_NAME_PREFIX` | Optional prefix of the named volumes and long-running containers (`<prefix>_secrets`, `<prefix>`, `<prefix>-proxy`, `<prefix>-db`); lowercase letters, digits, `_`, `-`. Only for a second stack on one host. | `nzbd` |
| `NZBD_UID`, `NZBD_GID` | The numeric user and group nzbd runs as (`nzbd`, `keygen`, `setup`); the data directory and the key volumes belong to it. Use a dedicated account (`id -u`, `id -g` of it) to manage `data/` without sudo; do not share the ids of other containers (media apps often run as 1000:1000). 1 to 2147483646; not 0 (root), 999 (PostgreSQL's superuser by peer authentication), 65532 (the proxy) or 65534 (nobody). With rootless Docker or userns-remap use `10001:10001` (a container UID is not your host account there). Choose it for a fresh install: existing key volumes of another user are refused, never re-owned. | required (the installer proposes your own IDs) |
| `NZBD_PROXY_IP`, `NZBD_BACK_SUBNET`, `NZBD_BACK_RANGE` | Fixed proxy address and subnet of the internal network; change only if `172.30.0.0/24` collides with another Docker network. `NZBD_PROXY_IP` must be inside the subnet and outside the range. | `172.30.0.2`, `172.30.0.0/24`, `172.30.0.128/25` |

Do not put `NZBD_IMAGE` / `NZBD_PROXY_IMAGE` in `.env` (the stack runs the images built from this tree, `nzbd:local` and
`nzbd-proxy:local`; the installer refuses any other value and ignores them in your shell).

Generate the proxy password and its hash. Use a long random password (20+ characters): the proxy does not rate-limit
failed attempts and each bcrypt check costs about a CPU-second.

```
openssl rand -base64 24                                                  # the password; store it in your password manager
docker run --rm -it --network none caddy:2 caddy hash-password      # type it twice (no echo); prints $2a$14$...
```

Paste the hash single-quoted into `.env`. (Avoid `--plaintext 'THE-PASSWORD'`: it leaves the password in your shell
history and in the process list.)

Create your settings file (mounted read-only into the container; edit it on the host later, see
[CONFIGURATION.md](CONFIGURATION.md)): `cp config/example.toml config/nzbd.toml && chmod 644 config/nzbd.toml`.

Render the compose file you will run. The shipped files in `compose-example/` are templates; this resolves them with
`.env` into one self-contained `deploy/compose.yaml` (re-run it after every `.env` change; `./install.sh` does the same):

```
# SQLite:
(umask 077 && env -u NZBD_IMAGE -u NZBD_PROXY_IMAGE docker compose --env-file .env -f compose-example/compose.yaml --profile setup config > compose.yaml)
# PostgreSQL: add the overlay after the first -f
(umask 077 && env -u NZBD_IMAGE -u NZBD_PROXY_IMAGE docker compose --env-file .env -f compose-example/compose.yaml -f compose-example/compose.postgres.yaml --profile setup config > compose.yaml)
```

(`umask 077` creates the file 0600 from the start: with the bundled proxy it holds the password hash. Keep
`NZBD_DATA_DIR` absolute: a relative value is resolved against `compose-example/`, not `deploy/`.)

(With your own reverse proxy add `-f compose-example/compose.external-proxy.yaml` after the other `-f`s; the installer
also generates the shared-network part for you, see [QUICK_INSTALL.md](QUICK_INSTALL.md) and
[OPERATOR_SECURITY.md](OPERATOR_SECURITY.md) "Existing reverse proxy". Afterwards check what your proxy does to nzbd's
security headers with `./audit-headers.sh https://<site> [--user <outer login>]`.)

## 3. Create the data directories (once)

The app validates its directories and does not create them. They must exist and be owned by `NZBD_UID:NZBD_GID` from
`.env` (in `deploy/`: `IDS="$(sed -n 's/^NZBD_UID=//p' .env):$(sed -n 's/^NZBD_GID=//p' .env)"`):

```
mkdir -p data/watch data/store data/failed data/duplicates data/tmp data/backups
docker run --rm -u 0 --network none -e IDS="$IDS" -v "$PWD/data:/d" --entrypoint sh caddy:2 -c 'chown -hR "$IDS" /d && chmod -R u=rwX,go= /d'
```

(On a Linux host without Docker Desktop, `sudo chown -hR "$IDS" data && chmod -R u=rwX,go= data` does the same.
Afterwards only that user can read `data/` on Linux: with your own IDs you add NZBs with a plain `cp`; with the image
user `10001:10001`, through the UI or API, or with `sudo -u '#10001' cp`.)

Then hand the new key volumes to the same user (once, before step 4; it refuses volumes holding files of another user
and never re-owns or deletes anything):

```
docker compose --profile setup run --rm volperms
```

## 4. Generate the TOTP encryption key (once)

```
docker compose --profile setup run --rm keygen
```

This builds the `nzbd` image if needed and writes `/run/secrets/nzbd_totp_key` (mode 0400, owned by `NZBD_UID`) into the Docker
volume `nzbd_secrets`. It refuses to overwrite an existing key. **Back this key up now, separately from the database**
(see [RUNBOOK §Backups](RUNBOOK.md)): without it nobody can finish an MFA login and you must reset MFA.

Recommended: a **backup encryption key** too (`nzbd backup` then writes only encrypted files), in the same volume:

```
docker compose --profile setup run --rm keygen keygen --out /run/secrets/nzbd_backup_key   # 0400, NZBD_UID
```

and in `config/nzbd.toml`: under `[maintenance]`, `backup_encryption_key_file = "/run/secrets/nzbd_backup_key"`
(RUNBOOK section 2; back this key up separately as well).

## 4b. PostgreSQL only: database passwords, server and schema (once)

```
docker compose --profile setup run --rm dbsecrets   # three random passwords, never printed; keeps existing ones
docker compose up -d postgres                       # first start initializes the cluster (roles, schema)
docker compose ps postgres                          # wait for "healthy"
docker compose --profile setup run --rm setup       # nzbd db migrate --yes, with the owner role
```

`dbsecrets` writes the app role's password into `nzbd_secrets` (read by nzbd), the owner role's password into
`nzbd_setup_secrets` (mounted **only** into the one-shot `setup` service) and the server's copies into
`nzbd_pg_secrets`. `setup` applies the schema; `nzbd serve` never migrates and refuses to start until it is done
(`MIGRATIONS_PENDING`). Run `setup` again after every upgrade, with `nzbd` stopped (RUNBOOK section 5; `setup` refuses
while nzbd is connected: `APP_SESSIONS_ACTIVE`).

## 5. Start

```
docker compose up -d
docker compose ps          # nzbd should report "healthy" after the first health probe (about a minute)
```

## 6. Trust the proxy's internal CA

Caddy issues the certificate for `NZBD_SITE` from its own CA. Fetch the root certificate and install it on the devices
you browse from (the root's private key stays in the `nzbd_caddy` volume; install the root only where needed):

```
docker run --rm -v nzbd_caddy:/d:ro --entrypoint cat caddy:2 /d/caddy/pki/authorities/local/root.crt > nzbd-root.crt
```

Install `nzbd-root.crt` as a trusted root with the usual OS procedure (macOS Keychain Access: System keychain, set
"Always Trust"; Debian/Ubuntu: copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates`; Windows:
import into "Trusted Root Certification Authorities"; Firefox has its own store). Make sure `NZBD_SITE` resolves to
`NZBD_BIND` on every device. Browse to `https://<NZBD_SITE>/` (add `:<port>` if `NZBD_HTTPS_PORT` is not 443).
`curl --cacert nzbd-root.crt --resolve nzbd.lan:443:<host-ip> ...` works without installing anything.

## 7. Create the user and enroll MFA

`nzbd` must be running. The CLI lives at `/nzbd` inside the container and runs as the container user (never use `-u 0`:
the database must stay owned by `NZBD_UID`):

```
docker compose exec -it nzbd /nzbd user create <username>
```

It prompts for the password twice (12-256 characters, no echo; passwords are never accepted on the command line or in the
environment) and prints a one-time **enrollment token** (valid 24 hours, shown once). Then:

1. Open `https://<NZBD_SITE>/`. The browser asks for the proxy credentials (`NZBD_PROXY_USER` / the proxy password).
2. Sign in to nzbd with the username and password.
3. The enrollment page asks for the token. Paste it. It shows a QR code and the secret key: scan it with an
   authenticator app (any TOTP app: SHA-1, 6 digits, 30 s).
4. Enter the current 6-digit code. nzbd shows **10 recovery codes once**: store them in a password manager.
5. You are in. From now on login is password + 6-digit code (or one recovery code, single use).

Token expired or lost before enrolling: `docker compose exec -it nzbd /nzbd user enroll-token`. Password lost or you
are locked out: `... user reset-password`. Authenticator lost and recovery codes gone: `... user reset-mfa` (prints a
new token). See [RUNBOOK.md](RUNBOOK.md).

## 8. Feed it NZBs

- **Watch folder**: put `.nzb` files into `deploy/data/watch/`. Write them under a hidden or `.part`/`.tmp` name and
  rename when complete, or just copy: a file is only picked up after its size and mtime stay unchanged for 5 s. Indexed
  files are moved into `store/`; the original name is kept as the display name.
- **UI**: `https://<NZBD_SITE>/upload` (several files, optional category and source label).
- **API**: create a key (Account page, or `docker compose exec -it nzbd /nzbd apikey create "label"`; it is shown once),
  then, from any LAN client (the proxy credentials are needed too):

  ```
  curl --cacert nzbd-root.crt -u "$NZBD_PROXY_USER:$PROXY_PW" \
       -H "X-Api-Key: $KEY" -H "Content-Type: application/x-nzb" \
       --data-binary @file.nzb https://nzbd.lan/api/v1/nzb
  ```

  Answers `201 {"status":"created","id":..,"sha256":..}` or `200 {"status":"duplicate",...}`. Optional headers:
  `X-Category` (a slug from `nzbd categories`), `X-Source` (label), `X-Source-Name` (display name).

## 9. Check health

- Web: **Health** in the sidebar (`/admin/health`) shows OK / WARN / FAIL per check; **Admin** shows the ingest log and
  counters.
- CLI: `docker compose exec nzbd /nzbd health` prints the same table; exit code 0 = all OK, 1 = warnings, 2 = failures.
  Directly after a fresh install it warns that no backup exists yet; the in-process scheduler writes the first one
  60 seconds after start (or run `docker compose exec nzbd /nzbd backup` once yourself).
- The container `HEALTHCHECK` runs `nzbd healthcheck` (a loopback probe of `/healthz`; the proxy answers 404 to
  `/healthz` from outside on purpose).

## 10. What is stored where (volumes and mounts)

Everything nzbd keeps lives in a few named Docker volumes and one host directory. The volumes have short, fixed names
(`<prefix>_secrets`, `<prefix>_state`, ...), not Compose's project-prefixed ones. The prefix is `nzbd` unless you set
`NZBD_NAME_PREFIX` in `deploy/.env` (for example `NZBD_NAME_PREFIX=nzbd2 ./install.sh` for a second, separate stack on
one host); the tables below use the default. The long-running containers are named the same way: `nzbd` (the app),
`nzbd-proxy` and, with PostgreSQL, `nzbd-db`.

**Host directory (bind mount).** `data/` (path set by `NZBD_DATA_DIR`, default `deploy/../data`), owned by
`NZBD_UID:NZBD_GID`, mode 0700 or 0750. This is where the library lives:

| Path in `data/` | Holds | Back it up? |
|---|---|---|
| `store/` | Your NZB files, named by SHA-256, never changed after writing | **Yes**: the only copy of your library |
| `nzbd.sqlite` (+ `-wal`, `-shm`) | The database, SQLite backend only | Use `nzbd backup`, not a raw file copy |
| `backups/` | Snapshots written by the scheduler and by `nzbd backup` | Copy them **off the host** |
| `index/` | The search index, rebuilt from the database | No |
| `watch/` | The input folder you drop `.nzb` files into | No (files are moved out after indexing) |
| `failed/`, `duplicates/`, `tmp/` | Rejected files, duplicate copies, upload staging | No |

**Named volumes, SQLite install** (the default):

| Volume | Mounted in | Holds | Back it up? |
|---|---|---|---|
| `nzbd_secrets` | `nzbd` (read-only) | The TOTP encryption key `nzbd_totp_key` and the optional backup encryption key | **Yes, separately from everything else and offline.** Without the TOTP key nobody can log in; without the backup key encrypted backups cannot be read |
| `nzbd_state` | `nzbd` | `serve.lock` and `db-anchor.json` (the restore anchor), mode 0700 | Only as part of a full snapshot, see the [runbook](RUNBOOK.md) |
| `nzbd_caddy` | `proxy` | The proxy's internal CA and certificates | Optional. If lost, a new CA is made and every device must trust the new root |

**Extra volumes, PostgreSQL install:**

| Volume | Holds | Back it up? |
|---|---|---|
| `nzbd_pg_data` | The PostgreSQL cluster (the database) | Use `nzbd backup` (a consistent snapshot export) |
| `nzbd_pg_socket` | The Unix socket between nzbd and PostgreSQL (there is no network port) | No |
| `nzbd_pg_secrets` | The server's copy of the generated database passwords | Keep the volume; not needed in backups |
| `nzbd_setup_secrets` | The database owner password, mounted only into the one-shot `setup` service | Keep the volume; not needed in backups |

Also mounted read-only from the host: `deploy/config/nzbd.toml` (your settings, no secrets) and `deploy/Caddyfile`.
The proxy credentials are in `deploy/.env`: keep that file private and in your password manager.

**Do not delete the secrets volumes.** `docker compose down` keeps all volumes and is safe. `docker compose down -v` and
`docker volume rm nzbd_secrets` delete the key for good. What to back up, how often and how to restore:
[RUNBOOK.md](RUNBOOK.md) (section 2, "Backups and restore").

**Disk space.** Plan for your NZB library in `data/store/`, the database and the search index, and the snapshots in
`backups/` (`maintenance.keep_backups`, default 14). Keep `backups/` on a different disk than the library if you can.

Next: plan the off-host backup copy and read the day-2 guide: [RUNBOOK.md](RUNBOOK.md).
