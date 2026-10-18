# Quick install

Five steps, about 15 minutes (most of it is the first image build). The installer asks a few questions and does the
rest. If you prefer to do it by hand, or something goes wrong, the full manual procedure is in [INSTALL.md](INSTALL.md).

## You need

- A Linux host, or Docker Desktop on macOS/Windows, with **Docker Engine and Docker Compose v2**. Nothing else.
- 2 cores and 4 GB of RAM (SQLite) or 8 GB (PostgreSQL), an SSD, and disk space for your NZB library plus about
  5-8 GB for the database and search index at a million releases.

**nzbd 3 is a fresh start.** It does not upgrade a 2.x library: if the installer finds a 2.x install next to it, it
explains this, saves the old `.env`, asks the questions again and uses a **new** data directory (default `./data-v3`);
the 2.x data directory is never touched. Bring your NZB files over afterwards by copying them into the new watch folder
(or with `nzbd import <dir>`, [RUNBOOK.md](RUNBOOK.md) section 5, "Refill a new library").
- A host name your browsers can resolve to this machine (`nzbd.lan` in LAN DNS or a `hosts` entry).

## Steps

**1. Get the files.** Unzip the production bundle (or clone the repository) and go to the `deploy` directory.

```
unzip nzbd-0.5.0-production.zip && cd nzbd-0.5.0/deploy
```

**2. Run the installer.**

```
./install.sh
```

It first asks **what the run should do**: `1` generate the configuration and deploy (default), or `2` only generate
the configuration (`.env` and `compose.yaml`), validate it with `docker compose config`, print it and stop. A generate-only run creates no network, data directory, image, key or container. To deploy it later,
re-run `./install.sh`, answer `1` and keep the existing `.env`.

Then it asks for the host name, then **whether you already run a reverse proxy** (Traefik, nginx, Caddy ... in Docker,
yes/no); the installer lists the proxy-like containers it finds and proposes "yes" when it found one. Then it depends on
your answer:

| Your answer | What the installer does | It also asks |
|---|---|---|
| **No: install the bundled proxy** | Builds and starts the bundled Caddy (HTTPS with its own CA + a login in front of nzbd). | Proxy login name, address to publish on (your LAN IP, or `127.0.0.1` for this machine only), HTTPS port, and a proxy password (it can generate a strong one and shows it once). |
| **Yes: use my existing proxy** | Does **not** start the bundled proxy. You choose how your proxy reaches nzbd (below). For **Traefik** it also generates the router labels (host, entrypoint, TLS options, certificate resolver, middlewares) so nzbd is ready to be routed; the suggested values are the ones your running containers already use (e.g. entrypoint `https`, `tls.options=default`, `security-headers@file`). It then offers an **outer login** (basic auth, like an .htaccess): reuse an auth middleware you already have (e.g. `myAuth`) or create a dedicated `nzbd-auth` login (generated password shown once, only its bcrypt hash is stored). Basic auth is applied first, then your other middlewares. Upload API clients must then send the basic-auth credentials as well. Declining the outer login is possible but warned (nzbd then faces whoever reaches the proxy with its own login only). Note: a Traefik `headers` middleware *sets* every header it defines and so replaces nzbd's stricter value (`Content-Security-Policy`, `Referrer-Policy`, `X-Frame-Options`, `Permissions-Policy`, ...); the installer warns about it and, at the end, offers the **header audit** (`./audit-headers.sh`, below) that shows exactly what changed. For nginx or Caddy it prints a ready snippet. | Which proxy container, and the network choice. |

How your proxy reaches nzbd (existing proxy only):

| Choice | Meaning |
|---|---|
| **1. Create a new network** (recommended) | The installer creates an *internal* Docker network (default name `nzbd_proxy`, a free private `/24`). nzbd joins it, and you add it as an `external` network in your proxy's compose file. The installer prints the snippet, including the fixed address your proxy gets (nzbd trusts forwarded headers only from that address). Only your proxy and nzbd are on it and nzbd keeps no internet access: **the strongest isolation**. If you type the name of a network that already exists, nzbd joins it as it is; when it is not internal you get the same warning and question as for choice 2. |
| **2. Attach to an existing network** (proposed when your proxy is already on a user network) | You pick a network your proxy compose already defines (each is listed with its subnet; the ones your proxy is attached to come first, marked `*`). nzbd joins it. If that network is not internal the installer warns, and asks you to confirm (default no), that **every other container on it can reach nzbd without your proxy's outer login** (nzbd's own password + TOTP still apply) and that nzbd gets a route to the internet there (nzbd itself opens no outbound connection). This is an accepted, opt-in exception ([OPERATOR_SECURITY.md](OPERATOR_SECURITY.md), "Existing reverse proxy"). |
| **3. Join your proxy to nzbd's private network** | Quick, nothing to edit: your running proxy container is attached to `nzbd_back` now. Not persistent: add the printed snippet to your proxy's compose file. |

With choices 1 and 2 the installer then asks for **nzbd's static IP on that network**: it shows the subnet and the
addresses in use (gateway and running containers; stopped ones are not visible, check your own address plan), suggests
the first free one, and refuses an address outside the subnet or already taken. The answer is stored in `.env`
(`NZBD_PROXY_NET_IP`; delete the line and re-run to change it). With choices 1 and 2 nzbd is **only** on that network:
its private network `back` (used by the bundled proxy and by choice 3) is not created, and the network keeps its real
name in `compose.yaml`. The installer uses the Compose `!override` tag for this, so Docker Compose 2.24.4 or later is
required. Docker only accepts a fixed address on a network created with an explicit subnet (in your
proxy compose: `ipam: config: - subnet: ...`).

nzbd trusts `X-Forwarded-For` only from your proxy's address on that network (`NZBD_PROXY_TRUSTED_IP` in `.env`).
That address **must be static**: pin it with `ipv4_address` in your proxy's compose file (the installer prints the
snippet and warns when the current address is not pinned, or when you leave it blank). Otherwise nzbd sees every
client as the proxy, and the per-address limits and the login lock are shared by everybody.

With choices 1 and 2 the installer can also attach your *running* proxy container right away (until it is recreated;
the printed compose snippet makes it permanent). Everything it generates for this is in `deploy/compose.yaml`
and is rewritten from `.env` on every run.

Both ask for the data directory, then for the **container user** and the **database**. Press Enter to accept the
suggestion in brackets.

**Container user.** nzbd runs as an unprivileged numeric user (UID) and group (GID); the data directory and the key
volumes belong to it. The installer proposes **your own IDs** (the account running it; with `sudo ./install.sh`, the
account that called sudo), so you can read and add files in the data directory without sudo. Run as root, it proposes
the image's own user `10001:10001` instead. Press Enter to accept, or type another `UID:GID` (two numbers, e.g.
`1000:1000`); `0` (root), `999` (PostgreSQL's superuser by peer authentication), `65532` (the proxy), `65534`
(nobody), a single number, names and anything else are refused and asked again. Prefer a **dedicated account**: the
account owns the whole library, and media containers (SABnzbd, Sonarr ...) often run as `1000:1000`. With rootless
Docker or userns-remap the installer proposes `10001:10001` (a container UID is not your host account there). The answer is stored in
`.env` as `NZBD_UID` / `NZBD_GID` and shown in the summary. A kept `.env` without them is asked the same question.
Pick it for a **fresh install**: if key volumes of an earlier install with another user exist, the installer stops and
tells you how to start fresh; it never re-owns or deletes them.

| Database | What you get |
|---|---|
| **1. SQLite** (default) | One container, the database is a file in the data directory; nothing else to run. Right for a personal or family library. |
| **2. PostgreSQL** | Adds a hardened PostgreSQL 18 container (no network at all, reached through a socket, non-root, read-only), generates its passwords (never shown), and applies the schema with a one-shot `setup` service that alone holds the database owner's password. The more secure choice for a **shared or internet-facing** install: the database itself then refuses what a compromised nzbd process might try (rewriting the audit history, deleting accounts), which SQLite cannot ([OPERATOR_SECURITY.md](OPERATOR_SECURITY.md), "Choosing a backend"). |

The choice is final for that library: a re-run keeps it and refuses to switch (moving a SQLite library to PostgreSQL is
not supported in 0.5).

With an existing proxy you are responsible for HTTPS (and an outer login if you want one) there; nzbd always
requires its own password + TOTP. Details and the exact requirements are printed at the end of the install.

**The compose file.** The shipped compose files are templates in `deploy/compose-example/` (`compose.yaml`,
`compose.postgres.yaml` for PostgreSQL and `compose.external-proxy.yaml` for an existing proxy). The installer renders them with your `.env` and answers into one
self-contained `deploy/compose.yaml` (mode 0600, absolute paths), and every `docker compose ...` command in `deploy/`
uses it. Do not edit it: change `.env` (or re-run the installer) and it is rewritten. The images are always
`nzbd:local` and `nzbd-proxy:local`, built from this tree: `NZBD_IMAGE` / `NZBD_PROXY_IMAGE` in your shell are ignored
(with a warning) and refused in `.env`. A `compose.yaml` the installer did
not write is saved as `compose.yaml.bak.<date>` first; leftovers of older installers (`COMPOSE_FILE` in `.env`,
`compose.proxy-net.yaml`) are removed.

**Your settings file.** `deploy/config/nzbd.toml` is created once (all settings commented out, never overwritten) and
mounted read-only into the container. Edit it on the host and run `docker compose restart nzbd`; for example, to allow
several accounts with invitations, add `multi_user = true` under `[security]`. Every key is in
[CONFIGURATION.md](CONFIGURATION.md).

**3. Wait for the build.** The installer builds the two images, creates the encryption key (with PostgreSQL also the
database passwords, starts the database and applies the schema), starts the stack and waits until it is healthy. Only
the build needs internet; the running stack has no outbound network.

**4. Create your account.** At the end the installer asks for your nzbd user name and password and prints a one-time
**enrollment token**. Keep the terminal open until you have used it.

**5. Open nzbd.**

1. Bundled proxy only: install `nzbd-root.crt` (written next to `install.sh`) as a trusted root certificate on your
   device. With your own proxy, use your own certificate.
2. Browse to `https://<your host name>/` and enter the proxy login (bundled proxy).
3. Sign in with your nzbd user, paste the token, scan the QR code with an authenticator app, enter the 6-digit code and
   **save the 10 recovery codes**.
4. Drop `.nzb` files into `<data directory>/watch/`, or use the **Upload** page.

## Afterwards

- **Back up the encryption key** (Docker volume `nzbd_secrets`) separately from the database:
  [RUNBOOK.md](RUNBOOK.md), section 2. Without it nobody can finish an MFA login. Set a backup encryption key too
  (same section).
- Check health: `docker compose exec nzbd /nzbd health`.
- With your own proxy: **audit the security headers** it delivers, now and after every change of its middlewares:
  `./audit-headers.sh https://<your host name> [--user <outer login>]` (in `deploy/`; curl asks for the password). It
  compares the proxied login page with `nzbd security-headers` and prints `OK`, `CHANGED` (both values), `MISSING`, an
  HSTS verdict and `Server`/`X-Powered-By` leaks; exit 0 = all OK, 1 = findings, 2 = could not check. A `CHANGED`
  header is your decision, not an error of nzbd ([OPERATOR_SECURITY.md](OPERATOR_SECURITY.md)).
- Re-running `./install.sh` is safe: it keeps your `.env`, never overwrites a key or database password, never switches
  the database and deletes nothing. With PostgreSQL a re-run also applies new schema migrations (upgrades).
- Use it: [USER_GUIDE.md](USER_GUIDE.md). Operate it: [RUNBOOK.md](RUNBOOK.md).

## If something fails

| Symptom | What to do |
|---|---|
| "docker not found" / "daemon not reachable" | Install or start Docker; on Linux add your user to the `docker` group. |
| Build fails while downloading | The build needs internet once (base images, crates, Go modules). Check proxy/DNS and re-run. |
| `networks have overlapping IPv4` when starting | Another Docker network already uses `172.30.0.0/24`. The installer now picks a free range by itself and stores it in `.env` (`NZBD_BACK_SUBNET`, `NZBD_PROXY_IP`, `NZBD_BACK_RANGE`). If you hit this with an older installer: update `install.sh` and re-run it, keeping your `.env`. |
| "nzbd is 'unhealthy'" | `docker compose logs nzbd` prints the reason; see the runbook troubleshooting table. |
| `LEGACY_DATABASE` in the nzbd log | The data directory holds a 2.x (or older) database: v3 refuses it and leaves it untouched. Use a new data directory (re-run the installer, do not keep the `.env`). |
| PostgreSQL: `MIGRATIONS_PENDING` | The schema was not applied: `docker compose --profile setup run --rm setup`, then `docker compose up -d`. |
| PostgreSQL: "postgres is 'unhealthy'" | `docker compose logs postgres`. The first start initializes the cluster; it needs the passwords from `dbsecrets`. |
| Browser certificate warning | Install `nzbd-root.crt` and browse by the host name, not the IP. |
| Header audit says `answered 401` | Your proxy asks for its outer login first: add `--user <name>` (curl prompts for the password). |
| Existing proxy cannot reach nzbd | The proxy container must be on the Docker network `nzbd_back` (the installer attaches it; add the snippet it printed to your proxy's compose file so it survives a re-create), and forward to `http://nzbd:8080`. |
| `400 BAD_HOST` through your proxy | The proxy must forward the original `Host` header, and it must equal the host name you gave the installer. |
| "the key volumes are not owned by UID:GID" | Key volumes of an earlier install with another `NZBD_UID:NZBD_GID` exist. Put that UID:GID back into `.env`, or start fresh: back up what you need, `docker compose --profile setup down -v` (deletes the TOTP key and the database volumes; the data directory stays), re-run `./install.sh`. |
| Permission denied on the data directory from the host | It belongs to `NZBD_UID:NZBD_GID` (see `.env`). Use that account, or `sudo`. |
| Proxy password lost (bundled proxy) | Re-run `./install.sh`, keep nothing, enter a new password (the old `.env` is saved as `.env.bak.*`). |
