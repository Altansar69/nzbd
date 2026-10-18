# Contributing

Thanks for your interest in nzbd. Bug reports, ideas and pull requests are welcome.

## Before you start

- Open an **issue** first for anything bigger than a small fix, so we agree on the direction.
- Security problems: do not open a public issue, see [SECURITY.md](SECURITY.md).
- By contributing you agree that your work is released under the [MIT licence](LICENSE).

## Ground rules (they keep the project safe and simple)

- **Zero outbound network connections.** No HTTP client, DNS lookup, telemetry, update check or CDN asset.
- **All input is hostile**: NZB contents, HTTP requests and file names are display data only, never paths, SQL, shell
  arguments or unescaped HTML.
- SQL is always parameterized. Secrets (passwords, TOTP keys, session ids, API keys) never appear in logs, errors or URLs.
- Rust only, `#![forbid(unsafe_code)]`, no `unwrap()`/`expect()`/`panic!` in non-test code.
- Prefer boring, explicit code. A new dependency needs a clear reason.

## Building

The application is built into Docker images by [deploy/Dockerfile](deploy/Dockerfile) (app) and
[deploy/Dockerfile.proxy](deploy/Dockerfile.proxy) (proxy); see [docs/QUICK_INSTALL.md](docs/QUICK_INSTALL.md).

```
docker build -f deploy/Dockerfile -t nzbd .
```

The full development and test environment (CI gates, fuzzing, browser checks) lives in a separate development
tree. Pull requests are reviewed here and may be re-applied there; you will stay credited as the author.
