# Security policy

nzbd is a login-protected server that handles files from untrusted sources, so security reports are welcome and taken
seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately, either way:

- GitHub: the repository's **Security** tab, then **Report a vulnerability** (private vulnerability reporting).
- Email: Zangetsu_Shinigami@protonmail.com

Please include the version (`nzbd --version`), what you did, what you expected and what happened, and a minimal way to
reproduce it. Do not include real passwords, TOTP secrets or API keys.

You can expect an acknowledgement within about a week. This is a hobby project maintained by one person, so there is
no guaranteed fix time, but confirmed vulnerabilities are fixed as a priority and credited in the changelog if you
want to be named.

## Supported versions

Only the latest release receives fixes.

## Scope and honest limits

- The security design and what protects the server are described in [docs/OPERATOR_SECURITY.md](docs/OPERATOR_SECURITY.md).
- nzbd is meant for one person or a small invited group on a trusted LAN. It is **not** meant to be exposed directly
  to the public internet.
- The code was written with an AI assistant (Claude) and reviewed by AI-assisted security reviews and automated tests.
  **There has been no independent human security audit.** Treat it accordingly.
