# How nzbd works

The short version, for humans.

nzbd is a small, self-contained web application: one static Rust binary, one SQLite database, one blob store and
a TLS/Basic-auth proxy in front. It **never talks to Usenet and never makes an outbound connection**; it only knows
the `.nzb` files you hand it.

```
 your .nzb files
   |  watch folder (move a file in)   UI upload form   POST /api/v1/nzb (API key)
   v
 ingest queue --> hardened streaming XML parser (size, depth and time limits, no entities, no DOCTYPE tricks)
   |                  |
   |                  +-- bad input --> failed/ (+ reason.json), duplicates --> duplicates/
   v
 analyze: title, files, segments, missing ranges, par2/obfuscation flags, Scene name -> category
   |
   +--> blob store (files, or zstd rows in SQLite)   +--> SQLite: release, files, full-text index, audit log
                                                              |
 browser --> proxy (HTTPS + Basic auth) --> login + TOTP --> index, search, release page, explorer, download
```

- **Two gates, one or several accounts.** The proxy's Basic-auth layer covers every path; the app then requires a
  password and a mandatory TOTP code. By default there is exactly one account (an administrator). With
  `security.multi_user = true` an administrator can invite uploaders (read, download and add) and viewers (read and download) to the
  same library; every account has its own password and authenticator, and what each did is attributed. There is no
  public registration and no read API.
- **Everything in an NZB is hostile display data.** Subjects, names, posters and message-ids are sanitized, escaped on
  output and never used as paths, SQL or shell arguments.
- **Nothing is deleted behind your back.** Ingested files are *moved*, failures are quarantined, and removal is an
  explicit, re-authenticated action (Delete release, Admin > Cleanup).
- **Crash safe.** Blob first (tmp + fsync + rename), database transaction second, source removal last; startup recovery
  re-does whatever a crash interrupted.
- **Small and boring.** Rust crates `nzb-core` (pure parsing and classification), `nzb-store` (SQLite + blobs),
  `nzb-ingest` (watch folder and pipeline), `nzb-web` (axum UI and API) and the `nzbd` binary. Layout and data flow:
