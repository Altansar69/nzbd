# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Production image for nzbd (docs/DEPLOYMENT.md). Build context is the repo root:
#   docker build -f deploy/Dockerfile -t nzbd:local .
#   scripts/dev release-image        # multi-arch (linux/amd64, linux/arm64)
#
# Base images are pinned by digest (multi-arch index digests). To bump: `docker pull <tag>`,
# read `docker inspect --format '{{index .RepoDigests 0}}' <tag>`, update here and in
# dev/Dockerfile (rust version must match rust-toolchain.toml).

# ---- builder: static musl binary, bundled SQLite --------------------------------------------
FROM rust:1.99.0-slim-bookworm@sha256:2c3a22f0a5533ea2dd5a16627bc841228151faa2d4de2644ac9987e4a2f1f2fa AS builder
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    CARGO_PROFILE_RELEASE_STRIP=symbols \
    CARGO_PROFILE_RELEASE_DEBUG=false \
    CARGO_TERM_COLOR=never
# gcc + musl-tools: libsqlite3-sys (bundled) compiles C with musl-gcc. Native build per platform
# (under emulation when cross-building), so musl-gcc always matches the target arch.
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev musl-tools \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) t=x86_64-unknown-linux-musl ;; \
      arm64) t=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    echo "$t" > /target; rustup target add "$t"
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    set -eu; t=$(cat /target); u=$(echo "$t" | tr - _); \
    export CC=musl-gcc "CC_$u=musl-gcc"; \
    cargo build --locked --release -p nzbd --target "$t"; \
    install -D "target/$t/release/nzbd" /out/nzbd; \
    install -d -o 10001 -g 10001 -m 0750 /out/data; \
    install -d -m 1777 /out/tmp; \
    install -d -m 0755 /out/rundir; \
    install -d -o 10001 -g 10001 -m 0700 /out/run/secrets; \
    install -d -o 10001 -g 10001 -m 0700 /out/state

# ---- runtime: scratch + the user database of distroless static, non-root ---------------------
# The distroless image sets ENV SSL_CERT_FILE (and ships a CA bundle). nzbd links no TLS stack and opens no outbound
# connection, and with db.backend = "postgres" it refuses to start while SSL_CERT_FILE/SSL_CERT_DIR or any libpq PG*
# variable is set (SEC-086, review 30 M5). A Dockerfile cannot unset an inherited ENV, so the runtime stage is
# `scratch`: only the static binary, /etc/passwd and /etc/group from the digest-pinned distroless image, and our dirs.
FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS base
FROM scratch
COPY --from=base /etc/passwd /etc/group /etc/
COPY --from=builder /out/nzbd /nzbd
# /data is owned by the runtime uid so a fresh named volume mounted there is writable.
COPY --from=builder --chown=10001:10001 /out/data /data
COPY --from=builder /out/tmp /tmp
# /run itself: root, 0755. Without this line the COPY below would create it with the --chown/--chmod of
# /run/secrets (10001, 0700), and any other container user (T128: NZBD_UID) could not reach /run/secrets,
# /run/postgresql or /run/setup-secrets mounted under it.
COPY --from=builder /out/rundir /run
# Mount point of the nzbd_secrets volume; owned by the runtime uid so `keygen` can write the key.
COPY --from=builder --chown=10001:10001 --chmod=0700 /out/run/secrets /run/secrets
# Mount point of the nzbd_state volume (paths.state: serve.lock, db-anchor.json): its own volume, so a snapshot of the
# data directory does not also roll back the restore anchor (review 34 M3). 0700, owned by the runtime uid.
COPY --from=builder --chown=10001:10001 --chmod=0700 /out/state /state
USER 10001:10001
WORKDIR /data
# Everything else comes from NZBD__section__key env vars (no config file required).
ENV NZBD__server__listen=0.0.0.0:8080
EXPOSE 8080
# start-period covers the startup check and the first index build of a large library.
# Loopback probe of GET /healthz; no curl/shell in the image, no outbound traffic.
HEALTHCHECK --interval=30s --timeout=5s --start-period=600s --retries=3 CMD ["/nzbd", "healthcheck"]
ENTRYPOINT ["/nzbd"]
CMD ["serve"]
