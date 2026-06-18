# syntax=docker/dockerfile:1.7
#
# hort-server — v2 service binary image.
#
# Scope: the compose stack for development and E2E testing. Not the
# production image. Uses debian:bookworm-slim at
# runtime instead of distroless so `sh`/`ls` are available for live
# debugging during early E2E shake-out.

# ---------- Stage 1: builder ----------
FROM rust:1.94-bookworm AS builder

WORKDIR /src

# Copy the minimum needed for a workspace build. The top-level migrations/
# directory is needed because `sqlx::migrate!("../../migrations")` (in
# crates/hort-server/src/migrate.rs) embeds the SQL files at compile time;
# the COPY destination must match the macro path (resolves to /src/migrations).
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations

# `sqlx::migrate!` is a proc-macro that reads the filesystem at expansion
# time and emits `tracked_path!()` entries for each migration file it sees.
# Cargo re-runs the macro only when a tracked file changes; it does NOT
# detect newly-added migration files, because they weren't in the tracked
# set at the previous expansion. The Docker `COPY migrations`
# layer above invalidates correctly when migrations change, but inside
# the cached `/src/target` mount the compiled artifact for `migrate.rs`
# is still considered up-to-date, so the macro is never re-run and new
# migrations silently go missing from the embedded set.
#
# Touching `migrate.rs` (the only file that invokes `sqlx::migrate!`)
# gives it a newer mtime than its cached artifact, forcing cargo to
# recompile that crate and the proc-macro to re-scan the migrations
# directory. Cheap — no other code depends on mtime.
RUN touch crates/hort-server/src/migrate.rs

# Build release binary. No SQLX_OFFLINE needed — the postgres adapter uses
# runtime sqlx APIs, not compile-time `query!` macros. cargo-chef could
# speed incremental rebuilds; punt that until build time becomes a
# bottleneck.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --bin hort-server && \
    cp target/release/hort-server /usr/local/bin/hort-server

# ---------- Stage 2: runtime ----------
FROM debian:bookworm-slim AS runtime

# Runtime deps: CA roots for outbound TLS (upstream fetch), nothing else.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Non-root user + CAS root dir. UID/GID 65532 matches the
# `gcr.io/distroless/*:nonroot` convention, which the v2 worker image
# (docker/Dockerfile.worker, distroless/cc:nonroot) also uses. Aligning
# the two images lets them share the `cas` named volume without an
# EACCES on cross-image writes — the worker's
# `ScanOrchestrationUseCase::record_outcome` writes per-finding blobs
# back to the same CAS the server reads from.
RUN groupadd --system --gid 65532 hort && \
    useradd --system --uid 65532 --gid 65532 --home-dir /var/lib/hort-server \
            --no-create-home --shell /usr/sbin/nologin hort && \
    mkdir -p /var/lib/hort-server/cas && \
    chown -R 65532:65532 /var/lib/hort-server

COPY --from=builder /usr/local/bin/hort-server /usr/local/bin/hort-server

USER 65532
WORKDIR /var/lib/hort-server

EXPOSE 8080 9090

ENTRYPOINT ["/usr/local/bin/hort-server"]
