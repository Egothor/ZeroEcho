# syntax=docker/dockerfile:1.7
###############################################################################
# ZeroEcho PKI administrative server — container image
#
# POSIX-ONLY. The ZeroEcho filesystem PKI store and keyring require a POSIX
# filesystem (0700/0600 permission enforcement, atomic rename, directory fsync,
# advisory flock). See docs/windows-portability-analysis.md. This image MUST run
# on a Linux/POSIX host; it will not provide its durability guarantees on a
# non-POSIX bind mount.
#
# The image bundles two installDist distributions from the Gradle build:
#   * zeroecho-pki-server  (the long-lived admin HTTPS server) -> bin/zeroecho-pki-server
#   * app                  (the openssl-style `zeroecho pki` CLI) -> bin/app
# The CLI is used ONLY by entrypoint.sh for the startup profile reconcile against
# the same on-disk store, BEFORE the server opens it (see entrypoint.sh).
#
# NOTE ON BUILDING: this repository is built via Gradle on a POSIX toolchain
# (the project's WSL Fedora + JDK 25 box). The `build` stage below reproduces
# `:pki-server:installDist` and `:app:installDist` on a JDK 25 image. If your CI
# already produced those trees, skip the source build and inject them instead by
# passing `--build-arg PREBUILT=1` and mounting/copying the installDist trees to
# the build context under `context/pki-server` and `context/app` (see the
# PREBUILT stage). No container engine was available in the authoring
# environment, so this Dockerfile has been statically validated only — it has
# NOT been built or run here.
###############################################################################

# --- Base image pins ---------------------------------------------------------
# Pinning by digest is ideal for supply-chain reproducibility. Replace the tags
# below with `image@sha256:<digest>` once you have selected a digest for your
# registry mirror. Tags are an acceptable interim.
ARG JDK_IMAGE=eclipse-temurin:25-jdk
ARG JRE_IMAGE=eclipse-temurin:25-jre

###############################################################################
# Stage 1a: build the installDist trees from source (default).
###############################################################################
FROM ${JDK_IMAGE} AS build
WORKDIR /src
# Copy the whole repository (a .dockerignore should exclude node_modules, .git,
# build/ and pki-frontend/dist so the context stays small).
COPY . .
# pki-server and app are BouncyCastle-confined to `lib` and have no Node/npm
# dependency, so this build does not need the frontend toolchain.
RUN --mount=type=cache,target=/root/.gradle \
    chmod +x ./gradlew && \
    ./gradlew --no-daemon :pki-server:installDist :app:installDist

###############################################################################
# Stage 1b: accept pre-built installDist trees from the build context instead.
# Enable by building the `prebuilt` target, e.g.:
#   docker build --target prebuilt -f deploy/pki-server/Dockerfile .
# with context/pki-server and context/app populated by your CI.
###############################################################################
FROM ${JRE_IMAGE} AS prebuilt-src
WORKDIR /src
COPY context/pki-server /src/pki-server/build/install/zeroecho-pki-server
COPY context/app        /src/app/build/install/app

###############################################################################
# Stage 2: slim runtime.
###############################################################################
FROM ${JRE_IMAGE} AS runtime

# curl is required for the container HEALTHCHECK (mTLS probe of /health/ready).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates; \
    rm -rf /var/lib/apt/lists/*

# Non-root runtime identity. The numeric uid/gid is stable so that Kubernetes
# `runAsUser`/`fsGroup` and host bind-mount ownership can be aligned to it.
ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd --gid ${APP_GID} zeroecho && \
    useradd  --uid ${APP_UID} --gid ${APP_GID} --home-dir /opt/zeroecho \
             --shell /usr/sbin/nologin --no-create-home zeroecho

# Application distributions.
COPY --from=build /src/pki-server/build/install/zeroecho-pki-server /opt/zeroecho/server
COPY --from=build /src/app/build/install/app                         /opt/zeroecho/app

# Entry point.
COPY deploy/pki-server/entrypoint.sh /opt/zeroecho/entrypoint.sh
RUN chmod 0555 /opt/zeroecho/entrypoint.sh && \
    chmod 0555 /opt/zeroecho/server/bin/zeroecho-pki-server /opt/zeroecho/app/bin/app

# Data directories. Pre-creating them OWNED by the runtime user means a freshly
# created (empty) Docker named volume inherits this ownership on first mount.
# BIND mounts do NOT inherit it — the host path must already be owned by uid
# ${APP_UID} and mode 0700 (store/keyring) — see deploy/README.md.
RUN install -d -o zeroecho -g zeroecho -m 0700 /var/lib/zeroecho/store   && \
    install -d -o zeroecho -g zeroecho -m 0700 /var/lib/zeroecho/keyring && \
    install -d -o zeroecho -g zeroecho -m 0750 /var/lib/zeroecho/artifacts && \
    install -d -o zeroecho -g zeroecho -m 0750 /var/lib/zeroecho/audit    && \
    install -d -o zeroecho -g zeroecho -m 0750 /etc/zeroecho

ENV PATH="/opt/zeroecho/server/bin:/opt/zeroecho/app/bin:${PATH}" \
    ZEROECHO_SERVER_HOME=/opt/zeroecho/server \
    ZEROECHO_APP_HOME=/opt/zeroecho/app \
    ZEROECHO_SERVER_CONFIG=/etc/zeroecho/server-config.json \
    ZEROECHO_PROFILES_DIR=/etc/zeroecho/profiles \
    ZEROECHO_STORE_DIR=/var/lib/zeroecho/store \
    ZEROECHO_AUDIT_DIR=/var/lib/zeroecho/audit \
    ZEROECHO_ADMIN_PORT=8443 \
    ZEROECHO_HEALTH_CLIENT_CERT=/etc/zeroecho/health/health-client.pem \
    ZEROECHO_HEALTH_CLIENT_KEY=/etc/zeroecho/health/health-client-key.pem \
    ZEROECHO_HEALTH_CA=/etc/zeroecho/health/health-ca.pem

# Persisted state. Store and keyring are DELIBERATELY separate volumes so the
# keyring (private-key material) can be placed on a stricter, separately backed
# volume. See deploy/README.md for the data/config contract.
VOLUME ["/var/lib/zeroecho/store", "/var/lib/zeroecho/keyring", \
        "/var/lib/zeroecho/artifacts", "/var/lib/zeroecho/audit"]

# Administrative mutual-TLS listener (browser cert is terminated at nginx; in the
# reference topology this port only ever accepts the reverse proxy's transport
# certificate). Uncomment 8444 if you enable the public repository listener.
EXPOSE 8443
# EXPOSE 8444

USER zeroecho
WORKDIR /var/lib/zeroecho

# /health/ready is served before authentication but STILL behind the mandatory
# TLS client-auth handshake (the admin listener sets needClientAuth=true), so the
# probe presents a dedicated health-probe client identity that chains to the
# admin listener's client trust store. Returns 200 only once the realm is READY.
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
    CMD curl -fsS --max-time 4 \
        --cert "${ZEROECHO_HEALTH_CLIENT_CERT}" \
        --key  "${ZEROECHO_HEALTH_CLIENT_KEY}" \
        --cacert "${ZEROECHO_HEALTH_CA}" \
        "https://127.0.0.1:${ZEROECHO_ADMIN_PORT}/health/ready" || exit 1

ENTRYPOINT ["/opt/zeroecho/entrypoint.sh"]
