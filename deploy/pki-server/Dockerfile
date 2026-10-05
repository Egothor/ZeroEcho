# syntax=docker/dockerfile:1.7
# Copyright (C) 2025, Leo Galambos
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. All advertising materials mentioning features or use of this software must
#    display the following acknowledgement:
#    This product includes software developed by the Egothor project.
#
# 4. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software without
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
# Build from source with the default target, or reuse CI distributions:
#   docker build --target prebuilt -f deploy/pki-server/Dockerfile .
# Populate context/pki-server and context/app with their installDist contents.
# Both targets share the same runtime configuration and entrypoint.
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
# Shared runtime: independent of the source-build stage.
###############################################################################
FROM ${JRE_IMAGE} AS runtime-base
COPY LICENSE-binary.txt /opt/zeroecho/LICENSE-binary.txt

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

# Entry point shared by source and prebuilt images.
COPY deploy/pki-server/entrypoint.sh /opt/zeroecho/entrypoint.sh
RUN chmod 0555 /opt/zeroecho/entrypoint.sh

# Data directories. Pre-creating them OWNED by the runtime user means a freshly
# created (empty) Docker named volume inherits this ownership on first mount.
# BIND mounts do NOT inherit it — the host path must already be owned by uid
# ${APP_UID} and mode 0700 (store/keyring) — see deploy/README.md.
RUN install -d -o zeroecho -g zeroecho -m 0700 /var/lib/zeroecho/store-container && \
    install -d -o zeroecho -g zeroecho -m 0700 /var/lib/zeroecho/keyring && \
    install -d -o zeroecho -g zeroecho -m 0750 /var/lib/zeroecho/artifacts && \
    install -d -o zeroecho -g zeroecho -m 0750 /var/lib/zeroecho/audit    && \
    install -d -o zeroecho -g zeroecho -m 0750 /etc/zeroecho

ENV PATH="/opt/zeroecho/server/bin:/opt/zeroecho/app/bin:${PATH}" \
    ZEROECHO_SERVER_HOME=/opt/zeroecho/server \
    ZEROECHO_APP_HOME=/opt/zeroecho/app \
    ZEROECHO_SERVER_CONFIG=/etc/zeroecho/server-config.json \
    ZEROECHO_PROFILE_BOOTSTRAP_CONFIG=/etc/zeroecho/profile-bootstrap.json \
    ZEROECHO_PROFILES_DIR=/etc/zeroecho/profiles \
    ZEROECHO_STORE_DIR=/var/lib/zeroecho/store-container/store \
    ZEROECHO_AUDIT_DIR=/var/lib/zeroecho/audit \
    ZEROECHO_ADMIN_PORT=8443 \
    ZEROECHO_HEALTH_CLIENT_CERT=/etc/zeroecho/health/health-client.pem \
    ZEROECHO_HEALTH_CLIENT_KEY=/etc/zeroecho/health/health-client-key.pem \
    ZEROECHO_HEALTH_CA=/etc/zeroecho/health/health-ca.pem

# Persisted state. Store and keyring are DELIBERATELY separate volumes so the
# keyring (private-key material) can be placed on a stricter, separately backed
# volume. See deploy/README.md for the data/config contract.
VOLUME ["/var/lib/zeroecho/store-container", "/var/lib/zeroecho/keyring", \
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

###############################################################################
# Prebuilt target: no dependency on the Gradle source-build stage.
###############################################################################
FROM runtime-base AS prebuilt
COPY context/pki-server/ /opt/zeroecho/server/
COPY context/app/ /opt/zeroecho/app/
USER root
RUN chmod 0555 /opt/zeroecho/server/bin/zeroecho-pki-server /opt/zeroecho/app/bin/app /opt/zeroecho/app/bin/zeroecho-pki-profile-bootstrap
USER zeroecho

###############################################################################
# Default target: distributions built from the checked-out source.
###############################################################################
FROM runtime-base AS runtime
COPY --from=build /src/pki-server/build/install/zeroecho-pki-server/ /opt/zeroecho/server/
COPY --from=build /src/app/build/install/app/ /opt/zeroecho/app/
USER root
RUN chmod 0555 /opt/zeroecho/server/bin/zeroecho-pki-server /opt/zeroecho/app/bin/app /opt/zeroecho/app/bin/zeroecho-pki-profile-bootstrap
USER zeroecho
