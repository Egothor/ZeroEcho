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
# ZeroEcho PKI UI edge — nginx image.
#
# Serves the static SPA bundle and reverse-proxies the admin API to pki-server
# over mutual TLS, terminating the browser's client certificate and forwarding
# it per RFC 9440. See nginx.conf / conf.d/default.conf.template for the model.
#
# The njs module is required to synthesize the RFC 9440 Client-Cert value.
#
# Reuse a CI bundle with --target prebuilt and context/frontend populated with
# the contents of pki-frontend/dist; the default target builds from source.
###############################################################################

# --- Base image pins (replace tags with @sha256 digests for production) ------
ARG NODE_IMAGE=node:22.11.0-bookworm
ARG NGINX_IMAGE=nginx:1.27-bookworm
ARG JAVA_IMAGE=eclipse-temurin:25-jdk

# Generate the authoritative frontend input from Java, independently of Node.
FROM ${JAVA_IMAGE} AS schema
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/root/.gradle ./gradlew :pki-server:generateSchema --no-daemon

###############################################################################
# Stage 1: build the SPA bundle from source with the pinned Node toolchain.
# The repository build normally does this via `:pki-frontend:npmBuild`; here we
# reproduce it directly so the image is self-contained. If your CI already
# produced pki-frontend/dist (or the distribution zip), use the `prebuilt`
# target instead and COPY the unpacked bundle to the context.
###############################################################################
FROM ${NODE_IMAGE} AS build
WORKDIR /src/pki-frontend
# The frontend module and canonical binary license produce the complete bundle.
COPY LICENSE-binary.txt /src/LICENSE-binary.txt
COPY pki-frontend/package.json pki-frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY pki-frontend/ ./
COPY --from=schema /src/pki-server/build/generated/schema/ /src/pki-server/build/generated/schema/
RUN npm run build   # emits ./dist (hashed assets under dist/assets, index.html)

###############################################################################
# Stage 2: runtime nginx with njs.
###############################################################################
FROM ${NGINX_IMAGE} AS runtime-base
COPY LICENSE-binary.txt /usr/share/licenses/zeroecho/LICENSE-binary.txt

# njs dynamic module (ngx_http_js_module.so).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends nginx-module-njs curl; \
    rm -rf /var/lib/apt/lists/*

# Configuration.
COPY deploy/nginx/nginx.conf                 /etc/nginx/nginx.conf
COPY deploy/nginx/conf.d/default.conf.template /etc/nginx/templates/default.conf.template
COPY deploy/nginx/njs/client_cert.js         /etc/nginx/njs/client_cert.js

# Only substitute our own placeholders at start-up; leave nginx $variables alone.
ENV NGINX_ENVSUBST_FILTER="^(NGINX_|PKI_)" \
    NGINX_SERVER_NAME="pki.example.com" \
    NGINX_HTTPS_PORT="8443" \
    PKI_UPSTREAM="pki-server:8443" \
    PKI_PROXY_SSL_NAME="zeroecho-admin"

# TLS material is provided at run time as read-only mounts:
#   /etc/nginx/tls/edge/           edge.crt, edge.key            (browser-facing)
#   /etc/nginx/tls/admin-trust/    admin-ca-bundle.pem           (browser mTLS trust)
#   /etc/nginx/tls/upstream/       proxy-client.crt/.key, pki-server-ca.pem
VOLUME ["/var/cache/nginx", "/var/run"]

EXPOSE 80 8443

# Prove nginx itself is serving (loopback plaintext endpoint in nginx.conf).
HEALTHCHECK --interval=15s --timeout=4s --start-period=10s --retries=5 \
    CMD curl -fsS --max-time 3 http://127.0.0.1:8080/nginx-health || exit 1

# The stock nginx entrypoint renders templates then runs nginx in the foreground.
# The official image already runs as a limited user for workers; master starts as
# root only to bind ports and read TLS keys, then drops to `user nginx`.

###############################################################################
# Prebuilt target: no dependency on Node or the source-build stage.
###############################################################################
FROM runtime-base AS prebuilt
COPY context/frontend/ /usr/share/nginx/html/

###############################################################################
# Default target: SPA bundle built from the checked-out source.
###############################################################################
FROM runtime-base AS runtime
COPY --from=build /src/pki-frontend/dist/ /usr/share/nginx/html/
