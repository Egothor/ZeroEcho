# syntax=docker/dockerfile:1.7
###############################################################################
# ZeroEcho PKI UI edge — nginx image.
#
# Serves the static SPA bundle and reverse-proxies the admin API to pki-server
# over mutual TLS, terminating the browser's client certificate and forwarding
# it per RFC 9440. See nginx.conf / conf.d/default.conf.template for the model.
#
# The njs module is required to synthesize the RFC 9440 Client-Cert value.
#
# NOT BUILT/RUN here (no container engine available); statically authored only.
###############################################################################

# --- Base image pins (replace tags with @sha256 digests for production) ------
ARG NODE_IMAGE=node:22.11.0-bookworm
ARG NGINX_IMAGE=nginx:1.27-bookworm

###############################################################################
# Stage 1: build the SPA bundle from source with the pinned Node toolchain.
# The repository build normally does this via `:pki-frontend:npmBuild`; here we
# reproduce it directly so the image is self-contained. If your CI already
# produced pki-frontend/dist (or the distribution zip), use the `prebuilt`
# target instead and COPY the unpacked bundle to the context.
###############################################################################
FROM ${NODE_IMAGE} AS build
WORKDIR /src
# Only the frontend module is needed to build the bundle.
COPY pki-frontend/package.json pki-frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY pki-frontend/ ./
RUN npm run build   # emits ./dist (hashed assets under dist/assets, index.html)

###############################################################################
# Stage 2: runtime nginx with njs.
###############################################################################
FROM ${NGINX_IMAGE} AS runtime

# njs dynamic module (ngx_http_js_module.so).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends nginx-module-njs curl; \
    rm -rf /var/lib/apt/lists/*

# Configuration.
COPY deploy/nginx/nginx.conf                 /etc/nginx/nginx.conf
COPY deploy/nginx/conf.d/default.conf.template /etc/nginx/templates/default.conf.template
COPY deploy/nginx/njs/client_cert.js         /etc/nginx/njs/client_cert.js

# SPA bundle.
COPY --from=build /src/dist/ /usr/share/nginx/html/

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
