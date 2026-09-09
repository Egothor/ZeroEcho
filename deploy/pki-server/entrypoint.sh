#!/bin/sh
###############################################################################
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

###############################################################################
# ZeroEcho PKI server container entrypoint (POSIX sh).
#
# Responsibilities, in order:
#   1. Preflight: validate the mounted server-config.json (fail fast).
#   2. Idempotent certificate-profile reconcile against the SAME on-disk store
#      the server will open, BEFORE the server opens it (single-writer store).
#   3. exec the long-lived server process (PID 1 in the container).
#
# Secrets are read ONLY from environment variables (keyring unlock, TLS store
# passwords). Nothing secret is written to the image or to any config file.
#
# This script is intentionally dependency-light: /bin/sh, the two bundled
# distributions, and coreutils only. It was syntax-checked with `sh -n`; it was
# NOT executed in the authoring environment (no container engine available).
###############################################################################
set -eu

log() { printf '%s entrypoint: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

: "${ZEROECHO_SERVER_HOME:=/opt/zeroecho/server}"
: "${ZEROECHO_APP_HOME:=/opt/zeroecho/app}"
: "${ZEROECHO_SERVER_CONFIG:=/etc/zeroecho/server-config.json}"
: "${ZEROECHO_PROFILES_DIR:=/etc/zeroecho/profiles}"
: "${ZEROECHO_STORE_DIR:=/var/lib/zeroecho/store}"
: "${ZEROECHO_AUDIT_DIR:=/var/lib/zeroecho/audit}"

SERVER_BIN="${ZEROECHO_SERVER_HOME}/bin/zeroecho-pki-server"
APP_BIN="${ZEROECHO_APP_HOME}/bin/app"

###############################################################################
# Extract the top-level "profileId" string from a profile document (best-effort,
# no JSON parser available in the base image). Prints the id or nothing.
###############################################################################
profile_id_of() {
    # Match:  "profileId" : "value"   (first occurrence wins).
    sed -n 's/.*"profileId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -n 1
}

###############################################################################
# Best-effort, profile-identity-idempotent reconcile of every *.json profile in
# ${ZEROECHO_PROFILES_DIR} into the store at ${ZEROECHO_STORE_DIR}.
###############################################################################
reconcile_profiles() {
    reconcile_config="$(mktemp)" || die "cannot create temp file"
    # CLI session configuration (schema version 2). NB: the CLI uses "provider"
    # (not "id") for provider selection. profile.register/activate touch only the
    # store; the audit sink is 'memory' so reconcile never contends with the
    # server's durable audit sink. No signing/keyring block is needed.
    cat > "${reconcile_config}" <<EOF
{
  "version": 2,
  "store":  { "provider": "fs",     "properties": { "root": "${ZEROECHO_STORE_DIR}" } },
  "audit":  { "provider": "memory", "properties": { "size": "512" } },
  "publishers": []
}
EOF

    # Snapshot of already-registered profile ids (JSON output, best-effort parse).
    existing="$("${APP_BIN}" pki profile.list --config "${reconcile_config}" --output json 2>/dev/null \
        | sed -n 's/.*"profileId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | sort -u || true)"

    found=0
    for profile_file in "${ZEROECHO_PROFILES_DIR}"/*.json; do
        [ -e "${profile_file}" ] || continue   # no matches -> glob stays literal
        found=1
        pid="$(profile_id_of "${profile_file}")"
        [ -n "${pid}" ] || { log "WARN: no profileId in ${profile_file}; skipping"; continue; }
        if printf '%s\n' "${existing}" | grep -Fxq "${pid}"; then
            log "profile '${pid}' already present; leaving as-is"
            continue
        fi
        log "registering profile '${pid}' from ${profile_file}"
        "${APP_BIN}" pki profile.register --config "${reconcile_config}" \
            --profile-file "${profile_file}" --output json \
            || die "profile.register failed for ${profile_file}"
        # A freshly registered profile is version 1; activate it.
        "${APP_BIN}" pki profile.activate --config "${reconcile_config}" \
            --profile-id "${pid}" --profile-version 1 --output json \
            || die "profile.activate failed for ${pid}"
        log "profile '${pid}' registered and activated (version 1)"
    done
    [ "${found}" -eq 1 ] || log "no *.json profiles found in ${ZEROECHO_PROFILES_DIR}"

    rm -f "${reconcile_config}"
}

[ -x "${SERVER_BIN}" ] || die "server launcher not found at ${SERVER_BIN}"
[ -f "${ZEROECHO_SERVER_CONFIG}" ] || die "server config not found at ${ZEROECHO_SERVER_CONFIG}"

###############################################################################
# 1. Config preflight. `--validate-config` parses and fully validates the strict
#    versioned JSON without opening providers, listeners, or the store.
###############################################################################
log "validating server configuration ${ZEROECHO_SERVER_CONFIG}"
if ! "${SERVER_BIN}" --validate-config --config "${ZEROECHO_SERVER_CONFIG}"; then
    die "server configuration is invalid (see message above); refusing to start"
fi
log "server configuration is valid"

###############################################################################
# 2. Idempotent profile reconcile (see reconcile_profiles above).
#    Set ZEROECHO_PROFILE_RECONCILE=off to skip (e.g. a separate migration job
#    owns profile lifecycle).
###############################################################################
if [ "${ZEROECHO_PROFILE_RECONCILE:-on}" = "on" ] && [ -d "${ZEROECHO_PROFILES_DIR}" ]; then
    if [ -x "${APP_BIN}" ]; then
        reconcile_profiles
    else
        log "WARN: CLI launcher ${APP_BIN} missing; skipping profile reconcile"
    fi
else
    log "profile reconcile disabled or profiles dir absent; skipping"
fi

###############################################################################
# 3. Hand off to the server as PID 1 so it receives SIGTERM directly and runs
#    its own graceful-shutdown hook.
###############################################################################
log "starting zeroecho-pki-server"
exec "${SERVER_BIN}" --config "${ZEROECHO_SERVER_CONFIG}"
