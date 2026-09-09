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
# ZeroEcho PKI container smoke test (Task 15 exit criterion).
#
# Brings up (optionally) the Compose stack, waits for readiness, then performs
# ONE end-to-end issuance flow through the edge over mutual TLS, and asserts a
# terminal success. Tears the stack down at the end (unless --no-down).
#
# WHY curl AND NOT `zeroecho pki --url`: the `zeroecho pki` CLI is a
# single-process LOCAL tool and is explicitly NOT a network client (see
# docs/examples/pki-cli/README.md and the BACKEND GAP note in deploy/README.md).
# The only network client contract is the admin HTTPS API, so the smoke test
# speaks it directly with curl over mTLS.
#
# This script was NOT executed here (no container engine available). It is
# syntax-checked (`sh -n`) and written to be correct and self-documenting.
#
# Usage:
#   deploy/smoke-test.sh [--no-up] [--no-down]
#
# Requires: docker compose, curl, sed. Reads deploy/.env. Prerequisites for a
# real issuance (provisioned during operator bootstrap, see deploy/README.md):
#   * a CA exists in the store          -> SMOKE_CA_ID
#   * an end-entity profile is active   -> SMOKE_PROFILE_ID (reconciled at start)
#   * a request is available, EITHER:
#       - already imported              -> SMOKE_REQUEST_ID, OR
#       - a request.import body to POST -> SMOKE_IMPORT_ARGS_FILE (admin JSON per
#         docs/pki-server-admin-https.md; inline base64 CSR, no file paths)
###############################################################################
set -eu

DO_UP=1
DO_DOWN=1
for arg in "$@"; do
    case "${arg}" in
        --no-up)   DO_UP=0 ;;
        --no-down) DO_DOWN=0 ;;
        *) echo "unknown argument: ${arg}" >&2; exit 2 ;;
    esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="${HERE}/compose/docker-compose.yml"
[ -f "${HERE}/.env" ] && . "${HERE}/.env"

: "${SMOKE_BASE_URL:=https://localhost:8443}"
: "${SMOKE_ADMIN_CERT:?SMOKE_ADMIN_CERT (admin client cert PEM) required}"
: "${SMOKE_ADMIN_KEY:?SMOKE_ADMIN_KEY (admin client key PEM) required}"
: "${SMOKE_CA_BUNDLE:?SMOKE_CA_BUNDLE (edge server CA PEM) required}"
: "${SMOKE_CA_ID:?SMOKE_CA_ID (issuer CA id) required}"
: "${SMOKE_PROFILE_ID:?SMOKE_PROFILE_ID (active end-entity profile id) required}"

log()  { printf '[smoke] %s\n' "$*" >&2; }
fail() { printf '[smoke] FAIL: %s\n' "$*" >&2; teardown; exit 1; }

# mTLS curl to the edge. Args: METHOD PATH [BODY]. Prints "<HTTP_CODE>\n<BODY>".
api() {
    _method="$1"; _path="$2"; _body="${3:-}"
    if [ -n "${_body}" ]; then
        curl -sS -o /tmp/smoke_body -w '%{http_code}' \
            --cert "${SMOKE_ADMIN_CERT}" --key "${SMOKE_ADMIN_KEY}" --cacert "${SMOKE_CA_BUNDLE}" \
            -X "${_method}" -H 'Content-Type: application/json' \
            --data "${_body}" "${SMOKE_BASE_URL}${_path}"
    else
        curl -sS -o /tmp/smoke_body -w '%{http_code}' \
            --cert "${SMOKE_ADMIN_CERT}" --key "${SMOKE_ADMIN_KEY}" --cacert "${SMOKE_CA_BUNDLE}" \
            -X "${_method}" "${SMOKE_BASE_URL}${_path}"
    fi
}

# Extract a top-level-ish JSON string field value (best-effort; prefer jq if you
# have it). Args: FIELD FILE.
json_field() {
    sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$2" | head -n 1
}

teardown() {
    if [ "${DO_DOWN}" -eq 1 ] && [ "${DO_UP}" -eq 1 ]; then
        log "tearing down the stack"
        docker compose -f "${COMPOSE_FILE}" down --remove-orphans || true
    fi
}

# --- 1. Bring the stack up ---------------------------------------------------
if [ "${DO_UP}" -eq 1 ]; then
    log "starting the Compose stack"
    docker compose -f "${COMPOSE_FILE}" up -d --build
fi

# --- 2. Wait for readiness (through the edge) --------------------------------
log "waiting for /health/ready via the edge"
ready=0
i=0
while [ "${i}" -lt 60 ]; do
    code="$(api GET /health/ready || true)"
    if [ "${code}" = "200" ]; then ready=1; break; fi
    i=$((i + 1)); sleep 2
done
[ "${ready}" -eq 1 ] || fail "server did not become ready"
log "server is READY"

# --- 3. Prove the mTLS -> RFC 9440 -> forwarded-identity chain ---------------
code="$(api GET /admin/v1/realm || true)"
[ "${code}" = "200" ] || fail "GET /admin/v1/realm returned ${code} (auth chain broken)"
log "authenticated administrative identity accepted"

# --- 4. Optionally import the request ---------------------------------------
if [ -n "${SMOKE_REQUEST_ID:-}" ]; then
    REQUEST_ID="${SMOKE_REQUEST_ID}"
    log "using pre-imported requestId=${REQUEST_ID}"
elif [ -n "${SMOKE_IMPORT_ARGS_FILE:-}" ]; then
    log "importing request from ${SMOKE_IMPORT_ARGS_FILE}"
    body="$(cat "${SMOKE_IMPORT_ARGS_FILE}")"
    code="$(api POST /admin/v1/operations/request.import "${body}" || true)"
    [ "${code}" = "200" ] || fail "request.import returned ${code}: $(cat /tmp/smoke_body)"
    REQUEST_ID="$(json_field requestId /tmp/smoke_body)"
    [ -n "${REQUEST_ID}" ] || fail "could not extract requestId from import response"
    log "imported requestId=${REQUEST_ID}"
else
    fail "set SMOKE_REQUEST_ID or SMOKE_IMPORT_ARGS_FILE"
fi

# --- 5. Issue one credential (the end-to-end flow) --------------------------
issue_body="$(printf '{"version":1,"authorityId":"%s","arguments":{"issuerCaId":"%s","requestId":"%s","profileId":"%s"}}' \
    "${SMOKE_CA_ID}" "${SMOKE_CA_ID}" "${REQUEST_ID}" "${SMOKE_PROFILE_ID}")"
log "POST credential.issue"
code="$(api POST /admin/v1/operations/credential.issue "${issue_body}" || true)"

case "${code}" in
    200)
        log "issuance completed synchronously"
        ;;
    202)
        # Signing-backed: follow the Location to the signing-operations resource.
        loc="$(curl -sS -D - -o /dev/null \
            --cert "${SMOKE_ADMIN_CERT}" --key "${SMOKE_ADMIN_KEY}" --cacert "${SMOKE_CA_BUNDLE}" \
            -X POST -H 'Content-Type: application/json' --data "${issue_body}" \
            "${SMOKE_BASE_URL}/admin/v1/operations/credential.issue" \
            | sed -n 's/^[Ll]ocation:[[:space:]]*\(.*\)\r*$/\1/p' | head -n 1)"
        [ -n "${loc}" ] || fail "202 without a Location header"
        log "polling signing operation ${loc}"
        outcome=""
        j=0
        while [ "${j}" -lt 60 ]; do
            code="$(api GET "${loc}" || true)"
            [ "${code}" = "200" ] || { j=$((j + 1)); sleep 2; continue; }
            state="$(json_field status /tmp/smoke_body)"
            [ -n "${state}" ] || state="$(json_field outcome /tmp/smoke_body)"
            case "${state}" in
                SUCCEEDED) outcome=ok; break ;;
                FAILED)    fail "signing operation FAILED: $(cat /tmp/smoke_body)" ;;
                *)         : ;;  # PENDING / unknown -> keep polling
            esac
            j=$((j + 1)); sleep 2
        done
        [ "${outcome}" = "ok" ] || fail "signing operation did not reach SUCCEEDED"
        log "signing operation SUCCEEDED"
        ;;
    *)
        fail "credential.issue returned ${code}: $(cat /tmp/smoke_body)"
        ;;
esac

log "PASS: one issuance flow completed end-to-end over mTLS"
teardown
exit 0
