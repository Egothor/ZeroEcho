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
# Validate configuration, seed absent profile identities with the deployment-only
# Java helper, close its local session, then exec the permanent server as PID 1.
###############################################################################
set -eu

log() { printf '%s entrypoint: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

: "${ZEROECHO_SERVER_HOME:=/opt/zeroecho/server}"
: "${ZEROECHO_APP_HOME:=/opt/zeroecho/app}"
: "${ZEROECHO_SERVER_CONFIG:=/etc/zeroecho/server-config.json}"
: "${ZEROECHO_PROFILE_BOOTSTRAP_CONFIG:=/etc/zeroecho/profile-bootstrap.json}"
: "${ZEROECHO_PROFILES_DIR:=/etc/zeroecho/profiles}"
: "${ZEROECHO_STORE_DIR:=/var/lib/zeroecho/store-container/store}"

# Older deployments mounted the PKI root itself. Never bootstrap a new child
# beside that existing authority: an operator must migrate the complete volume offline.
STORE_PARENT=$(dirname -- "${ZEROECHO_STORE_DIR}")
[ ! -f "${STORE_PARENT}/VERSION" ] || die "legacy store volume requires offline layout migration"

SERVER_BIN="${ZEROECHO_SERVER_HOME}/bin/zeroecho-pki-server"
BOOTSTRAP_BIN="${ZEROECHO_APP_HOME}/bin/zeroecho-pki-profile-bootstrap"

[ -x "${SERVER_BIN}" ] || die "server launcher is missing"
[ -f "${ZEROECHO_SERVER_CONFIG}" ] || die "server configuration is missing"
log "validating server configuration"
set -- --config "${ZEROECHO_SERVER_CONFIG}"
if [ -n "${ZEROECHO_BACKUP_TRANSFER_CONFIG:-}" ]; then
    [ -f "${ZEROECHO_BACKUP_TRANSFER_CONFIG}" ] || die "backup transfer configuration is missing"
    set -- "$@" --backup-transfer-config "${ZEROECHO_BACKUP_TRANSFER_CONFIG}"
fi
if [ -n "${ZEROECHO_ENROLLMENT_CONFIG:-}" ]; then
    [ -f "${ZEROECHO_ENROLLMENT_CONFIG}" ] || die "enrollment configuration is missing"
    set -- "$@" --enrollment-config "${ZEROECHO_ENROLLMENT_CONFIG}"
fi
"${SERVER_BIN}" --validate-config "$@" \
    || die "server configuration is invalid; refusing to start"

case "${ZEROECHO_PROFILE_RECONCILE:-on}" in
    on)
        [ -x "${BOOTSTRAP_BIN}" ] || die "profile bootstrap launcher is missing"
        [ -f "${ZEROECHO_PROFILE_BOOTSTRAP_CONFIG}" ] || die "explicit local profile bootstrap configuration is missing"
        [ -d "${ZEROECHO_PROFILES_DIR}" ] || die "profile directory is missing"
        "${BOOTSTRAP_BIN}" --config "${ZEROECHO_PROFILE_BOOTSTRAP_CONFIG}" \
            --profiles-dir "${ZEROECHO_PROFILES_DIR}" --store-dir "${ZEROECHO_STORE_DIR}" \
            || die "profile bootstrap failed; refusing to start"
        ;;
    off) log "profile bootstrap explicitly disabled" ;;
    *) die "ZEROECHO_PROFILE_RECONCILE must be on or off" ;;
esac

log "starting zeroecho-pki-server"
exec "${SERVER_BIN}" "$@"
