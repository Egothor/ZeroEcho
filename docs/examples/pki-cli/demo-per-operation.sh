#!/usr/bin/env bash
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
# ZeroEcho PKI CLI — minimal worked scenario, one operation per invocation
#
# Same fictional org and same result as demo-minimal.sh, but here EVERY PKI
# operation is its own `zeroecho pki <op>` process (the openssl-style model:
# one command, one synchronous operation, machine-readable JSON on stdout).
# Output IDs are threaded between invocations by parsing steps[0].output.<field>.
#
# Contrast with demo-minimal.sh, which performs the identical scenario as ONE
# `zeroecho pki run <plan>` batch. Use batch to sign a whole series in one run;
# use per-operation when scripting incrementally or wiring into other tools.
#
# Usage:  ZE_HOME=<dir with bin/app> ./demo-per-operation.sh [workdir]
# Requires: openssl and python3 on PATH; a built ZeroEcho app distribution.
###############################################################################
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

echo "== ZeroEcho PKI CLI per-operation demo =="
pki_demo_setup "${1:-$(mktemp -d)}"   # provides run_op and field helpers

echo "== register + activate profiles =="
for p in root-ca intermediate-ca server-tls vpn-server vpn-client; do
  run_op "reg-${p}" profile.register --profile-file "${WORK}/profiles/${p}.json"
  run_op "act-${p}" profile.activate --profile-id "${p}" --profile-version 1
done

echo "== build the two-tier CA =="
run_op root ca.create \
  --format-id x509 --subject-ref "CN=Example Root CA" --profile-id root-ca --key-ref zeroecho-lib:root.prv
ROOT_CA="$(field root caId)"; echo "  root CA        : ${ROOT_CA}"

run_op inter ca.intermediate.create \
  --format-id x509 --issuer-ca-id "${ROOT_CA}" --subject-ref "CN=Example Issuing CA" \
  --profile-id intermediate-ca --key-ref zeroecho-lib:intermediate.prv
INTER_CA="$(field inter caId)"; echo "  issuing CA     : ${INTER_CA}"

# issue_leaf <label> <csr-name> <profile> -> echoes the credentialId
issue_leaf() {
  local label="$1" csr="$2" profile="$3"
  run_op "csr-${label}" request.import --format-id x509 --encoding DER --request-file "${WORK}/csr/${csr}.csr.der"
  run_op "${label}" credential.issue \
    --issuer-ca-id "${INTER_CA}" --request-id "$(field "csr-${label}" requestId)" --profile-id "${profile}"
}

echo "== issue the three leaf certificates =="
issue_leaf web web server-tls   # a) HTTPS service on host "web"
issue_leaf gtw gtw vpn-server   # b) IPsec gateway "gtw"
issue_leaf rw  rw  vpn-client   # c) IPsec road-warrior (Windows client)
RW_CRED="$(field rw credentialId)"
echo "  web cert       : $(field web credentialId)"
echo "  gtw cert       : $(field gtw credentialId)"
echo "  road-warrior   : ${RW_CRED}"

echo "== revoke the road-warrior cert (theft -> KEY_COMPROMISE) =="
run_op revoke credential.revoke \
  --credential-id "${RW_CRED}" --reason KEY_COMPROMISE --justification "stolen-laptop-INC-42"
echo "  new state      : $(field revoke state)"

echo "== generate + publish the CRL =="
run_op crl status.generate --issuer-ca-id "${INTER_CA}" --type CRL --format-id x509
CRL_ID="$(field crl statusObjectId)"; echo "  CRL object     : ${CRL_ID}"
run_op pub-crl publication.register \
  --publication-id crl-pub-1 --source-type STATUS_OBJECT --source-id "${CRL_ID}" \
  --target-type FILESYSTEM --target-id local
run_op proc-crl publication.process --publication-id "$(field pub-crl publicationId)"

echo "== export certificates + CRL to files (for openssl inspection) =="
export_cert root-ca      "$(ca_cert_credential "${ROOT_CA}")"
export_cert issuing-ca   "$(ca_cert_credential "${INTER_CA}")"
export_cert web          "$(field web credentialId)"
export_cert gtw          "$(field gtw credentialId)"
export_cert road-warrior "$(field rw credentialId)"
export_crl  crl          "${CRL_ID}"

echo
echo "== done. inspectable artifacts in ${WORK}/certs =="
ls -1 "${WORK}/certs"
echo
echo "Inspect, for example:"
echo "  openssl x509 -in ${WORK}/certs/web.pem -noout -subject -issuer -ext subjectAltName,extendedKeyUsage"
echo "  openssl crl  -in ${WORK}/certs/crl.pem -noout -text | head"
echo "workdir: ${WORK}"
