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
# ZeroEcho PKI CLI — enterprise-grade worked scenario (per-operation)
#
# Extends the minimal a-c scenario into a realistic operator run for the
# fictional org "Example s.r.o.", exercising a broader slice of the PKI
# operation set and, notably, CROSS-CERTIFICATION between two roots:
#
#   * two independent roots  : Root A (primary), Root B (bridge/partner)
#   * one issuing CA          : under Root A
#   * cross-certification     : Root B issues a cross-certificate for the same
#                               issuing CA (ca.intermediate.issue), giving it a
#                               second trust path; that path is registered and
#                               can be selected for issuance (issuer.path.*)
#   * SIX leaf certificates   : two HTTPS hosts, one IPsec gateway, three IPsec
#                               road-warriors  (more than the minimal a-c set)
#   * two revocations         : theft -> KEY_COMPROMISE, rollover -> SUPERSEDED
#   * status + publication     : CRL generated and published to the filesystem
#   * lifecycle + inventory    : reissue, ca.list, revocation.snapshot
#
# Every step is its own `zeroecho pki <op>` process (openssl-style), with
# output IDs threaded between invocations. Where a scenario cannot be a single
# batch (cross-cert path selection depends on IDs discovered mid-run), splitting
# into individual operations is the natural model — and it is shown here across
# many more certificates than the minimal demo, as intended.
#
# Usage:  ZE_HOME=<dir with bin/app> ./demo-enterprise.sh [workdir]
# Requires: openssl and python3 on PATH; a built ZeroEcho app distribution.
###############################################################################
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

echo "== ZeroEcho PKI CLI enterprise demo =="
WORK="${1:-$(mktemp -d)}"
pki_demo_setup "${WORK}"

# Additional subject CSRs beyond the shared web/gtw/rw set (SAN IPs from RFC 5737).
_gen_csr web01 "web01.example.com" "DNS:web01.example.com,IP:192.0.2.11"
_gen_csr web02 "web02.example.com" "DNS:www.example.com,DNS:web02.example.com,IP:192.0.2.12"
_gen_csr alice "roadwarrior.alice" "email:alice@example.com,URI:spiffe://example.com/vpn/alice"
_gen_csr bob   "roadwarrior.bob"   "email:bob@example.com,URI:spiffe://example.com/vpn/bob"
_gen_csr carol "roadwarrior.carol" "email:carol@example.com,URI:spiffe://example.com/vpn/carol"

echo "== register + activate profiles =="
for p in root-ca intermediate-ca server-tls vpn-server vpn-client; do
  run_op "reg-${p}" profile.register --profile-file "${WORK}/profiles/${p}.json"
  run_op "act-${p}" profile.activate --profile-id "${p}" --profile-version 1
done

echo "== build two roots and one issuing CA =="
run_op root-a ca.create \
  --format-id x509 --subject-ref "CN=Example Root CA A" --profile-id root-ca --key-ref zeroecho-lib:root.prv
inspect_ca root-a
ROOT_A="$(field root-a-certificate authorityId)"; echo "  Root A         : ${ROOT_A}"

run_op root-b ca.create \
  --format-id x509 --subject-ref "CN=Example Root CA B" --profile-id root-ca --key-ref zeroecho-lib:root-b.prv
inspect_ca root-b
ROOT_B="$(field root-b-certificate authorityId)"; echo "  Root B         : ${ROOT_B}"

run_op inter ca.intermediate.create \
  --format-id x509 --issuer-ca-id "${ROOT_A}" --subject-ref "CN=Example Issuing CA" \
  --profile-id intermediate-ca --key-ref zeroecho-lib:intermediate.prv
inspect_ca inter
INTER="$(intermediate_ca)"; echo "  Issuing CA     : ${INTER}"

echo "== inspect issuer generations / paths (before cross-certification) =="
run_op inter-inspect ca.inspect --ca-id "${INTER}"
ISSUER_ID="$(field inter-inspect currentIssuanceIssuerId)"; echo "  issuer id      : ${ISSUER_ID}"
run_op paths-before issuer.path.list --issuer-id "${ISSUER_ID}"
echo "  paths (before) : $(field paths-before count)"

echo "== cross-certify the issuing CA under Root B =="
# Root B issues a cross-certificate over the SAME issuing-CA key that Root A
# already certified. Relying parties that trust Root B now accept certificates
# from the issuing CA too — the essence of cross-certification / bridging.
run_op cross ca.intermediate.issue \
  --format-id x509 --issuer-ca-id "${ROOT_B}" --subject-ca-id "${INTER}" --profile-id intermediate-ca
echo "  cross-cert     : $(field cross credentialId)"
echo "  cross issuer   : ${ROOT_B} (Root B) over subject ${INTER}"

echo "== inspect the issuing CA's issuer generation after cross-certification =="
run_op gen-inspect issuer.generation.inspect --issuer-id "${ISSUER_ID}"
echo "  issuer state   : $(field gen-inspect state)"
echo "  authority      : $(field gen-inspect authorityId)"

# issue_leaf <label> <csr-name> <profile> -> issues one leaf, echoes credentialId
issue_leaf() {
  local label="$1" csr="$2" profile="$3"
  run_op "csr-${label}" request.import --format-id x509 --encoding DER --request-file "${WORK}/csr/${csr}.csr.der"
  run_op "${label}" credential.issue \
    --issuer-ca-id "${INTER}" --request-id "$(field "csr-${label}" requestId)" --profile-id "${profile}"
}

echo "== issue six leaf certificates from the issuing CA =="
issue_leaf web01 web01 server-tls   # HTTPS host web01
issue_leaf web02 web02 server-tls   # HTTPS host web02 (www alias)
issue_leaf gtw   gtw   vpn-server   # IPsec gateway
issue_leaf alice alice vpn-client   # road-warrior alice
issue_leaf bob   bob   vpn-client   # road-warrior bob
issue_leaf carol carol vpn-client   # road-warrior carol
for c in web01 web02 gtw alice bob carol; do echo "  ${c}: $(field "${c}" credentialId)"; done

echo "== revoke two client certificates (different reasons) =="
run_op revoke-bob credential.revoke \
  --credential-id "$(field bob credentialId)" --reason KEY_COMPROMISE --justification "stolen-laptop-INC-42"
echo "  bob            : $(field revoke-bob state) (theft -> KEY_COMPROMISE)"
run_op revoke-carol credential.revoke \
  --credential-id "$(field carol credentialId)" --reason SUPERSEDED --justification "reissued-under-new-key"
echo "  carol          : $(field revoke-carol state) (SUPERSEDED)"

echo "== lifecycle: reissue alice's credential =="
run_op reissue-alice credential.reissue --credential-id "$(field alice credentialId)"
echo "  alice reissue  : $(field reissue-alice credentialId)"

echo "== generate + publish the CRL =="
run_op crl status.generate --issuer-ca-id "${INTER}" --type CRL --format-id x509
CRL_ID="$(field crl statusObjectId)"; echo "  CRL object     : ${CRL_ID} (entries reflect 2 revocations)"
run_op pub-crl publication.register \
  --publication-id crl-pub-1 --source-type STATUS_OBJECT --source-id "${CRL_ID}" \
  --target-type FILESYSTEM --target-id local
run_op proc-crl publication.process --publication-id "$(field pub-crl publicationId)"

echo "== export certificates + CRL to files (for openssl inspection) =="
export_cert root-a       "$(field root-a credentialId)"
export_cert root-b       "$(field root-b credentialId)"
export_cert issuing-ca   "$(field inter credentialId)"
export_cert issuing-ca-cross "$(field cross credentialId)"   # cross-cert under Root B
for c in web01 web02 gtw alice bob carol; do export_cert "${c}" "$(field "${c}" credentialId)"; done
export_cert alice-reissued "$(field reissue-alice credentialId)"
export_crl  crl          "${CRL_ID}"

echo "== inventory / audit views =="
run_op ca-list ca.list --limit 50
echo "  authorities    : $(field ca-list count)"
run_op rev-snapshot revocation.snapshot --limit 50
echo "  revocations    : $(field rev-snapshot count)"

echo
echo "== done. inspectable artifacts in ${WORK}/certs =="
ls -1 "${WORK}/certs"
echo
echo "Inspect, for example:"
echo "  openssl x509 -in ${WORK}/certs/web01.pem -noout -subject -issuer -ext subjectAltName,extendedKeyUsage"
echo "  openssl x509 -in ${WORK}/certs/issuing-ca-cross.pem -noout -subject -issuer   # cross-cert: issuer = Root B"
echo "  openssl crl  -in ${WORK}/certs/crl.pem -noout -text | head"
echo "workdir: ${WORK}"
