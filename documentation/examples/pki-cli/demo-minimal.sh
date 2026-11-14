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
# ZeroEcho PKI CLI — two-tier CA and three leaf certificates in sequential plans.
# Root and intermediate creation have separate plans so the next plan can respect
# the issuer certificate's actual notBefore. Issuance/revocation uses step refs.
# Usage: ZE_HOME=<dir with bin/app> ./demo-minimal.sh [empty-workdir]
# Requires Bash, Python 3, OpenSSL and ZEROECHO_KEYRING_PASSWORD in the environment.
###############################################################################
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

echo "== ZeroEcho PKI CLI batch demo =="
pki_demo_setup "${1:-$(mktemp -d)}"

# Python encodes filesystem paths safely; step references remain literal strings.
python3 - "${WORK}" <<'PYPLANS'
import json, pathlib, sys
work = pathlib.Path(sys.argv[1])
def step(label, operation, **arguments):
    return {"id": label, "operation": operation, "arguments": arguments}
def save(name, operations):
    with open(work / (name + ".json"), "w") as target:
        json.dump({"version": 1, "failurePolicy": "FAIL_FAST", "operations": operations}, target, indent=2)
profiles = []
for profile in ["root-ca", "intermediate-ca", "server-tls", "vpn-server", "vpn-client"]:
    profiles += [step("reg-" + profile, "profile.register", profileFile=str(work / "profiles" / (profile + ".json"))),
                 step("act-" + profile, "profile.activate", profileId=profile, profileVersion=1)]
save("plan-root", profiles + [step("root", "ca.create", formatId="x509", subjectRef="CN=Example Root CA",
                                  profileId="root-ca", keyRef="zeroecho-lib:root.prv")])
PYPLANS
run_plan plan-root
inspect_ca root

python3 - "${WORK}" "$(field root-certificate authorityId)" <<'PYPLAN'
import json, pathlib, sys
work = pathlib.Path(sys.argv[1])
with open(work / "plan-intermediate.json", "w") as target:
    json.dump({"version": 1, "failurePolicy": "FAIL_FAST", "operations": [
        {"id": "inter", "operation": "ca.intermediate.create", "arguments": {
            "formatId": "x509", "issuerCaId": sys.argv[2], "subjectRef": "CN=Example Issuing CA",
            "profileId": "intermediate-ca", "keyRef": "zeroecho-lib:intermediate.prv"}}
    ]}, target, indent=2)
PYPLAN
run_plan plan-intermediate
inspect_ca inter

python3 - "${WORK}" "$(intermediate_ca)" <<'PYPLAN'
import json, pathlib, sys
work = pathlib.Path(sys.argv[1])
operations = []
for label, profile in [("web", "server-tls"), ("gtw", "vpn-server"), ("rw", "vpn-client")]:
    operations += [
        {"id": "csr-" + label, "operation": "request.import", "arguments": {
            "formatId": "x509", "encoding": "DER", "requestFile": str(work / "csr" / (label + ".csr.der"))}},
        {"id": label, "operation": "credential.issue", "arguments": {
            "issuerCaId": sys.argv[2], "requestId": "${csr-" + label + ".requestId}", "profileId": profile}}
    ]
operations += [
    {"id": "revoke", "operation": "credential.revoke", "arguments": {
        "credentialId": "${rw.credentialId}", "reason": "KEY_COMPROMISE", "justification": "stolen-laptop-INC-42"}},
    {"id": "crl", "operation": "status.generate", "arguments": {
        "issuerCaId": sys.argv[2], "type": "CRL", "formatId": "x509"}}
]
with open(work / "plan-issuance.json", "w") as target:
    json.dump({"version": 1, "failurePolicy": "FAIL_FAST", "operations": operations}, target, indent=2)
PYPLAN
run_plan plan-issuance

# Export through the actual synchronous filesystem publisher.
export_cert root-ca "$(field root credentialId)"
export_cert issuing-ca "$(field inter credentialId)"
export_cert web "$(field web credentialId)"
export_cert gtw "$(field gtw credentialId)"
export_cert road-warrior "$(field rw credentialId)"
export_crl crl "$(field crl statusObjectId)"

echo "== done. inspectable artifacts in ${WORK}/certs =="
ls -1 "${WORK}/certs"
