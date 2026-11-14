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
# Shared setup for the ZeroEcho PKI CLI example scripts.
#
# pki_demo_setup <workdir> prepares everything that is a PREREQUISITE of PKI
# operations (exactly as an openssl-based CA setup would): it seeds the CA
# keyring, writes the session config and the certificate profiles, and generates
# the subject key-pairs + PKCS#10 CSRs. It exports: ZE, WORK, KEYRING, CONFIG.
#
# The PKI CLI itself never mints private keys: CA keys live in a keyring the
# operator provisions; subjects hold their own keys and submit CSRs.
###############################################################################

# Some distributions ship openssl under /usr/sbin.
case ":${PATH}:" in *:/usr/sbin:*) ;; *) PATH="${PATH}:/usr/sbin" ;; esac
export PATH

# Extract one JSON field: json_field <jsonfile> <step-index> <field>
json_field() {
  python3 - "$@" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
print(doc["steps"][int(sys.argv[2])]["output"][sys.argv[3]])
PY
}

# run_op <label> <operation> [--flag value ...]
# Runs one PKI operation as its own process, saves out/<label>.json, aborts on non-success.
# Requires ZE, CONFIG, WORK to be exported (pki_demo_setup does this).
run_op() {
  local label="$1" op="$2"; shift 2
  local code=0
  "${ZE}" pki "${op}" --config "${CONFIG}" --output json "$@" > "${WORK}/out/${label}.json" || code=$?
  if (( code != 0 )); then
    echo "ABORT: ${op} exited ${code}; receipt retained in ${WORK}/out/${label}.json" >&2
    exit "${code}"
  fi
  local status
  status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "${WORK}/out/${label}.json")"
  printf '  %-16s %-26s %s\n' "${label}" "${op}" "${status}"
  [ "${status}" = "SUCCEEDED" ] || { echo "ABORT: ${op} -> ${status}"; cat "${WORK}/out/${label}.json"; exit 1; }
  if [[ "${op}" == publication.process ]] && [[ "$(field "${label}" status)" != SUCCEEDED ]]; then
    echo "ABORT: publication did not succeed; inspect ${WORK}/out/${label}.json before explicit recovery" >&2
    exit 1
  fi
}

# field <label> <name> -> value of steps[0].output.<name> from out/<label>.json
field() { json_field "${WORK}/out/$1.json" 0 "$2"; }

# The PKI CLI keeps issued objects in the store; to hand an operator files they
# can inspect with openssl we PUBLISH each object to the filesystem publisher and
# copy the resulting bytes (DER) into certs/ under a friendly name. The publisher
# names files sha256(publicationId).bin, which we recompute to locate them.

# export_published <label> <source-type> <source-id> -> writes certs/<label>.der
export_published() {
  local label="$1" stype="$2" sid="$3" pid="pub-${1}"
  run_op "reg-pub-${label}" publication.register --publication-id "${pid}" \
    --source-type "${stype}" --source-id "${sid}" --target-type FILESYSTEM --target-id local
  run_op "proc-pub-${label}" publication.process --publication-id "$(field "reg-pub-${label}" publicationId)"
  local hash; hash="$(printf '%s' "${pid}" | sha256sum | cut -d' ' -f1)"
  cp "${WORK}/published/${hash}.bin" "${WORK}/certs/${label}.der"
}

# export_cert <label> <credentialId> -> certs/<label>.der (DER) + certs/<label>.pem (PEM)
export_cert() {
  export_published "$1" CREDENTIAL "$2"
  openssl x509 -inform DER -in "${WORK}/certs/$1.der" -outform PEM -out "${WORK}/certs/$1.pem" 2>/dev/null
}

# export_crl <label> <statusObjectId> -> certs/<label>.der + certs/<label>.pem (PEM CRL)
export_crl() {
  export_published "$1" STATUS_OBJECT "$2"
  openssl crl -inform DER -in "${WORK}/certs/$1.der" -outform PEM -out "${WORK}/certs/$1.pem" 2>/dev/null
}

# Inspect a completed CA certificate and wait only for its actual validity start.
# No mutating command is retried. The CLI itself remains fully synchronous.
inspect_ca() {
  local label="$1"
  run_op "${label}-certificate" credential.inspect --credential-id "$(field "${label}" credentialId)"
  python3 - "${WORK}/out/${label}-certificate.json" <<'PYWAIT'
import datetime, json, sys, time
with open(sys.argv[1]) as source:
    valid_from = datetime.datetime.fromisoformat(json.load(source)["steps"][0]["output"]["notBefore"].replace("Z", "+00:00")).timestamp()
deadline = time.monotonic() + 5
while valid_from > time.time():
    if time.monotonic() >= deadline:
        raise SystemExit("Issuer validity has not started within five seconds; stop without resubmitting")
    time.sleep(min(0.05, max(0, valid_from - time.time())))
PYWAIT
}

# These fresh-store scenarios create exactly one intermediate. A credential's
# authorityId identifies its issuer, so discover the new subject CA in inventory.
intermediate_ca() {
  "${ZE}" pki ca.list --config "${CONFIG}" --output json --limit 50 > "${WORK}/out/ca-inventory.json"
  python3 - "${WORK}/out/ca-inventory.json" <<'PYCA'
import json, sys
with open(sys.argv[1]) as source:
    authorities = json.load(source)["steps"][0]["output"]["authorities"]
children = [row["caId"] for row in authorities if row["kind"] == "INTERMEDIATE"]
if len(children) != 1:
    raise SystemExit("Expected exactly one intermediate in the fresh demo store")
print(children[0])
PYCA
}

# run_plan <name>: retains the full receipt, then exposes step outputs to field().
run_plan() {
  local name="$1" code=0
  "${ZE}" pki run "${WORK}/${name}.json" --config "${CONFIG}" --output json > "${WORK}/out/${name}.json" || code=$?
  if (( code != 0 )); then
    echo "ABORT: plan ${name} exited ${code}; receipt retained in ${WORK}/out/${name}.json" >&2
    exit "${code}"
  fi
  python3 - "${WORK}/out/${name}.json" "${WORK}/out" <<'PYSTEPS'
import json, pathlib, sys
with open(sys.argv[1]) as source:
    result = json.load(source)
for step in result["steps"]:
    with open(pathlib.Path(sys.argv[2]) / (step["id"] + ".json"), "w") as target:
        json.dump({"steps": [step]}, target)
PYSTEPS
}

pki_demo_setup() {
  local here work
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  ZE_HOME="${ZE_HOME:-$(cd "${here}/../../.." && pwd)/app/build/install/app}"
  ZE="${ZE_HOME}/bin/app"
  : "${ZEROECHO_KEYRING_PASSWORD:?Set a nonempty demo keyring password in the environment}"
  export ZEROECHO_KEYRING_PASSWORD
  umask 077
  WORK="${1:-$(mktemp -d)}"
  mkdir -p "${WORK}"
  WORK="$(cd "${WORK}" && pwd)"
  if [[ -n "$(ls -A "${WORK}")" ]]; then
    echo "ABORT: choose an empty work directory" >&2
    exit 2
  fi
  chmod 700 "${WORK}"
  CONFIG="${WORK}/config.json"

  echo "launcher : ${ZE}"
  echo "workdir  : ${WORK}"
  mkdir -p "${WORK}"/{store,published,profiles,csr,out,keyring,certs}
  chmod 700 "${WORK}/keyring"          # keyring parent must be owner-only (0700)
  KEYRING="${WORK}/keyring/ca-keyring.zek"

  # 1. Seed CA keyring (root + intermediate + a second root for cross-signing).
  local alias
  for alias in root intermediate root-b; do
    "${ZE}" -K --generate --alg RSA --alias "${alias}" --keystore "${KEYRING}" \
            --keystore-password-env ZEROECHO_KEYRING_PASSWORD >/dev/null
  done

  # 2. Explicit local configuration; JSON encoding also handles unusual paths.
  python3 - "${CONFIG}" "${WORK}" "${KEYRING}" <<'PYCONFIG'
import json, pathlib, sys
work = pathlib.Path(sys.argv[2])
configuration = {
    "version": 1, "mode": "local", "operatorId": "demo-local-root",
    "store": {"provider": "fs", "properties": {"root": str(work / "store")}},
    "audit": {"provider": "memory", "properties": {"size": "512"}},
    "signing": {
        "provider": {"provider": "zeroecho-lib", "properties": {"keyringPath": sys.argv[3]}},
        "signatureAlgorithm": "zealg:2:9:signature8:zeroecho14:rsa-pkcs1-v1_516:zeroecho.builtin39:ZGlnZXN0PXplcm9lY2hvLnNoYTItMjU2Lm5vbmU", "signingTtlSeconds": 30,
        "unlockEnvironmentVariable": "ZEROECHO_KEYRING_PASSWORD",
        "claimLeaseMillis": 30000, "providerCallTimeoutMillis": 20000
    },
    "publishers": [{"provider": "filesystem", "properties": {"root": str(work / "published"), "targetId": "local"}}],
    "bindingProviders": []
}
with open(sys.argv[1], "w") as target:
    json.dump(configuration, target, indent=2)
PYCONFIG

  # 3. Certificate profiles (practice-usable definitions).
  cat > "${WORK}/profiles/root-ca.json" <<'JSON'
{"schemaVersion":5,"certificateType":"ROOT_CA","profileId":"root-ca","profileVersion":1,"formatId":"x509","displayName":"Root CA","maxValidity":"PT87600H","approvalRequirement":"NONE","algorithmBindings":{"mode":"STANDARD_ONLY"},"subject":{"allowEmpty":false,"rules":[{"oid":"2.5.4.3","source":"REQUESTER","minimumOccurrences":1,"maximumOccurrences":1,"maximumUtf8Bytes":253}]},"caCertificate":{"basicConstraintsCritical":true,"pathLengthConstraint":1,"keyUsageCritical":true,"keyUsages":["CRL_SIGN","KEY_CERT_SIGN"],"allowedSubjectKeyAlgorithms":["ECDSA","Ed25519","RSA"]}}
JSON
  cat > "${WORK}/profiles/intermediate-ca.json" <<'JSON'
{"schemaVersion":5,"certificateType":"INTERMEDIATE_CA","profileId":"intermediate-ca","profileVersion":1,"formatId":"x509","displayName":"Intermediate CA","maxValidity":"PT43800H","approvalRequirement":"NONE","algorithmBindings":{"mode":"STANDARD_ONLY"},"subject":{"allowEmpty":false,"rules":[{"oid":"2.5.4.3","source":"REQUESTER","minimumOccurrences":1,"maximumOccurrences":1,"maximumUtf8Bytes":253}]},"caCertificate":{"basicConstraintsCritical":true,"pathLengthConstraint":0,"keyUsageCritical":true,"keyUsages":["CRL_SIGN","KEY_CERT_SIGN"],"allowedSubjectKeyAlgorithms":["ECDSA","Ed25519","RSA"]}}
JSON
  cat > "${WORK}/profiles/server-tls.json" <<'JSON'
{"schemaVersion":5,"certificateType":"END_ENTITY","profileId":"server-tls","profileVersion":1,"formatId":"x509","displayName":"Server TLS","maxValidity":"PT8760H","approvalRequirement":"NONE","algorithmBindings":{"mode":"STANDARD_ONLY"},"confirmationPolicy":{"disclosurePolicy":"OWNER_ONLY","confirmationWindow":"PT24H","proofSuiteId":"zeroecho.signature-pop.v1","proofSuiteCommitment":"5ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11","policyCommitment":"4933b3d9a9dd31b972d5835884ed8ef9218f8d331928e6ac0feb802d28ab9a30"},"subject":{"allowEmpty":true,"rules":[{"oid":"2.5.4.3","source":"REQUESTER","minimumOccurrences":0,"maximumOccurrences":1,"maximumUtf8Bytes":253}]},"subjectAlternativeNames":{"minimumTotal":1,"maximumTotal":64,"serviceIdentityRequired":true,"emailIdentityRequired":false,"criticalWhenSubjectNonEmpty":false,"rules":[{"type":"DNS_NAME","minimumOccurrences":0,"maximumOccurrences":64,"wildcardAllowed":false},{"type":"IP_ADDRESS","minimumOccurrences":0,"maximumOccurrences":16,"ipv4Allowed":true,"ipv6Allowed":true}]},"leafCertificate":{"basicConstraintsCritical":true,"keyUsageCritical":true,"keyUsage":["DIGITAL_SIGNATURE"],"extendedKeyUsageCritical":false,"extendedKeyUsage":["1.3.6.1.5.5.7.3.1"],"allowedKeyAlgorithms":["ECDSA","Ed25519","RSA"]}}
JSON
  cat > "${WORK}/profiles/vpn-server.json" <<'JSON'
{"schemaVersion":5,"certificateType":"END_ENTITY","profileId":"vpn-server","profileVersion":1,"formatId":"x509","displayName":"VPN Server","maxValidity":"PT8760H","approvalRequirement":"NONE","algorithmBindings":{"mode":"STANDARD_ONLY"},"confirmationPolicy":{"disclosurePolicy":"OWNER_ONLY","confirmationWindow":"PT24H","proofSuiteId":"zeroecho.signature-pop.v1","proofSuiteCommitment":"5ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11","policyCommitment":"4933b3d9a9dd31b972d5835884ed8ef9218f8d331928e6ac0feb802d28ab9a30"},"subject":{"allowEmpty":true,"rules":[{"oid":"2.5.4.3","source":"REQUESTER","minimumOccurrences":0,"maximumOccurrences":1,"maximumUtf8Bytes":253}]},"subjectAlternativeNames":{"minimumTotal":1,"maximumTotal":64,"serviceIdentityRequired":true,"emailIdentityRequired":false,"criticalWhenSubjectNonEmpty":false,"rules":[{"type":"DNS_NAME","minimumOccurrences":0,"maximumOccurrences":64,"wildcardAllowed":false},{"type":"IP_ADDRESS","minimumOccurrences":0,"maximumOccurrences":16,"ipv4Allowed":true,"ipv6Allowed":true}]},"leafCertificate":{"basicConstraintsCritical":true,"keyUsageCritical":true,"keyUsage":["DIGITAL_SIGNATURE"],"extendedKeyUsageCritical":false,"extendedKeyUsage":["1.3.6.1.5.5.7.3.1"],"allowedKeyAlgorithms":["ECDSA","Ed25519","RSA"]}}
JSON
  cat > "${WORK}/profiles/vpn-client.json" <<'JSON'
{"schemaVersion":5,"certificateType":"END_ENTITY","profileId":"vpn-client","profileVersion":1,"formatId":"x509","displayName":"VPN Client","maxValidity":"PT8760H","approvalRequirement":"NONE","algorithmBindings":{"mode":"STANDARD_ONLY"},"confirmationPolicy":{"disclosurePolicy":"OWNER_ONLY","confirmationWindow":"PT24H","proofSuiteId":"zeroecho.signature-pop.v1","proofSuiteCommitment":"5ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11","policyCommitment":"4933b3d9a9dd31b972d5835884ed8ef9218f8d331928e6ac0feb802d28ab9a30"},"subject":{"allowEmpty":true,"rules":[{"oid":"2.5.4.3","source":"REQUESTER","minimumOccurrences":0,"maximumOccurrences":1,"maximumUtf8Bytes":253}]},"subjectAlternativeNames":{"minimumTotal":1,"maximumTotal":16,"serviceIdentityRequired":false,"emailIdentityRequired":false,"criticalWhenSubjectNonEmpty":false,"rules":[{"type":"RFC822_NAME","minimumOccurrences":0,"maximumOccurrences":16},{"type":"URI","minimumOccurrences":0,"maximumOccurrences":16,"allowedSchemes":["spiffe"]}]},"leafCertificate":{"basicConstraintsCritical":true,"keyUsageCritical":true,"keyUsage":["DIGITAL_SIGNATURE"],"extendedKeyUsageCritical":false,"extendedKeyUsage":["1.3.6.1.5.5.7.3.2"],"allowedKeyAlgorithms":["ECDSA","Ed25519","RSA"]}}
JSON

  # 4. Subject key-pairs + PKCS#10 CSRs (DER). SAN IPs from RFC 5737; DNS from RFC 2606.
  _gen_csr web "web.example.com"   "DNS:web.example.com,IP:192.0.2.10"
  _gen_csr gtw "gtw.example.com"   "DNS:gtw.example.com,IP:192.0.2.20"
  _gen_csr rw  "roadwarrior.alice" "email:alice@example.com,URI:spiffe://example.com/vpn/alice"

  export ZE WORK KEYRING CONFIG
}

_gen_csr() { # <name> <subject-CN> <san>
  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "${WORK}/csr/$1.key.pem" -subj "/CN=$2" -addext "subjectAltName=$3" \
    -outform DER -out "${WORK}/csr/$1.csr.der" >/dev/null 2>&1
}
