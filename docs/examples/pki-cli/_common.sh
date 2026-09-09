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
  "${ZE}" pki "${op}" --config "${CONFIG}" --output json "$@" > "${WORK}/out/${label}.json"
  local status
  status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "${WORK}/out/${label}.json")"
  printf '  %-16s %-26s %s\n' "${label}" "${op}" "${status}"
  [ "${status}" = "SUCCEEDED" ] || { echo "ABORT: ${op} -> ${status}"; cat "${WORK}/out/${label}.json"; exit 1; }
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

# ca_cert_credential <caId> -> echoes the CA's current issuance credentialId (quiet, for $(...))
ca_cert_credential() {
  "${ZE}" pki ca.inspect --config "${CONFIG}" --output json --ca-id "$1" >"${WORK}/out/_cainsp.json" 2>/dev/null
  local issuer; issuer="$(json_field "${WORK}/out/_cainsp.json" 0 currentIssuanceIssuerId)"
  "${ZE}" pki issuer.generation.inspect --config "${CONFIG}" --output json \
    --issuer-id "${issuer}" >"${WORK}/out/_geninsp.json" 2>/dev/null
  json_field "${WORK}/out/_geninsp.json" 0 credentialId
}

pki_demo_setup() {
  local here work
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  ZE_HOME="${ZE_HOME:-$(cd "${here}/../../.." && pwd)/app/build/install/app}"
  ZE="${ZE_HOME}/bin/app"
  WORK="${1:-$(mktemp -d)}"
  CONFIG="${WORK}/config.json"
  export ZEROECHO_KEYRING_PASSWORD="${ZEROECHO_KEYRING_PASSWORD:-demo-keyring-passphrase-change-me}"

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

  # 2. Session configuration.
  cat > "${CONFIG}" <<JSON
{
  "version": 2,
  "store":  { "provider": "fs",     "properties": { "root": "${WORK}/store" } },
  "audit":  { "provider": "memory", "properties": { "size": "512" } },
  "signing": {
    "workflow":  { "provider": "zeroecho-lib", "properties": { "keyringPath": "${KEYRING}" } },
    "framework": { "provider": "x509-bc", "properties": {} },
    "signatureAlgorithm": "SHA256withRSA",
    "signingTtlSeconds": 30,
    "unlockEnvironmentVariable": "ZEROECHO_KEYRING_PASSWORD"
  },
  "publishers": [
    { "provider": "filesystem", "properties": { "root": "${WORK}/published", "targetId": "local" } }
  ]
}
JSON

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
