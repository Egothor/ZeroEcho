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
# ZeroEcho PKI CLI — minimal worked scenario (single batch)
#
# Fictional org "Example s.r.o." issues, from a two-tier CA, three real X.509
# leaf certificates and then revokes one:
#   a) HTTPS service on host "web"      (profile server-tls,  EKU serverAuth)
#   b) IPsec gateway "gtw"              (profile vpn-server,   EKU serverAuth)
#   c) IPsec road-warrior client cert   (profile vpn-client,   EKU clientAuth)
# then revokes (c) with reason KEY_COMPROMISE ("odcizení") and publishes a CRL.
#
# The whole chain runs as ONE `zeroecho pki run <plan>` batch — the practical
# "sign a whole series of certificates in one operator run" model.
#
# Prerequisites performed here (outside the PKI operation set, exactly like an
# openssl-based CA setup): CA key generation into a keyring (via `zeroecho -K`),
# and subject key-pair + PKCS#10 CSR generation (via openssl). The PKI CLI does
# not mint private keys — subjects hold their own keys and submit CSRs.
#
# Usage:  ZE_HOME=<dir with bin/app> ./demo-minimal.sh [workdir]
# Requires: openssl on PATH; a built ZeroEcho app distribution.
###############################################################################
set -euo pipefail

# Some distributions ship openssl under /usr/sbin; make sure it is reachable.
case ":${PATH}:" in *:/usr/sbin:*) ;; *) PATH="${PATH}:/usr/sbin" ;; esac
export PATH

ZE_HOME="${ZE_HOME:-$(cd "$(dirname "$0")/../../.." && pwd)/app/build/install/app}"
ZE="${ZE_HOME}/bin/app"
WORK="${1:-$(mktemp -d)}"
export ZEROECHO_KEYRING_PASSWORD="demo-keyring-passphrase-change-me"

echo "== ZeroEcho PKI CLI minimal demo =="
echo "launcher : ${ZE}"
echo "workdir  : ${WORK}"
mkdir -p "${WORK}"/{store,published,profiles,csr,out,keyring,certs}
# The keyring's parent directory must be owner-only (0700), as the keyring store requires.
chmod 700 "${WORK}/keyring"
KEYRING="${WORK}/keyring/ca-keyring.zek"

# --- 1. Seed the CA keyring (root + intermediate private keys) --------------
# Non-interactive via the env-var unlock added for scripted keyring management.
"${ZE}" -K --generate --alg RSA --alias root         --keystore "${KEYRING}" \
        --keystore-password-env ZEROECHO_KEYRING_PASSWORD
"${ZE}" -K --generate --alg RSA --alias intermediate --keystore "${KEYRING}" \
        --keystore-password-env ZEROECHO_KEYRING_PASSWORD

# --- 2. Session configuration (fs store + zeroecho-lib signer + fs publisher)
cat > "${WORK}/config.json" <<JSON
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

# --- 3. Certificate profiles (real practice-usable definitions) -------------
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

# --- 4. Subject key-pairs + PKCS#10 CSRs (DER) via openssl ------------------
# SAN IPs from the RFC 5737 documentation range; DNS from the RFC 2606 example domain.
gen_csr() { # <name> <subject-CN> <san>
  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "${WORK}/csr/$1.key.pem" -subj "/CN=$2" -addext "subjectAltName=$3" \
    -outform DER -out "${WORK}/csr/$1.csr.der" >/dev/null 2>&1
}
gen_csr web "web.example.com"      "DNS:web.example.com,IP:192.0.2.10"
gen_csr gtw "gtw.example.com"      "DNS:gtw.example.com,IP:192.0.2.20"
gen_csr rw  "roadwarrior.alice"    "email:alice@example.com,URI:spiffe://example.com/vpn/alice"

# --- 5. The single batch plan ----------------------------------------------
cat > "${WORK}/plan-minimal.json" <<JSON
{"version":1,"failurePolicy":"FAIL_FAST","operations":[
  {"id":"preg-root","operation":"profile.register","arguments":{"profileFile":"${WORK}/profiles/root-ca.json"}},
  {"id":"pact-root","operation":"profile.activate","arguments":{"profileId":"root-ca","profileVersion":1}},
  {"id":"preg-inter","operation":"profile.register","arguments":{"profileFile":"${WORK}/profiles/intermediate-ca.json"}},
  {"id":"pact-inter","operation":"profile.activate","arguments":{"profileId":"intermediate-ca","profileVersion":1}},
  {"id":"preg-srv","operation":"profile.register","arguments":{"profileFile":"${WORK}/profiles/server-tls.json"}},
  {"id":"pact-srv","operation":"profile.activate","arguments":{"profileId":"server-tls","profileVersion":1}},
  {"id":"preg-vpns","operation":"profile.register","arguments":{"profileFile":"${WORK}/profiles/vpn-server.json"}},
  {"id":"pact-vpns","operation":"profile.activate","arguments":{"profileId":"vpn-server","profileVersion":1}},
  {"id":"preg-vpnc","operation":"profile.register","arguments":{"profileFile":"${WORK}/profiles/vpn-client.json"}},
  {"id":"pact-vpnc","operation":"profile.activate","arguments":{"profileId":"vpn-client","profileVersion":1}},

  {"id":"root","operation":"ca.create","arguments":{"formatId":"x509","subjectRef":"CN=Example Root CA","profileId":"root-ca","keyRef":"zeroecho-lib:root.prv"}},
  {"id":"inter","operation":"ca.intermediate.create","arguments":{"formatId":"x509","issuerCaId":"\${root.caId}","subjectRef":"CN=Example Issuing CA","profileId":"intermediate-ca","keyRef":"zeroecho-lib:intermediate.prv"}},

  {"id":"csr-web","operation":"request.import","arguments":{"formatId":"x509","encoding":"DER","requestFile":"${WORK}/csr/web.csr.der"}},
  {"id":"web","operation":"credential.issue","arguments":{"issuerCaId":"\${inter.caId}","requestId":"\${csr-web.requestId}","profileId":"server-tls"}},

  {"id":"csr-gtw","operation":"request.import","arguments":{"formatId":"x509","encoding":"DER","requestFile":"${WORK}/csr/gtw.csr.der"}},
  {"id":"gtw","operation":"credential.issue","arguments":{"issuerCaId":"\${inter.caId}","requestId":"\${csr-gtw.requestId}","profileId":"vpn-server"}},

  {"id":"csr-rw","operation":"request.import","arguments":{"formatId":"x509","encoding":"DER","requestFile":"${WORK}/csr/rw.csr.der"}},
  {"id":"rw","operation":"credential.issue","arguments":{"issuerCaId":"\${inter.caId}","requestId":"\${csr-rw.requestId}","profileId":"vpn-client"}},

  {"id":"revoke","operation":"credential.revoke","arguments":{"credentialId":"\${rw.credentialId}","reason":"KEY_COMPROMISE","justification":"stolen-laptop-INC-42"}},

  {"id":"crl","operation":"status.generate","arguments":{"issuerCaId":"\${inter.caId}","type":"CRL","formatId":"x509"}},
  {"id":"pub-crl","operation":"publication.register","arguments":{"publicationId":"crl-pub-1","sourceType":"STATUS_OBJECT","sourceId":"\${crl.statusObjectId}","targetType":"FILESYSTEM","targetId":"local"}},
  {"id":"proc-crl","operation":"publication.process","arguments":{"publicationId":"\${pub-crl.publicationId}"}},

  {"id":"root-inspect","operation":"ca.inspect","arguments":{"caId":"\${root.caId}"}},
  {"id":"root-gen","operation":"issuer.generation.inspect","arguments":{"issuerId":"\${root-inspect.currentIssuanceIssuerId}"}},
  {"id":"inter-inspect","operation":"ca.inspect","arguments":{"caId":"\${inter.caId}"}},
  {"id":"inter-gen","operation":"issuer.generation.inspect","arguments":{"issuerId":"\${inter-inspect.currentIssuanceIssuerId}"}},

  {"id":"pub-root","operation":"publication.register","arguments":{"publicationId":"cert-root","sourceType":"CREDENTIAL","sourceId":"\${root-gen.credentialId}","targetType":"FILESYSTEM","targetId":"local"}},
  {"id":"proc-root","operation":"publication.process","arguments":{"publicationId":"\${pub-root.publicationId}"}},
  {"id":"pub-inter","operation":"publication.register","arguments":{"publicationId":"cert-inter","sourceType":"CREDENTIAL","sourceId":"\${inter-gen.credentialId}","targetType":"FILESYSTEM","targetId":"local"}},
  {"id":"proc-inter","operation":"publication.process","arguments":{"publicationId":"\${pub-inter.publicationId}"}},
  {"id":"pub-web","operation":"publication.register","arguments":{"publicationId":"cert-web","sourceType":"CREDENTIAL","sourceId":"\${web.credentialId}","targetType":"FILESYSTEM","targetId":"local"}},
  {"id":"proc-web","operation":"publication.process","arguments":{"publicationId":"\${pub-web.publicationId}"}},
  {"id":"pub-gtw","operation":"publication.register","arguments":{"publicationId":"cert-gtw","sourceType":"CREDENTIAL","sourceId":"\${gtw.credentialId}","targetType":"FILESYSTEM","targetId":"local"}},
  {"id":"proc-gtw","operation":"publication.process","arguments":{"publicationId":"\${pub-gtw.publicationId}"}},
  {"id":"pub-rw","operation":"publication.register","arguments":{"publicationId":"cert-rw","sourceType":"CREDENTIAL","sourceId":"\${rw.credentialId}","targetType":"FILESYSTEM","targetId":"local"}},
  {"id":"proc-rw","operation":"publication.process","arguments":{"publicationId":"\${pub-rw.publicationId}"}}
]}
JSON

# --- 6. Run the whole batch in one CLI invocation --------------------------
echo "== running batch plan =="
"${ZE}" pki run "${WORK}/plan-minimal.json" --config "${WORK}/config.json" --output json \
        | tee "${WORK}/out/result.json"

# --- 7. Copy the published bytes to friendly, openssl-readable files ---------
# The filesystem publisher stores each object as sha256(publicationId).bin; we
# recompute that name and copy it to certs/<name>.der, then convert to PEM.
copy_published() { # <publicationId> <out-name> <x509|crl>
  local hash; hash="$(printf '%s' "$1" | sha256sum | cut -d' ' -f1)"
  cp "${WORK}/published/${hash}.bin" "${WORK}/certs/$2.der"
  if [ "$3" = "crl" ]; then
    openssl crl  -inform DER -in "${WORK}/certs/$2.der" -outform PEM -out "${WORK}/certs/$2.pem" 2>/dev/null
  else
    openssl x509 -inform DER -in "${WORK}/certs/$2.der" -outform PEM -out "${WORK}/certs/$2.pem" 2>/dev/null
  fi
}
copy_published cert-root  root-ca      x509
copy_published cert-inter issuing-ca   x509
copy_published cert-web   web          x509
copy_published cert-gtw   gtw          x509
copy_published cert-rw    road-warrior x509
copy_published crl-pub-1  crl          crl

echo
echo "== done. inspectable artifacts in ${WORK}/certs =="
ls -1 "${WORK}/certs"
echo
echo "Inspect, for example:"
echo "  openssl x509 -in ${WORK}/certs/web.pem -noout -subject -issuer -ext subjectAltName,extendedKeyUsage"
echo "  openssl crl  -in ${WORK}/certs/crl.pem -noout -text | head"
echo "workdir: ${WORK}"
