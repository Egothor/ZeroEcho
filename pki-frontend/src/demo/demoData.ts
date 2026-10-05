/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgement:
 *    This product includes software developed by the Egothor project.
 *
 * 4. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

/**
 * In-memory demo dataset. Representative, believable records so a reviewer can
 * walk every screen without a live server. Mutations during a demo session
 * append to these collections; reloading resets them.
 */

export interface DemoState {
  [collection: string]: Record<string, unknown>[];
}

let counter = 1000;
export function demoId(prefix: string): string {
  counter += 1;
  return `${prefix}-${counter.toString(36)}`;
}

export function createDemoState(): DemoState {
  return {
    authorities: [
      { caId: 'ca-root-01', subject: 'CN=ZeroEcho Root CA, O=ZeroEcho', state: 'ACTIVE', kind: 'ROOT', profileId: 'root-ca-v1' },
      { caId: 'ca-tls-issuing-01', subject: 'CN=ZeroEcho TLS Issuing CA', state: 'ACTIVE', kind: 'INTERMEDIATE', profileId: 'tls-issuing-v2' },
      { caId: 'ca-devices-01', subject: 'CN=ZeroEcho Device CA', state: 'ACTIVE', kind: 'INTERMEDIATE', profileId: 'device-v1' },
      { caId: 'ca-pqc-root-01', subject: 'CN=ZeroEcho PQC Root CA, O=ZeroEcho', state: 'ACTIVE', kind: 'ROOT', profileId: 'pqc-root-v1', displayName: 'PQC Root CA (ML-DSA-65)' },
      { caId: 'ca-legacy-01', subject: 'CN=ZeroEcho Legacy CA', state: 'RETIRED', kind: 'INTERMEDIATE', profileId: 'tls-issuing-v1' },
    ],
    generations: [
      { issuerId: 'gen-01', authorityId: 'ca-tls-issuing-01', credentialId: 'cred-9f01', state: 'ACTIVE', profileId: 'tls-server-v3' },
      { issuerId: 'gen-root', authorityId: 'ca-root-01', state: 'ACTIVE', profileId: 'root-ca-v1' },
    ],
    capabilities: [{ capabilityId: 'cap-01', objectId: 'cred-9f01', expiresAt: '2027-01-01T00:00:00Z', revoked: false }],
    chainPaths: [
      { pathId: 'path-root', issuerId: 'gen-root', hops: 1 },
      { pathId: 'path-01', issuerId: 'gen-01', hops: 2, active: true },
      { pathId: 'path-02', issuerId: 'gen-02', hops: 2, active: false },
    ],
    profiles: [
      { profileId: 'root-ca-v1', displayName: 'Root authority', formatId: 'x509', profileVersion: 1, active: true, publicKeyAlgorithms: ['EC'], x509BindingPolicies: ['sha256-ecdsa'] },
      { profileId: 'tls-server-v3', displayName: 'TLS server certificate', formatId: 'x509', profileVersion: 3, publicKeyAlgorithms: ['EC'], x509BindingPolicies: ['sha256-ecdsa'], maximumValidity: 'PT24H', active: true, keyUsage: 'digitalSignature,keyEncipherment', eku: 'serverAuth' },
      { profileId: 'tls-client-v2', displayName: 'TLS client certificate', formatId: 'x509', profileVersion: 2, publicKeyAlgorithms: ['EC'], x509BindingPolicies: ['sha256-ecdsa'], maximumValidity: 'PT24H', active: true, keyUsage: 'digitalSignature', eku: 'clientAuth' },
      { profileId: 'code-signing-v1', profileVersion: 1, active: false, keyUsage: 'digitalSignature', eku: 'codeSigning' },
    ],
    requests: [
      { formatId: 'x509', requestId: 'req-1a2b', subject: 'CN=web01.example.org', keyAlgorithm: 'EC P-256', state: 'IMPORTED' },
      { formatId: 'x509', requestId: 'req-3c4d', subject: 'CN=api.example.org', keyAlgorithm: 'RSA 3072', state: 'VERIFIED' },
    ],
    credentials: [
      { credentialId: 'cred-9f01', subject: 'CN=web01.example.org', serial: '0x4a2f...', state: 'VALID', notAfter: '2027-03-01T00:00:00Z', authorityId: 'ca-tls-issuing-01', issuerId: 'gen-01', issuerCaId: 'ca-tls-issuing-01' },
      { credentialId: 'cred-9f02', subject: 'CN=api.example.org', serial: '0x77b1...', state: 'VALID', notAfter: '2027-04-15T00:00:00Z', authorityId: 'ca-tls-issuing-01', issuerId: 'gen-01', issuerCaId: 'ca-tls-issuing-01' },
      { credentialId: 'cred-8801', subject: 'CN=old.example.org', serial: '0x1200...', state: 'REVOKED', notAfter: '2026-01-01T00:00:00Z', issuerCaId: 'ca-legacy-01' },
    ],
    statusObjects: [
      { statusObjectId: 'crl-tls-014', type: 'CRL', crlNumber: 14, authorityId: 'ca-tls-issuing-01', issuerId: 'gen-01', issuerCaId: 'ca-tls-issuing-01', producedAt: '2026-09-06T00:00:00Z' },
      { statusObjectId: 'crl-tls-013', type: 'CRL', crlNumber: 13, authorityId: 'ca-tls-issuing-01', issuerId: 'gen-01', issuerCaId: 'ca-tls-issuing-01', producedAt: '2026-08-30T00:00:00Z' },
    ],
    publications: [
      { publicationId: 'pub-01', sourceType: 'STATUS_OBJECT', targetType: 'FILESYSTEM', status: 'PUBLISHED' },
      { publicationId: 'pub-02', sourceType: 'CREDENTIAL', targetType: 'HTTP', status: 'PENDING' },
    ],
    principals: [
      { principalId: 'alice', type: 'USER', displayName: 'Alice Admin', enabled: true },
      { principalId: 'bob', type: 'USER', displayName: 'Bob Operator', enabled: true },
      { principalId: 'svc-ci', type: 'SERVICE', displayName: 'CI Pipeline', enabled: true },
    ],
    roleTemplates: [
      { templateId: 'realm-administrator', version: 1 },
      { templateId: 'issuance-operator', version: 2 },
      { templateId: 'auditor', version: 1 },
    ],
    roleAssignments: [
      { assignmentId: 'ra-01', principalId: 'alice', templateId: 'realm-administrator', templateVersion: 1 },
      { assignmentId: 'ra-02', principalId: 'bob', templateId: 'issuance-operator', templateVersion: 2 },
    ],
    grants: [
      { grantId: 'g-01', principalId: 'bob', effect: 'ALLOW', action: 'CERTIFICATE_ISSUE', resourceType: 'CERTIFICATE', relationship: 'ANY' },
      { grantId: 'g-02', principalId: 'svc-ci', effect: 'ALLOW', action: 'REQUEST_SUBMIT', resourceType: 'REQUEST', relationship: 'OWN' },
    ],
    approvals: [
      { approvalId: 'ap-01', operation: 'ca.rotate', state: 'PENDING', requesterId: 'bob' },
      { approvalId: 'ap-02', operation: 'profile.activate', state: 'APPROVED', requesterId: 'alice' },
    ],
    breakGlass: [{ breakGlassId: 'bg-01', principalId: 'alice', state: 'REVOKED', reason: 'DR rehearsal' }],
    repositoryAliases: [
      { authorityId: 'ca-tls-issuing-01', recordCommitment: 'c'.repeat(64), type: 'CURRENT_CRL', state: 'ACTIVE', targetObjectId: 'crl-tls-014' },
    ],
    acmeDirectories: [
      { directoryId: 'acme-tls', alias: 'tls', authorityId: 'ca-tls-issuing-01', state: 'ACTIVE', eabRequired: false },
    ],
    acmeAccounts: [{ accountId: 'acct-01', state: 'valid', contact: 'mailto:ops@example.org' }],
    ocspResponders: [
      { responderId: 'ocsp-tls', alias: 'tls', authorityId: 'ca-tls-issuing-01', state: 'ACTIVE', signingMode: 'DELEGATED_RESPONDER' },
    ],
    scepEndpoints: [
      { label: 'devices', authorityId: 'ca-devices-01', profileId: 'device-v1', challengePasswordHash: 'e3b0c44298fc1c149afb' },
    ],
    cmpEndpoints: [
      { label: 'tls-servers', authorityId: 'ca-tls-issuing-01', profileId: 'tls-server-v3', protectionPolicy: 'SHARED_SECRET' },
    ],
    estEndpoints: [
      { label: 'tls-clients', authorityId: 'ca-tls-issuing-01', profileId: 'tls-client-v2', keygenEnabled: false, keygenAlgorithms: [], keygenMaxKeySizeBits: 0, keygenStoreKeys: false },
    ],
    enrollmentProfiles: [
      { id: 'device-enroll-v1', displayName: 'Device enrollment (v1)', state: 'ACTIVE', certificateProfileId: 'device-v1', allowedAuthorityIds: ['ca-devices-01'], subjectDnPattern: 'CN=device-.+', requiredSanDomains: [], requireApproval: false },
      { id: 'tls-server-enroll-v1', displayName: 'TLS server enrollment (v1)', state: 'ACTIVE', certificateProfileId: 'tls-server-v3', allowedAuthorityIds: [], subjectDnPattern: '', requiredSanDomains: ['example.org'], requireApproval: true },
      { id: 'pqc-enroll-v1', displayName: 'PQC device enrollment (v1)', state: 'SUSPENDED', certificateProfileId: 'pqc-root-v1', allowedAuthorityIds: ['ca-pqc-root-01'], subjectDnPattern: '', requiredSanDomains: [], requireApproval: false },
    ],
    algorithmBindings: [
      { bindingId: 'sha256-ecdsa', origin: 'default', role: 'signing', bindingCommitment: 'a'.repeat(64), algorithmId: 'SHA256withECDSA' },
      { bindingId: 'sha384-ecdsa', origin: 'default', role: 'signing', bindingCommitment: 'a'.repeat(64), algorithmId: 'SHA384withECDSA' },
    ],
    auditRecords: [
      { sequence: 1042, category: 'ISSUANCE', action: 'CERTIFICATE_ISSUE', principalName: 'bob', at: '2026-09-06T10:12:04Z', objectId: 'cred-9f02' },
      { sequence: 1041, category: 'REVOCATION', action: 'CERTIFICATE_REVOKE', principalName: 'alice', at: '2026-09-05T16:44:51Z', objectId: 'cred-8801' },
      { sequence: 1040, category: 'AUTHORITY', action: 'AUTHORITY_CREATE', principalName: 'alice', at: '2026-09-01T09:00:00Z', objectId: 'ca-devices-01' },
    ],
    revocationHistory: [
      { credentialId: 'cred-8801', reason: 'SUPERSEDED', revokedAt: '2026-01-02T00:00:00Z', principalName: 'alice' },
    ],
    revocations: [
      { credentialId: 'cred-8801', serial: '0x1200...', reason: 'SUPERSEDED', revokedAt: '2026-01-02T00:00:00Z', crlNumber: 14 },
    ],
    pendingConfirmations: [
      { credentialId: 'cred-9f01', profileId: 'tls-server-v3', challengeIssuedAt: '2026-09-06T10:00:00Z', state: 'PENDING' },
    ],
  };
}
