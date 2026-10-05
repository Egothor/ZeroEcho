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

/** Display labels never replace the exact value submitted to the server. */
const LABELS: Readonly<Record<string, string>> = {
  caId: 'Certificate authority', issuerCaId: 'Issuing authority', subjectCaId: 'Subject authority',
  authorityId: 'Certificate authority', __authorityId: 'Certificate authority',
  issuerId: 'Issuer generation', profileId: 'Certificate profile', profileVersion: 'Profile version',
  requestId: 'Certificate request', credentialId: 'Certificate', existingCredentialId: 'Existing certificate',
  formatId: 'Certificate format', keyRef: 'Signing key', newKeyRef: 'New signing key',
  pathId: 'Certificate chain', parentPathId: 'Parent certificate chain', chainPathId: 'Certificate chain',
  subjectRef: 'Subject', statusObjectId: 'Revocation list', approvalId: 'Approval',
  principalId: 'Principal', templateId: 'Role template', assignmentId: 'Role assignment',
  grantId: 'Permission grant', publicationId: 'Publication', targetOperation: 'Operation to approve',
  PROFILE_MAXIMUM: 'Use profile maximum (up to 398 days)', CUSTOM: 'Set a shorter validity',
  CRL: 'Certificate revocation list (CRL)', DELTA_CRL: 'Delta certificate revocation list',
  DER: 'Binary ASN.1 (DER)', PEM: 'PEM text', X509: 'X.509',
  ISSUER_SIGNED: 'Signed by the issuing authority', DELEGATED_RESPONDER: 'Dedicated OCSP responder',
  SHA1: 'SHA-1', SHA256: 'SHA-256',
  // CMP protection policies
  SHARED_SECRET: 'Shared secret (password-based)', SIGNATURE: 'Signature (certificate-based)',
  // EST server-keygen policies
  DISABLED: 'Disabled (client key only)', OPTIONAL: 'Optional (client or server key)', REQUIRED: 'Required (server key only)',
  // PQC and hybrid algorithm identifiers
  'ML-DSA': 'ML-DSA (FIPS 204 — lattice)', 'ML-DSA-44': 'ML-DSA-44 (FIPS 204, ~128-bit)',
  'ML-DSA-65': 'ML-DSA-65 (FIPS 204, ~192-bit)', 'ML-DSA-87': 'ML-DSA-87 (FIPS 204, ~256-bit)',
  'SLH-DSA': 'SLH-DSA (FIPS 205 — hash-based)', 'SLH-DSA-SHA2-128s': 'SLH-DSA-SHA2-128s (FIPS 205)',
  'SLH-DSA-SHA2-128f': 'SLH-DSA-SHA2-128f (FIPS 205)', 'SLH-DSA-SHA2-192s': 'SLH-DSA-SHA2-192s (FIPS 205)',
  'SLH-DSA-SHA2-192f': 'SLH-DSA-SHA2-192f (FIPS 205)', 'SLH-DSA-SHA2-256s': 'SLH-DSA-SHA2-256s (FIPS 205)',
  'SLH-DSA-SHA2-256f': 'SLH-DSA-SHA2-256f (FIPS 205)',
  // Hybrid certificate modes
  NONE: 'Classic only (no hybrid)', ALT_SIGNATURE: 'Alt-signature (dual-signature hybrid, RFC 9618)',
  TWIN_CERTIFICATE: 'Twin certificate (dual-certificate hybrid)', COMPOSITE: 'Composite (combined key/signature)',
  // Enrollment profile states
  ACTIVE: 'Active', SUSPENDED: 'Suspended',
};

export function displayLabel(value: string): string {
  const known = LABELS[value];
  if (known) return known;
  const words = value.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]/g, ' ').toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Search both the readable name and the precise wire spelling. */
export function filterChoices(options: readonly string[], query: string): string[] {
  const search = query.toLowerCase();
  return options.filter((value) => value.toLowerCase().includes(search) || displayLabel(value).toLowerCase().includes(search));
}
