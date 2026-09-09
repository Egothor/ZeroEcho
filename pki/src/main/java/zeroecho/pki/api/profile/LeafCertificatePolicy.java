/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
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
package zeroecho.pki.api.profile;

import java.util.Set;

/**
 * Complete issuer-controlled leaf certificate extension and identity policy.
 *
 * @param subjectAlternativeNamePolicy  SAN policy
 * @param keyUsages                     exact key-usage set
 * @param extendedKeyUsages             exact extended-key-usage set
 * @param keyUsageCritical              key-usage criticality
 * @param extendedKeyUsageCritical      extended-key-usage criticality
 * @param basicConstraintsCritical      BasicConstraints criticality
 * @param allowedSubjectKeyAlgorithmIds exact canonical ZeroEcho key algorithm
 *                                      identifiers
 */
// The algorithm-set component name is an exported accessor and configuration vocabulary term.
@SuppressWarnings("PMD.LongVariable")
public record LeafCertificatePolicy(SubjectAlternativeNamePolicy subjectAlternativeNamePolicy,
        Set<LeafKeyUsage> keyUsages, Set<ExtendedKeyUsageId> extendedKeyUsages, boolean keyUsageCritical,
        boolean extendedKeyUsageCritical, boolean basicConstraintsCritical, Set<String> allowedSubjectKeyAlgorithmIds)
        implements CertificatePolicy {

    private static final Set<String> SUPPORTED_KEY_ALGORITHMS = Set.of("RSA", "ECDSA", "Ed25519", "Ed448",
            "SPHINCS+");

    /**
     * Validates and constructs the policy.
     */
    public LeafCertificatePolicy {
        if (subjectAlternativeNamePolicy == null || keyUsages == null || extendedKeyUsages == null
                || allowedSubjectKeyAlgorithmIds == null) {
            throw new IllegalArgumentException("Leaf certificate policy values must not be null");
        }
        keyUsages = Set.copyOf(keyUsages);
        extendedKeyUsages = Set.copyOf(extendedKeyUsages);
        allowedSubjectKeyAlgorithmIds = Set.copyOf(allowedSubjectKeyAlgorithmIds);
        if (allowedSubjectKeyAlgorithmIds.isEmpty()
                || !SUPPORTED_KEY_ALGORITHMS.containsAll(allowedSubjectKeyAlgorithmIds)) {
            throw new IllegalArgumentException("At least one supported subject key algorithm is required");
        }
        if ((keyUsages.contains(LeafKeyUsage.ENCIPHER_ONLY) || keyUsages.contains(LeafKeyUsage.DECIPHER_ONLY))
                && !keyUsages.contains(LeafKeyUsage.KEY_AGREEMENT)) {
            throw new IllegalArgumentException("encipherOnly and decipherOnly require keyAgreement");
        }
    }
}
