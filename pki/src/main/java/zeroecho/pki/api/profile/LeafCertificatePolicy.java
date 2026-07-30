/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
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
public record LeafCertificatePolicy(SubjectAlternativeNamePolicy subjectAlternativeNamePolicy,
        Set<LeafKeyUsage> keyUsages, Set<ExtendedKeyUsageId> extendedKeyUsages, boolean keyUsageCritical,
        boolean extendedKeyUsageCritical, boolean basicConstraintsCritical, Set<String> allowedSubjectKeyAlgorithmIds)
        implements CertificatePolicy {

    private static final Set<String> SUPPORTED_SUBJECT_KEY_ALGORITHMS = Set.of("RSA", "ECDSA", "Ed25519", "Ed448");

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
                || !SUPPORTED_SUBJECT_KEY_ALGORITHMS.containsAll(allowedSubjectKeyAlgorithmIds)) {
            throw new IllegalArgumentException("At least one supported subject key algorithm is required");
        }
        if ((keyUsages.contains(LeafKeyUsage.ENCIPHER_ONLY) || keyUsages.contains(LeafKeyUsage.DECIPHER_ONLY))
                && !keyUsages.contains(LeafKeyUsage.KEY_AGREEMENT)) {
            throw new IllegalArgumentException("encipherOnly and decipherOnly require keyAgreement");
        }
    }
}
