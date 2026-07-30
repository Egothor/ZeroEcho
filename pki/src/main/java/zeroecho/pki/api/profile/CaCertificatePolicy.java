/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

import java.util.Set;

/**
 * Immutable issuer-controlled CA certificate policy.
 *
 * <p>
 * CA status is always {@code true}. Basic Constraints and Key Usage are always
 * critical. SAN and EKU are not representable for CA profiles. Subject and
 * authority key identifiers, when emitted by a CA implementation, remain fixed
 * repository invariants rather than configurable profile values.
 * </p>
 *
 * @param basicConstraintsCritical      Basic Constraints criticality, required
 *                                      to be {@code true}
 * @param pathLengthConstraint          nonnegative maximum subordinate-CA depth
 * @param keyUsageCritical              Key Usage criticality, required to be
 *                                      {@code true}
 * @param keyUsages                     exact CA key-usage set
 * @param allowedSubjectKeyAlgorithmIds exact canonical ZeroEcho subject-key
 *                                      algorithm identifiers
 */
public record CaCertificatePolicy(boolean basicConstraintsCritical, int pathLengthConstraint,
        boolean keyUsageCritical, Set<CaKeyUsage> keyUsages,
        Set<String> allowedSubjectKeyAlgorithmIds) implements CertificatePolicy {

    /** Maximum supported path-length constraint. */
    public static final int MAXIMUM_PATH_LENGTH = 32;

    private static final Set<String> SUPPORTED_SUBJECT_KEY_ALGORITHMS =
            Set.of("RSA", "ECDSA", "Ed25519", "Ed448");

    /** Validates and constructs the CA policy. */
    public CaCertificatePolicy {
        if (!basicConstraintsCritical) {
            throw new IllegalArgumentException("CA Basic Constraints must be critical");
        }
        if (pathLengthConstraint < 0 || pathLengthConstraint > MAXIMUM_PATH_LENGTH) {
            throw new IllegalArgumentException("CA path length is outside the supported range");
        }
        if (!keyUsageCritical) {
            throw new IllegalArgumentException("CA Key Usage must be critical");
        }
        if (keyUsages == null || allowedSubjectKeyAlgorithmIds == null) {
            throw new IllegalArgumentException("CA policy collections must not be null");
        }
        keyUsages = Set.copyOf(keyUsages);
        allowedSubjectKeyAlgorithmIds = Set.copyOf(allowedSubjectKeyAlgorithmIds);
        if (!keyUsages.contains(CaKeyUsage.KEY_CERT_SIGN)
                || !keyUsages.contains(CaKeyUsage.CRL_SIGN)) {
            throw new IllegalArgumentException("CA Key Usage must permit certificate and CRL signing");
        }
        if (allowedSubjectKeyAlgorithmIds.isEmpty()
                || !SUPPORTED_SUBJECT_KEY_ALGORITHMS.containsAll(allowedSubjectKeyAlgorithmIds)) {
            throw new IllegalArgumentException("At least one supported CA subject-key algorithm is required");
        }
    }
}
