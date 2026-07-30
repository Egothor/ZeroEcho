/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

import java.time.Duration;

import zeroecho.pki.api.FormatId;

/**
 * Immutable, versioned certificate-profile configuration.
 *
 * <p>
 * Schema version 2 replaces the pre-release version 1 shape. The certificate
 * kind and its closed policy variant are immutable across the definition.
 * Runtime activation state is deliberately excluded.
 * </p>
 *
 * @param certificateType kind of certificate governed by the profile
 * @param profileId       stable profile identifier
 * @param profileVersion  positive configuration version
 * @param formatId        framework/format identifier
 * @param displayName     human-readable profile name
 * @param maximumValidity positive maximum validity
 * @param subjectPolicy   complete subject policy
 * @param certificatePolicy closed certificate-specific policy variant
 */
public record CertificateProfileDefinition(CertificateProfileKind certificateType,
        String profileId, long profileVersion, FormatId formatId, String displayName,
        Duration maximumValidity, SubjectPolicy subjectPolicy,
        CertificatePolicy certificatePolicy) {

    /** Current certificate-profile document schema version. */
    public static final int SCHEMA_VERSION = 2;

    /**
     * Creates a certificate-profile definition.
     *
     * @throws IllegalArgumentException if a required value is absent or the
     *                                  profile version is not positive
     */
    public CertificateProfileDefinition {
        if (certificateType == null) {
            throw new IllegalArgumentException("certificateType must not be null");
        }
        if (profileId == null || profileId.isBlank()) {
            throw new IllegalArgumentException("profileId must not be null/blank");
        }
        if (profileVersion <= 0) {
            throw new IllegalArgumentException("profileVersion must be positive");
        }
        if (formatId == null) {
            throw new IllegalArgumentException("formatId must not be null");
        }
        if (displayName == null || displayName.isBlank()) {
            throw new IllegalArgumentException("displayName must not be null/blank");
        }
        if (maximumValidity == null || maximumValidity.isZero() || maximumValidity.isNegative()) {
            throw new IllegalArgumentException("maximumValidity must be positive");
        }
        if (subjectPolicy == null || certificatePolicy == null) {
            throw new IllegalArgumentException("profile policies must not be null");
        }
        boolean leaf = certificatePolicy instanceof LeafCertificatePolicy;
        if (certificateType == CertificateProfileKind.END_ENTITY != leaf) {
            throw new IllegalArgumentException("certificate type and policy variant do not match");
        }
        if (certificateType != CertificateProfileKind.END_ENTITY
                && (subjectPolicy.allowEmpty() || subjectPolicy.rules().isEmpty()
                        || subjectPolicy.rules().stream().noneMatch(rule -> rule.minimumOccurrences() > 0))) {
            throw new IllegalArgumentException("CA profiles require a nonempty subject policy");
        }
    }

    /**
     * Returns the end-entity policy.
     *
     * @return leaf policy
     * @throws IllegalStateException if this is a CA profile
     */
    public LeafCertificatePolicy leafPolicy() {
        if (certificatePolicy instanceof LeafCertificatePolicy leaf) {
            return leaf;
        }
        throw new IllegalStateException("Profile is not an end-entity profile");
    }

    /**
     * Returns the CA policy.
     *
     * @return CA policy
     * @throws IllegalStateException if this is an end-entity profile
     */
    public CaCertificatePolicy caPolicy() {
        if (certificatePolicy instanceof CaCertificatePolicy ca) {
            return ca;
        }
        throw new IllegalStateException("Profile is not a CA profile");
    }
}
