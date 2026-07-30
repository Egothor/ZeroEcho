/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

import zeroecho.pki.api.FormatId;

/**
 * Immutable, versioned certificate-profile configuration.
 *
 * <p>
 * This definition deliberately excludes runtime activation state. Its
 * {@link LeafCertificatePolicy} is the authoritative typed policy used by the
 * issuance path.
 * </p>
 *
 * @param profileId      stable profile identifier
 * @param profileVersion positive configuration version
 * @param formatId       framework/format identifier
 * @param displayName    human-readable profile name
 * @param leafPolicy     complete leaf certificate policy
 */
public record CertificateProfileDefinition(String profileId, long profileVersion, FormatId formatId,
        String displayName, LeafCertificatePolicy leafPolicy) {

    /** Current certificate-profile document schema version. */
    public static final int SCHEMA_VERSION = 1;

    /**
     * Creates a certificate-profile definition.
     *
     * @throws IllegalArgumentException if a required value is absent or the
     *                                  profile version is not positive
     */
    public CertificateProfileDefinition {
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
        if (leafPolicy == null) {
            throw new IllegalArgumentException("leafPolicy must not be null");
        }
    }
}
