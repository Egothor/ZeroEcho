/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Validated active profile resolution result used by end-entity issuance.
 *
 * @param reference  exact active version reference
 * @param definition authoritative immutable definition
 */
public record ActiveCertificateProfile(CertificateProfileRef reference, CertificateProfileDefinition definition) {
    /** Creates an active profile result. */
    public ActiveCertificateProfile {
        Objects.requireNonNull(reference, "reference");
        Objects.requireNonNull(definition, "definition");
        if (!reference.profileId().equals(definition.profileId())
                || reference.profileVersion() != definition.profileVersion()
                || !MessageDigest.isEqual(reference.canonicalSha256(), canonicalHash(definition))) {
            throw new IllegalArgumentException("active profile identity mismatch");
        }
    }

    /**
     * Returns the deterministic runtime projection of the authoritative definition.
     *
     * @return runtime profile
     */
    public CertificateProfile profile() {
        return CertificateProfile.fromDefinition(definition);
    }

    private static byte[] canonicalHash(CertificateProfileDefinition definition) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(CertificateProfileDocumentCodec.writeCanonical(definition));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }
}
