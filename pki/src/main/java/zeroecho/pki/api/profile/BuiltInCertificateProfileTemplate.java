/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable built-in certificate-profile provisioning template.
 *
 * <p>
 * A template is configuration input only. Loading it neither persists nor
 * activates a profile. The canonical JSON and its SHA-256 hash are defensive
 * snapshots suitable for deterministic later provisioning and audit. The hash
 * is an identity and audit aid, not a signature or trust anchor.
 * </p>
 */
public final class BuiltInCertificateProfileTemplate {

    private static final int SHA_256_BYTES = 32;

    private final CertificateProfileDefinition definition;
    private final byte[] canonicalJson;
    private final byte[] canonicalSha256;
    private final String resourceName;

    /* default */ BuiltInCertificateProfileTemplate(CertificateProfileDefinition definition, byte[] canonicalJson,
            byte[] canonicalSha256, String resourceName) {
        this.definition = Objects.requireNonNull(definition, "definition");
        this.canonicalJson = Objects.requireNonNull(canonicalJson, "canonicalJson").clone();
        this.canonicalSha256 = Objects.requireNonNull(canonicalSha256, "canonicalSha256").clone();
        this.resourceName = Objects.requireNonNull(resourceName, "resourceName");
        if (this.canonicalJson.length == 0) {
            throw new IllegalArgumentException("canonicalJson must not be empty");
        }
        if (this.canonicalSha256.length != SHA_256_BYTES) {
            throw new IllegalArgumentException("canonicalSha256 must contain 32 bytes");
        }
        if (resourceName.isBlank()) {
            throw new IllegalArgumentException("resourceName must not be blank");
        }
    }

    /**
     * Returns the validated immutable profile definition.
     *
     * @return profile definition
     */
    public CertificateProfileDefinition definition() {
        return definition;
    }

    /**
     * Returns a copy of the canonical ZeroEcho profile JSON.
     *
     * @return newly allocated canonical JSON bytes
     */
    public byte[] canonicalJson() {
        return canonicalJson.clone();
    }

    /**
     * Returns a copy of the SHA-256 hash of the canonical JSON.
     *
     * @return newly allocated 32-byte hash
     */
    public byte[] canonicalSha256() {
        return canonicalSha256.clone();
    }

    /**
     * Returns the validated classpath resource name.
     *
     * @return resource name
     */
    public String resourceName() {
        return resourceName;
    }

    @Override
    public boolean equals(Object other) {
        return this == other || other instanceof BuiltInCertificateProfileTemplate template
                && definition.equals(template.definition) && Arrays.equals(canonicalJson, template.canonicalJson)
                && Arrays.equals(canonicalSha256, template.canonicalSha256)
                && resourceName.equals(template.resourceName);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(definition, resourceName);
        result = 31 * result + Arrays.hashCode(canonicalJson);
        return 31 * result + Arrays.hashCode(canonicalSha256);
    }

    @Override
    public String toString() {
        return "BuiltInCertificateProfileTemplate[profileId=" + definition.profileId() + ", profileVersion="
                + definition.profileVersion() + ", resourceName=" + resourceName + "]";
    }
}
