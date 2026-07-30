/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.credential;

import java.util.Objects;

import zeroecho.pki.api.profile.CertificateProfileRef;

/**
 * Exact imported and activated profile identity for an end-entity credential.
 *
 * @param reference exact certificate-profile version
 */
public record EndEntityProfileBinding(CertificateProfileRef reference) implements CredentialProfileBinding {
    /** Creates an end-entity binding. */
    public EndEntityProfileBinding {
        Objects.requireNonNull(reference, "reference");
    }
}
