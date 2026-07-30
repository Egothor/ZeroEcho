/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.credential;

import java.util.Objects;

import zeroecho.pki.api.profile.CertificateProfileRef;

/**
 * Exact versioned CA profile identity for a root or intermediate credential.
 *
 * @param reference imported CA profile version used for issuance
 */
public record CaProfileBinding(CertificateProfileRef reference) implements CredentialProfileBinding {
    /** Creates a CA profile binding. */
    public CaProfileBinding {
        Objects.requireNonNull(reference, "reference");
    }
}
