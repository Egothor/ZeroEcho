/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.credential;

/**
 * Explicit CA policy identity for a root or intermediate credential.
 *
 * @param profileId existing CA policy identifier
 */
public record CaProfileBinding(String profileId) implements CredentialProfileBinding {
    /** Creates a CA profile binding. */
    public CaProfileBinding {
        if (profileId == null || profileId.isBlank()) {
            throw new IllegalArgumentException("profileId must not be null/blank");
        }
    }
}
