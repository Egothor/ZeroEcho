/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.revocation;

import java.util.Objects;

import zeroecho.pki.api.PkiId;

/**
 * Immutable current revocation state for one credential.
 *
 * @param credentialId exact credential identity
 * @param transition latest committed transition
 */
public record RevocationRecord(PkiId credentialId, RevocationTransition transition) {

    /**
     * Creates a current-state record.
     *
     * @throws NullPointerException if either value is {@code null}
     */
    public RevocationRecord {
        Objects.requireNonNull(credentialId, "credentialId");
        Objects.requireNonNull(transition, "transition");
    }
}
