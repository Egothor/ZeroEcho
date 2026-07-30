/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.revocation;

import java.time.Instant;
import java.util.Optional;

import zeroecho.pki.api.attr.AttributeSet;

/**
 * One committed transition in an authoritative revocation journal.
 *
 * @param revision        positive contiguous revision
 * @param state           resulting state
 * @param time            authoritative transition time
 * @param permanentReason permanent reason only for permanent state
 * @param attributes      safe administrative metadata
 */
public record RevocationTransition(long revision, RevocationState state, Instant time,
        Optional<RevocationReason> permanentReason, AttributeSet attributes) {

    /**
     * Validates structural transition fields.
     */
    public RevocationTransition {
        if (revision <= 0L || state == null || time == null || permanentReason == null || attributes == null) {
            throw new IllegalArgumentException("Invalid revocation transition");
        }
        attributes = RevocationJournal.snapshot(attributes);
    }
}
