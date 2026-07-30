/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.revocation;

import java.util.Objects;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeSet;

/**
 * Closed, immutable commands accepted by the revocation state machine.
 */
public sealed interface RevocationCommand
        permits RevocationCommand.Hold, RevocationCommand.Unhold, RevocationCommand.RevokePermanently {

    /**
     * Returns the target credential.
     *
     * @return credential identifier
     */
    PkiId credentialId();

    /**
     * Returns an immutable snapshot of safe administrative metadata.
     *
     * @return administrative attributes
     */
    AttributeSet attributes();

    /**
     * Places a credential on hold.
     *
     * @param credentialId credential identifier
     * @param attributes   safe administrative metadata
     */
    record Hold(PkiId credentialId, AttributeSet attributes) implements RevocationCommand {
        /** Validates and snapshots the command. */
        public Hold {
            Objects.requireNonNull(credentialId, "credentialId");
            attributes = RevocationJournal.snapshot(attributes);
        }
    }

    /**
     * Removes an existing hold.
     *
     * @param credentialId credential identifier
     * @param attributes   safe administrative metadata
     */
    record Unhold(PkiId credentialId, AttributeSet attributes) implements RevocationCommand {
        /** Validates and snapshots the command. */
        public Unhold {
            Objects.requireNonNull(credentialId, "credentialId");
            attributes = RevocationJournal.snapshot(attributes);
        }
    }

    /**
     * Permanently revokes a credential.
     *
     * @param credentialId credential identifier
     * @param reason       permanent revocation reason
     * @param attributes   safe administrative metadata
     */
    record RevokePermanently(PkiId credentialId, RevocationReason reason, AttributeSet attributes)
            implements RevocationCommand {
        /** Validates and snapshots the command. */
        public RevokePermanently {
            Objects.requireNonNull(credentialId, "credentialId");
            Objects.requireNonNull(reason, "reason");
            if (reason == RevocationReason.CERTIFICATE_HOLD || reason == RevocationReason.REMOVE_FROM_CRL) {
                throw new IllegalArgumentException("reason must be permanent");
            }
            attributes = RevocationJournal.snapshot(attributes);
        }
    }
}
