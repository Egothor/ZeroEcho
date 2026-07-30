/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgement:
 *    This product includes software developed by the Egothor project.
 *
 * 4. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
