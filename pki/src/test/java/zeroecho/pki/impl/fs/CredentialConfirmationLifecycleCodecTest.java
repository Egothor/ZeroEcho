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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofCas;

class CredentialConfirmationLifecycleCodecTest {
    @Test
    void roundTripsBothClosedPersistentRevisionsExactly() throws Exception {
        CredentialConfirmationLifecycle pending = CredentialConfirmationLifecycle.initialize(initialization());
        CredentialConfirmationLifecycle confirmed = pending.deriveConfirmed(
                new CredentialConfirmationProofCas(pending.credentialId(), pending.revision(),
                        pending.recordCommitment(), "3".repeat(64)),
                Instant.ofEpochSecond(4_000L, 123_456_789));

        assertEquals(pending, CredentialConfirmationLifecycleCodec.decode(
                CredentialConfirmationLifecycleCodec.encode(pending)));
        byte[] confirmedBytes = CredentialConfirmationLifecycleCodec.encode(confirmed);
        CredentialConfirmationLifecycle decoded = CredentialConfirmationLifecycleCodec.decode(confirmedBytes);
        assertEquals(confirmed, decoded);
        assertArrayEquals(confirmedBytes, CredentialConfirmationLifecycleCodec.encode(decoded));
    }

    @Test
    void rejectsMalformedVersionTruncationAndTrailingData() {
        byte[] encoded = CredentialConfirmationLifecycleCodec.encode(
                CredentialConfirmationLifecycle.initialize(initialization()));
        byte[] obsolete = encoded.clone();
        obsolete[7] = 1;
        byte[] invalidConsumedPresence = encoded.clone();
        invalidConsumedPresence[invalidConsumedPresence.length - 34] = 2;
        byte[] corruptCommitment = encoded.clone();
        corruptCommitment[corruptCommitment.length - 1] ^= 1;
        byte[] nonCanonicalNanos = encoded.clone();
        java.nio.ByteBuffer cursor = java.nio.ByteBuffer.wrap(nonCanonicalNanos);
        cursor.position(Integer.BYTES * 2);
        int credentialLength = cursor.getInt();
        cursor.position(cursor.position() + credentialLength + Long.BYTES + Integer.BYTES + 32 + 1
                + Long.BYTES);
        cursor.putInt(-1);

        assertThrows(java.io.IOException.class,
                () -> CredentialConfirmationLifecycleCodec.decode(obsolete));
        assertThrows(java.io.IOException.class,
                () -> CredentialConfirmationLifecycleCodec.decode(invalidConsumedPresence));
        assertThrows(java.io.IOException.class,
                () -> CredentialConfirmationLifecycleCodec.decode(corruptCommitment));
        assertThrows(java.io.IOException.class,
                () -> CredentialConfirmationLifecycleCodec.decode(nonCanonicalNanos));
        assertThrows(java.io.IOException.class,
                () -> CredentialConfirmationLifecycleCodec.decode(
                        java.util.Arrays.copyOf(encoded, encoded.length - 1)));
        assertThrows(java.io.IOException.class,
                () -> CredentialConfirmationLifecycleCodec.decode(
                        java.util.Arrays.copyOf(encoded, encoded.length + 1)));
    }

    private static CredentialConfirmationInitialization initialization() {
        return new CredentialConfirmationInitialization(new PkiId("credential-α"),
                ConfirmationDisclosurePolicy.AUTHENTICATED, "1".repeat(64), true,
                Instant.ofEpochSecond(3_000L, 987_654_321),
                new ConfirmationProofSuiteRef("holder-proof.v1", "2".repeat(64)));
    }
}
