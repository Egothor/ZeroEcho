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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;

class CredentialConfirmationChallengeCodecTest {
    @Test
    void roundTripsCanonicalChallengeExactly() throws Exception {
        CredentialConfirmationChallenge challenge = challenge("https://pki.example.test/confirmation");
        byte[] encoded = CredentialConfirmationChallengeCodec.encode(challenge);
        CredentialConfirmationChallenge decoded = CredentialConfirmationChallengeCodec.decode(encoded);

        assertEquals(challenge, decoded);
        assertArrayEquals(encoded, CredentialConfirmationChallengeCodec.encode(decoded));
        assertTrue(encoded.length <= CredentialConfirmationChallengeCodec.MAXIMUM_ENCODED_BYTES);
    }

    @Test
    void acceptsMaximumAudienceWithinGlobalBound() throws Exception {
        CredentialConfirmationChallenge challenge = challenge("a".repeat(512));
        byte[] encoded = CredentialConfirmationChallengeCodec.encode(challenge);

        assertEquals(challenge, CredentialConfirmationChallengeCodec.decode(encoded));
        assertTrue(encoded.length <= CredentialConfirmationChallengeCodec.MAXIMUM_ENCODED_BYTES);
    }

    @Test
    void rejectsCorruptionTruncationTrailingAndOversizedInput() {
        byte[] encoded = CredentialConfirmationChallengeCodec.encode(
                challenge("https://pki.example.test/confirmation"));
        byte[] corrupt = encoded.clone();
        corrupt[corrupt.length - 1] ^= 1;
        byte[] noncanonicalRealm = encoded.clone();
        noncanonicalRealm[Integer.BYTES * 3] = 'A';
        byte[] unsafeLength = encoded.clone();
        ByteBuffer.wrap(unsafeLength).putInt(Integer.BYTES * 2, Integer.MAX_VALUE);

        assertThrows(IOException.class, () -> CredentialConfirmationChallengeCodec.decode(corrupt));
        assertThrows(IOException.class, () -> CredentialConfirmationChallengeCodec.decode(
                Arrays.copyOf(encoded, encoded.length - 1)));
        assertThrows(IOException.class, () -> CredentialConfirmationChallengeCodec.decode(
                Arrays.copyOf(encoded, encoded.length + 1)));
        assertThrows(IOException.class,
                () -> CredentialConfirmationChallengeCodec.decode(noncanonicalRealm));
        assertThrows(IOException.class, () -> CredentialConfirmationChallengeCodec.decode(unsafeLength));
        assertThrows(IOException.class, () -> CredentialConfirmationChallengeCodec.decode(
                new byte[CredentialConfirmationChallengeCodec.MAXIMUM_ENCODED_BYTES + 1]));
    }

    @Test
    void rejectsMalformedHeaderAndNonWholeSecondEncoding() {
        byte[] encoded = CredentialConfirmationChallengeCodec.encode(
                challenge("https://pki.example.test/confirmation"));
        byte[] wrongVersion = encoded.clone();
        ByteBuffer.wrap(wrongVersion).putInt(Integer.BYTES, 2);
        byte[] nonWholeSecond = encoded.clone();
        ByteBuffer cursor = ByteBuffer.wrap(nonWholeSecond);
        cursor.position(Integer.BYTES * 2);
        skipBytes(cursor);
        skipBytes(cursor);
        skipBytes(cursor);
        cursor.position(cursor.position() + Long.BYTES + 32 + Integer.BYTES + 32);
        skipBytes(cursor);
        cursor.position(cursor.position() + 32 + Integer.BYTES
                + CredentialConfirmationChallenge.RAW_CHALLENGE_BYTES + Long.BYTES);
        cursor.putInt(1);

        assertThrows(IOException.class, () -> CredentialConfirmationChallengeCodec.decode(wrongVersion));
        assertThrows(IOException.class, () -> CredentialConfirmationChallengeCodec.decode(nonWholeSecond));
    }

    private static void skipBytes(ByteBuffer cursor) {
        int length = cursor.getInt();
        cursor.position(cursor.position() + length);
    }

    private static CredentialConfirmationChallenge challenge(String audience) {
        byte[] raw = new byte[CredentialConfirmationChallenge.RAW_CHALLENGE_BYTES];
        for (int index = 0; index < raw.length; index++) {
            raw[index] = (byte) index;
        }
        PkiId credentialId = new PkiId("x509:" + "a".repeat(64));
        ConfirmationProofSuiteBinding suite = new ConfirmationProofSuiteBinding(
                new ConfirmationProofSuiteRef("zeroecho.signature-pop.v1",
                        "5ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11"),
                8_192);
        CredentialConfirmationLifecycle lifecycle = CredentialConfirmationLifecycle.initialize(
                new CredentialConfirmationInitialization(credentialId, ConfirmationDisclosurePolicy.OWNER_ONLY,
                        "c".repeat(64), true, Instant.ofEpochSecond(1_767_225_900L), suite.proofSuiteRef()));
        return CredentialConfirmationChallenge.create(new ConfirmationRealmBinding("prod-eu"), audience,
                lifecycle, suite, raw, Instant.ofEpochSecond(1_767_225_600L),
                Instant.ofEpochSecond(1_767_225_900L));
    }
}
