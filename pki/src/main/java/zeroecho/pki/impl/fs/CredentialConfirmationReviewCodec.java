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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationReview;

/** Strict current-format codec for one derived confirmation-review projection. */
final class CredentialConfirmationReviewCodec {
    private static final int MAGIC = 0x5a455256; // ZERV
    private static final int VERSION = 2;
    private static final int FIXED_BYTES = Integer.BYTES * 7 + Long.BYTES;
    private static final int MAXIMUM_BYTES = FIXED_BYTES
            + CredentialConfirmationInitialization.MAXIMUM_CREDENTIAL_ID_UTF8_BYTES
            + CredentialConfirmationReview.MAXIMUM_AUTHORITY_ID_UTF8_BYTES
            + CredentialConfirmationReview.MAXIMUM_PROFILE_ID_UTF8_BYTES;

    private CredentialConfirmationReviewCodec() { }

    /* default */ static byte[] encode(CredentialConfirmationReview review) {
        byte[] credential = review.credentialId().value().getBytes(StandardCharsets.UTF_8);
        byte[] authority = review.authorityId().value().getBytes(StandardCharsets.UTF_8);
        byte[] profile = review.profileId().getBytes(StandardCharsets.UTF_8);
        ByteBuffer output = ByteBuffer.allocate(FIXED_BYTES
                + credential.length + authority.length + profile.length);
        output.putInt(MAGIC).putInt(VERSION);
        putBytes(output, credential);
        putBytes(output, authority);
        putBytes(output, profile);
        output.putLong(review.confirmationReviewAt().getEpochSecond());
        output.putInt(review.confirmationReviewAt().getNano());
        output.putInt(review.initialDisclosurePolicy().code());
        return output.array();
    }

    /* default */ static CredentialConfirmationReview decode(byte[] encoded) throws IOException {
        try {
            if (encoded.length < FIXED_BYTES + 3 || encoded.length > MAXIMUM_BYTES) {
                throw malformed();
            }
            ByteBuffer input = ByteBuffer.wrap(encoded);
            if (input.getInt() != MAGIC || input.getInt() != VERSION) {
                throw malformed();
            }
            String credential = readText(input,
                    CredentialConfirmationInitialization.MAXIMUM_CREDENTIAL_ID_UTF8_BYTES);
            String authority = readText(input,
                    CredentialConfirmationReview.MAXIMUM_AUTHORITY_ID_UTF8_BYTES);
            String profile = readText(input,
                    CredentialConfirmationReview.MAXIMUM_PROFILE_ID_UTF8_BYTES);
            Instant reviewAt = Instant.ofEpochSecond(input.getLong(), input.getInt());
            ConfirmationDisclosurePolicy disclosure = ConfirmationDisclosurePolicy.fromCode(input.getInt());
            if (input.hasRemaining()) {
                throw malformed();
            }
            return new CredentialConfirmationReview(new PkiId(credential), new PkiId(authority),
                    profile, reviewAt, disclosure);
        } catch (IllegalArgumentException | java.nio.BufferUnderflowException failure) {
            throw malformed(failure);
        }
    }

    private static void putBytes(ByteBuffer output, byte[] value) {
        output.putInt(value.length).put(value);
    }

    private static String readText(ByteBuffer input, int maximumBytes) throws IOException {
        int length = input.getInt();
        if (length < 1 || length > maximumBytes || input.remaining() < length) {
            throw malformed();
        }
        byte[] value = new byte[length];
        input.get(value);
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value)).toString();
        } catch (CharacterCodingException failure) {
            throw malformed(failure);
        }
    }

    private static IOException malformed() {
        return new IOException("Credential confirmation review projection is malformed");
    }

    private static IOException malformed(Exception cause) {
        return new IOException("Credential confirmation review projection is malformed", cause);
    }
}
