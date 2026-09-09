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
package zeroecho.pki.api.confirmation;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;
import java.util.regex.Pattern;

import zeroecho.pki.api.PkiId;

/** Shared canonical validation for immutable credential-confirmation values. */
final class ConfirmationModelSupport {
    private static final int MAXIMUM_ONE_BYTE_CODE_POINT = 0x7f;
    private static final int MAXIMUM_TWO_BYTE_CODE_POINT = 0x7ff;
    private static final long MAXIMUM_EPOCH_SECOND = 253_402_300_799L;
    private static final Pattern SHA_256 = Pattern.compile("[0-9a-f]{64}");

    private ConfirmationModelSupport() { }

    /* default */ static PkiId requireCredentialId(PkiId credentialId) {
        PkiId exact = Objects.requireNonNull(credentialId, "credentialId");
        String value = exact.value();
        int encodedBytes = 0;
        int index = 0;
        while (index < value.length()) {
            char current = value.charAt(index);
            int codePoint;
            if (Character.isHighSurrogate(current)) {
                int lowIndex = index + 1;
                if (lowIndex >= value.length() || !Character.isLowSurrogate(value.charAt(lowIndex))) {
                    throw invalidCredentialId();
                }
                codePoint = Character.toCodePoint(current, value.charAt(lowIndex));
            } else if (Character.isLowSurrogate(current)) {
                throw invalidCredentialId();
            } else {
                codePoint = current;
            }
            if (codePoint <= MAXIMUM_ONE_BYTE_CODE_POINT) {
                encodedBytes++;
            } else if (codePoint <= MAXIMUM_TWO_BYTE_CODE_POINT) {
                encodedBytes += 2;
            } else if (Character.isSupplementaryCodePoint(codePoint)) {
                encodedBytes += 4;
            } else {
                encodedBytes += 3;
            }
            if (encodedBytes > CredentialConfirmationInitialization.MAXIMUM_CREDENTIAL_ID_UTF8_BYTES) {
                throw invalidCredentialId();
            }
            index += Character.charCount(codePoint);
        }
        if (encodedBytes == 0) {
            throw invalidCredentialId();
        }
        return exact;
    }

    /* default */ static Instant requireCanonicalInstant(Instant value, String name) {
        Objects.requireNonNull(value, name);
        if (value.getEpochSecond() < 0 || value.getEpochSecond() > MAXIMUM_EPOCH_SECOND) {
            throw new IllegalArgumentException(name + " is outside the supported UTC range");
        }
        return value;
    }

    /* default */ static String requireCommitment(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!SHA_256.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " is not a canonical SHA-256 commitment");
        }
        return value;
    }

    /* default */ static String requireServerAudience(String value) {
        Objects.requireNonNull(value, "serverAudience");
        byte[] encoded = strictUtf8(value);
        if (encoded.length == 0
                || encoded.length > CredentialConfirmationChallenge.MAXIMUM_SERVER_AUDIENCE_UTF8_BYTES
                || value.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Server audience is not canonical");
        }
        return value;
    }

    /* default */ static byte[] requireRawChallenge(byte[] value) {
        if (value == null || value.length != CredentialConfirmationChallenge.RAW_CHALLENGE_BYTES) {
            throw new IllegalArgumentException("Raw confirmation challenge must contain exactly 32 bytes");
        }
        return value.clone();
    }

    private static byte[] strictUtf8(String value) {
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(java.nio.CharBuffer.wrap(value));
            byte[] result = new byte[encoded.remaining()];
            encoded.get(result);
            return result;
        } catch (CharacterCodingException invalid) {
            throw new IllegalArgumentException("Server audience is not strict UTF-8", invalid);
        }
    }

    private static IllegalArgumentException invalidCredentialId() {
        return new IllegalArgumentException("Credential identity is not canonical strict UTF-8");
    }
}
