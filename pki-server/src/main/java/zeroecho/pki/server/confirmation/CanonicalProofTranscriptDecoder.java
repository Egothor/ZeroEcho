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
package zeroecho.pki.server.confirmation;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;

/** Strict stateless hostile-byte decoder for canonical proof transcripts. */
final class CanonicalProofTranscriptDecoder {

    private static final byte[] MAGIC = { 'Z', 'E', 'P', 'P' };
    private static final byte[] PURPOSE_BYTES = CanonicalProofTranscript.PURPOSE
            .getBytes(StandardCharsets.US_ASCII);
    private static final int FIELD_COUNT = 9;
    private static final int MAXIMUM_REALM_BYTES = 128;
    private static final int MAXIMUM_AUDIENCE_BYTES = 512;
    private static final int X509_CREDENTIAL_ID_BYTES = 69;

    private CanonicalProofTranscriptDecoder() {
        throw new AssertionError("No instances");
    }

    /* default */ static CanonicalProofTranscript decode(byte[] encodedBytes,
            ProofSuiteDescriptor expectedDescriptor) {
        Objects.requireNonNull(expectedDescriptor, "expectedDescriptor");
        if (encodedBytes == null || encodedBytes.length == 0
                || encodedBytes.length > CanonicalProofTranscript.MAXIMUM_ENCODED_BYTES) {
            throw invalidEncoding();
        }
        byte[] exactEncoding = encodedBytes.clone();
        try {
            return decodeExact(exactEncoding, expectedDescriptor);
        } finally {
            clear(exactEncoding);
        }
    }

    private static CanonicalProofTranscript decodeExact(byte[] exactEncoding,
            ProofSuiteDescriptor expectedDescriptor) {
        ByteBuffer input = ByteBuffer.wrap(exactEncoding).asReadOnlyBuffer().order(ByteOrder.BIG_ENDIAN);
        requireHeader(input);
        DecodedFields fields = readFields(input, expectedDescriptor);
        try {
            return reconstruct(exactEncoding, expectedDescriptor, fields);
        } finally {
            fields.clear();
        }
    }

    private static void requireHeader(ByteBuffer input) {
        requireRemaining(input, MAGIC.length + Short.BYTES);
        for (byte expected : MAGIC) {
            if (input.get() != expected) {
                throw invalidEncoding();
            }
        }
        if (Short.toUnsignedInt(input.getShort()) != FIELD_COUNT) {
            throw invalidEncoding();
        }
    }

    private static DecodedFields readFields(ByteBuffer input, ProofSuiteDescriptor expectedDescriptor) {
        byte[][] values = new byte[FIELD_COUNT][];
        boolean complete = false;
        try {
            values[0] = field(input, 1, Integer.BYTES, Integer.BYTES);
            values[1] = field(input, 2, PURPOSE_BYTES.length, PURPOSE_BYTES.length);
            values[2] = field(input, 3, 1, MAXIMUM_REALM_BYTES);
            values[3] = field(input, 4, 1, MAXIMUM_AUDIENCE_BYTES);
            values[4] = field(input, 5, X509_CREDENTIAL_ID_BYTES, X509_CREDENTIAL_ID_BYTES);
            values[5] = field(input, 6, 1, ProofSuiteId.MAXIMUM_LENGTH);
            values[6] = field(input, 7, ProofSuiteCommitment.LENGTH, ProofSuiteCommitment.LENGTH);
            values[7] = field(input, 8, expectedDescriptor.challengeBytes(),
                    expectedDescriptor.challengeBytes());
            values[8] = field(input, 9, Long.BYTES + Integer.BYTES, Long.BYTES + Integer.BYTES);
            if (input.hasRemaining()) {
                throw invalidEncoding();
            }
            DecodedFields result = new DecodedFields(values);
            complete = true;
            return result;
        } finally {
            if (!complete) {
                clear(values);
            }
        }
    }

    private static CanonicalProofTranscript reconstruct(byte[] exactEncoding,
            ProofSuiteDescriptor expectedDescriptor, DecodedFields fields) {
        requireVersion(fields.value(1));
        requirePurpose(fields.value(2));
        ConfirmationRealmBinding realmId = new ConfirmationRealmBinding(ascii(fields.value(3)));
        String serverAudience = utf8(fields.value(4));
        PkiId credentialId = new PkiId(ascii(fields.value(5)));
        ProofSuiteId suiteId = new ProofSuiteId(ascii(fields.value(6)));
        ProofSuiteCommitment suiteCommitment = new ProofSuiteCommitment(fields.value(7));
        requireExpectedSuite(expectedDescriptor, suiteId, suiteCommitment);
        Instant expiresAt = expiry(fields.value(9));
        CanonicalProofTranscript decoded = new CanonicalProofTranscript(realmId, serverAudience,
                credentialId, expectedDescriptor, fields.value(8), expiresAt);
        requireCanonical(exactEncoding, decoded);
        return decoded;
    }

    private static void requireVersion(byte[] value) {
        if (ByteBuffer.wrap(value).order(ByteOrder.BIG_ENDIAN).getInt() != CanonicalProofTranscript.VERSION) {
            throw invalidEncoding();
        }
    }

    private static void requirePurpose(byte[] value) {
        if (!Arrays.equals(value, PURPOSE_BYTES)) {
            throw invalidEncoding();
        }
    }

    private static void requireExpectedSuite(ProofSuiteDescriptor expectedDescriptor,
            ProofSuiteId suiteId, ProofSuiteCommitment suiteCommitment) {
        if (!expectedDescriptor.suiteId().equals(suiteId)
                || !expectedDescriptor.configurationCommitment().matches(suiteCommitment)) {
            throw new IllegalArgumentException("Proof transcript identifies another suite profile");
        }
    }

    private static Instant expiry(byte[] value) {
        ByteBuffer encoded = ByteBuffer.wrap(value).order(ByteOrder.BIG_ENDIAN);
        try {
            return Instant.ofEpochSecond(encoded.getLong(), encoded.getInt());
        } catch (DateTimeException invalid) {
            throw invalidEncoding(invalid);
        }
    }

    private static void requireCanonical(byte[] expected, CanonicalProofTranscript decoded) {
        byte[] actual = decoded.encoded();
        try {
            if (!Arrays.equals(expected, actual)) {
                throw new IllegalArgumentException("Proof transcript is not canonically encoded");
            }
        } finally {
            clear(actual);
        }
    }

    private static byte[] field(ByteBuffer input, int expectedTag, int minimumBytes, int maximumBytes) {
        requireRemaining(input, Byte.BYTES + Integer.BYTES);
        int tag = Byte.toUnsignedInt(input.get());
        int length = input.getInt();
        if (tag != expectedTag || length < minimumBytes || length > maximumBytes
                || input.remaining() < length) {
            throw invalidEncoding();
        }
        byte[] value = new byte[length];
        input.get(value);
        return value;
    }

    private static void requireRemaining(ByteBuffer input, int requiredBytes) {
        if (input.remaining() < requiredBytes) {
            throw invalidEncoding();
        }
    }

    private static String ascii(byte[] value) {
        for (byte octet : value) {
            if (octet < 0) {
                throw invalidEncoding();
            }
        }
        return new String(value, StandardCharsets.US_ASCII);
    }

    private static String utf8(byte[] value) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value)).toString();
        } catch (CharacterCodingException invalid) {
            throw invalidEncoding(invalid);
        }
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static void clear(byte[][] values) {
        for (byte[] value : values) {
            clear(value);
        }
    }

    private static IllegalArgumentException invalidEncoding() {
        return new IllegalArgumentException("Proof transcript encoding is invalid");
    }

    private static IllegalArgumentException invalidEncoding(Exception cause) {
        return new IllegalArgumentException("Proof transcript encoding is invalid", cause);
    }

    private record DecodedFields(byte[][] values) {
        private byte[] value(int tag) {
            return values[tag - 1];
        }

        private void clear() {
            CanonicalProofTranscriptDecoder.clear(values);
        }
    }
}
