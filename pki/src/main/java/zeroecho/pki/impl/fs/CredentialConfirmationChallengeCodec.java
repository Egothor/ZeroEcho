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
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;

/** Strict bounded binary version-1 codec for portable confirmation challenges. */
final class CredentialConfirmationChallengeCodec {
    /* default */ static final int MAXIMUM_ENCODED_BYTES = 2_048;

    private static final int MAGIC = 0x5a454348; // ZECH
    private static final int VERSION = 1;
    private static final int SHA_256_BYTES = 32;
    private static final int MAXIMUM_REALM_BYTES = 128;
    private static final int MAXIMUM_SUITE_ID_BYTES = 128;
    private static final long MAXIMUM_EPOCH_SECOND = 253_402_300_799L;
    private static final HexFormat HEX = HexFormat.of();

    private CredentialConfirmationChallengeCodec() { }

    /* default */ static byte[] encode(CredentialConfirmationChallenge challenge) {
        CredentialConfirmationChallenge exact = Objects.requireNonNull(challenge, "challenge");
        byte[] realm = strictUtf8(exact.realm().value());
        byte[] audience = strictUtf8(exact.serverAudience());
        byte[] credential = strictUtf8(exact.credentialId().value());
        byte[] suiteId = strictUtf8(exact.proofSuiteBinding().proofSuiteRef().suiteId());
        byte[] rawChallenge = exact.rawChallenge();
        try {
            int size = Integer.BYTES * 2
                    + Integer.BYTES + realm.length
                    + Integer.BYTES + audience.length
                    + Integer.BYTES + credential.length
                    + Long.BYTES + SHA_256_BYTES + Integer.BYTES + SHA_256_BYTES
                    + Integer.BYTES + suiteId.length + SHA_256_BYTES + Integer.BYTES
                    + CredentialConfirmationChallenge.RAW_CHALLENGE_BYTES
                    + (Long.BYTES + Integer.BYTES) * 2 + SHA_256_BYTES;
            if (size > MAXIMUM_ENCODED_BYTES) {
                throw new IllegalArgumentException("Credential confirmation challenge exceeds its size limit");
            }
            ByteBuffer output = ByteBuffer.allocate(size);
            output.putInt(MAGIC).putInt(VERSION);
            putBytes(output, realm);
            putBytes(output, audience);
            putBytes(output, credential);
            output.putLong(exact.expectedLifecycleRevision());
            putHash(output, exact.expectedLifecycleRecordCommitment());
            output.putInt(exact.initialDisclosurePolicy().code());
            putHash(output, exact.confirmationPolicyCommitment());
            putBytes(output, suiteId);
            putHash(output, exact.proofSuiteBinding().proofSuiteRef().configurationCommitment());
            output.putInt(exact.proofSuiteBinding().rsaMaximumModulusBits());
            output.put(rawChallenge);
            putInstant(output, exact.issuedAt());
            putInstant(output, exact.expiresAt());
            putHash(output, exact.recordCommitment());
            return output.array();
        } finally {
            clear(realm);
            clear(audience);
            clear(credential);
            clear(suiteId);
            clear(rawChallenge);
        }
    }

    /* default */ static CredentialConfirmationChallenge decode(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length == 0 || encoded.length > MAXIMUM_ENCODED_BYTES) {
            throw malformed();
        }
        byte[] exactEncoding = encoded.clone();
        try {
            return decodeExact(exactEncoding);
        } finally {
            clear(exactEncoding);
        }
    }

    private static CredentialConfirmationChallenge decodeExact(byte[] exactEncoding) throws IOException {
        byte[] rawChallenge = null;
        try {
            ByteBuffer input = ByteBuffer.wrap(exactEncoding).asReadOnlyBuffer();
            if (input.getInt() != MAGIC || input.getInt() != VERSION) {
                throw malformed();
            }
            ConfirmationRealmBinding realm = new ConfirmationRealmBinding(readUtf8(input, MAXIMUM_REALM_BYTES));
            String audience = readUtf8(input,
                    CredentialConfirmationChallenge.MAXIMUM_SERVER_AUDIENCE_UTF8_BYTES);
            PkiId credentialId = new PkiId(readUtf8(input,
                    CredentialConfirmationInitialization.MAXIMUM_CREDENTIAL_ID_UTF8_BYTES));
            long expectedRevision = input.getLong();
            String expectedLifecycleCommitment = readHash(input);
            ConfirmationDisclosurePolicy policy = ConfirmationDisclosurePolicy.fromCode(input.getInt());
            String policyCommitment = readHash(input);
            String suiteId = readUtf8(input, MAXIMUM_SUITE_ID_BYTES);
            String suiteCommitment = readHash(input);
            int rsaMaximumModulusBits = input.getInt();
            rawChallenge = readFixed(input, CredentialConfirmationChallenge.RAW_CHALLENGE_BYTES);
            Instant issuedAt = readInstant(input);
            Instant expiresAt = readInstant(input);
            String recordCommitment = readHash(input);
            if (input.hasRemaining()) {
                throw malformed();
            }
            ConfirmationProofSuiteRef suiteRef = new ConfirmationProofSuiteRef(suiteId, suiteCommitment);
            ConfirmationProofSuiteBinding suite = new ConfirmationProofSuiteBinding(
                    suiteRef, rsaMaximumModulusBits);
            CredentialConfirmationChallenge decoded = new CredentialConfirmationChallenge(realm, audience,
                    credentialId, expectedRevision, expectedLifecycleCommitment, policy, policyCommitment,
                    suite, rawChallenge, issuedAt, expiresAt, recordCommitment);
            requireCanonical(exactEncoding, decoded);
            return decoded;
        } catch (BufferUnderflowException | IllegalArgumentException failure) {
            throw new IOException("Credential confirmation challenge metadata is malformed", failure);
        } finally {
            clear(rawChallenge);
        }
    }

    private static void putBytes(ByteBuffer output, byte[] value) {
        output.putInt(value.length).put(value);
    }

    private static void putHash(ByteBuffer output, String value) {
        byte[] decoded = HEX.parseHex(value);
        try {
            output.put(decoded);
        } finally {
            clear(decoded);
        }
    }

    private static void putInstant(ByteBuffer output, Instant value) {
        output.putLong(value.getEpochSecond()).putInt(value.getNano());
    }

    private static String readUtf8(ByteBuffer input, int maximumBytes) throws IOException {
        int length = input.getInt();
        if (length <= 0 || length > maximumBytes || input.remaining() < length) {
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
            throw new IOException("Credential confirmation challenge contains malformed UTF-8", failure);
        } finally {
            clear(value);
        }
    }

    private static Instant readInstant(ByteBuffer input) throws IOException {
        long seconds = input.getLong();
        int nanos = input.getInt();
        if (seconds < 0L || seconds > MAXIMUM_EPOCH_SECOND || nanos != 0) {
            throw malformed();
        }
        return Instant.ofEpochSecond(seconds, nanos);
    }

    private static String readHash(ByteBuffer input) throws IOException {
        byte[] value = readFixed(input, SHA_256_BYTES);
        try {
            return HEX.formatHex(value);
        } finally {
            clear(value);
        }
    }

    private static byte[] readFixed(ByteBuffer input, int length) throws IOException {
        if (input.remaining() < length) {
            throw malformed();
        }
        byte[] value = new byte[length];
        input.get(value);
        return value;
    }

    private static void requireCanonical(byte[] expected, CredentialConfirmationChallenge decoded)
            throws IOException {
        byte[] actual = encode(decoded);
        try {
            if (!Arrays.equals(expected, actual)) {
                throw malformed();
            }
        } finally {
            clear(actual);
        }
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
        } catch (CharacterCodingException impossible) {
            throw new IllegalArgumentException("Confirmation challenge is not strict UTF-8", impossible);
        }
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static IOException malformed() {
        return new IOException("Credential confirmation challenge metadata is malformed");
    }
}
