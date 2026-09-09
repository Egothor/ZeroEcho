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
import java.util.HexFormat;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;

/** Strict bounded binary version-2 codec for authoritative confirmation metadata. */
final class CredentialConfirmationLifecycleCodec {
    private static final int MAGIC = 0x5a454343; // ZECC
    private static final int VERSION = 2;
    private static final int SHA_256_BYTES = 32;
    private static final int MAXIMUM_SUITE_ID_BYTES = 128;
    private static final int MAXIMUM_ENCODED_BYTES = 1024;
    private static final long MAXIMUM_EPOCH_SECOND = 253_402_300_799L;
    private static final HexFormat HEX = HexFormat.of();

    private CredentialConfirmationLifecycleCodec() { }

    /* default */ static byte[] encode(CredentialConfirmationLifecycle lifecycle) {
        byte[] credentialId = strictUtf8(lifecycle.credentialId().value());
        byte[] suiteId = strictUtf8(lifecycle.proofSuite().suiteId());
        int size = Integer.BYTES * 2 + Integer.BYTES + credentialId.length + Long.BYTES
                + Integer.BYTES + SHA_256_BYTES + 1 + Long.BYTES + Integer.BYTES
                + Integer.BYTES + suiteId.length + SHA_256_BYTES + 1 + 1 + SHA_256_BYTES;
        if (lifecycle.consumedChallengeRecordCommitment().isPresent()) {
            size += SHA_256_BYTES;
        }
        if (lifecycle.confirmedAt().isPresent()) {
            size += Long.BYTES + Integer.BYTES;
        }
        ByteBuffer output = ByteBuffer.allocate(size);
        output.putInt(MAGIC).putInt(VERSION);
        putBytes(output, credentialId);
        output.putLong(lifecycle.revision()).putInt(lifecycle.initialPolicy().code());
        output.put(HEX.parseHex(lifecycle.initialPolicyCommitment()));
        output.put((byte) (lifecycle.confirmationRequired() ? 1 : 0));
        putInstant(output, lifecycle.confirmationReviewAt());
        putBytes(output, suiteId);
        output.put(HEX.parseHex(lifecycle.proofSuite().configurationCommitment()));
        output.put((byte) (lifecycle.consumedChallengeRecordCommitment().isPresent() ? 1 : 0));
        lifecycle.consumedChallengeRecordCommitment()
                .ifPresent(value -> output.put(HEX.parseHex(value)));
        output.put((byte) (lifecycle.confirmedAt().isPresent() ? 1 : 0));
        lifecycle.confirmedAt().ifPresent(value -> putInstant(output, value));
        output.put(HEX.parseHex(lifecycle.recordCommitment()));
        return output.array();
    }

    /* default */ static CredentialConfirmationLifecycle decode(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length == 0 || encoded.length > MAXIMUM_ENCODED_BYTES) {
            throw malformed();
        }
        try {
            ByteBuffer input = ByteBuffer.wrap(encoded);
            if (input.getInt() != MAGIC || input.getInt() != VERSION) {
                throw malformed();
            }
            PkiId credentialId = new PkiId(readUtf8(input,
                    CredentialConfirmationInitialization.MAXIMUM_CREDENTIAL_ID_UTF8_BYTES));
            long revision = input.getLong();
            ConfirmationDisclosurePolicy policy = ConfirmationDisclosurePolicy.fromCode(input.getInt());
            String policyCommitment = readHash(input);
            boolean required = readBoolean(input);
            Instant reviewAt = readInstant(input);
            String suiteId = readUtf8(input, MAXIMUM_SUITE_ID_BYTES);
            String suiteCommitment = readHash(input);
            Optional<String> consumedRecordCommitment = readBoolean(input)
                    ? Optional.of(readHash(input)) : Optional.empty();
            Optional<Instant> confirmedAt = readBoolean(input)
                    ? Optional.of(readInstant(input)) : Optional.empty();
            String recordCommitment = readHash(input);
            if (input.hasRemaining()) {
                throw malformed();
            }
            return new CredentialConfirmationLifecycle(credentialId, revision, policy,
                    policyCommitment, required, reviewAt,
                    new ConfirmationProofSuiteRef(suiteId, suiteCommitment),
                    consumedRecordCommitment, confirmedAt,
                    recordCommitment);
        } catch (IllegalArgumentException | java.nio.BufferUnderflowException failure) {
            throw new IOException("Credential confirmation lifecycle metadata is malformed", failure);
        }
    }

    private static void putBytes(ByteBuffer output, byte[] value) {
        output.putInt(value.length).put(value);
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
            throw new IOException("Credential confirmation metadata contains malformed UTF-8", failure);
        }
    }

    private static Instant readInstant(ByteBuffer input) throws IOException {
        long seconds = input.getLong();
        int nanos = input.getInt();
        if (seconds < 0L || seconds > MAXIMUM_EPOCH_SECOND
                || nanos < 0 || nanos > 999_999_999) {
            throw malformed();
        }
        return Instant.ofEpochSecond(seconds, nanos);
    }

    private static boolean readBoolean(ByteBuffer input) throws IOException {
        byte value = input.get();
        if (value != 0 && value != 1) {
            throw malformed();
        }
        return value == 1;
    }

    private static String readHash(ByteBuffer input) throws IOException {
        if (input.remaining() < SHA_256_BYTES) {
            throw malformed();
        }
        byte[] value = new byte[SHA_256_BYTES];
        input.get(value);
        return HEX.formatHex(value);
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
            throw new IllegalArgumentException("Confirmation metadata is not strict UTF-8", impossible);
        }
    }

    private static IOException malformed() {
        return new IOException("Credential confirmation lifecycle metadata is malformed");
    }
}
