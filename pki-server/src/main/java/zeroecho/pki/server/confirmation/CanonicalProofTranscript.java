/* *****************************************************************************
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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.regex.Pattern;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;

/** Canonical immutable signature input for credential key-possession proof v1. */
final class CanonicalProofTranscript {

    /* default */ static final int VERSION = 1;
    /* default */ static final String PURPOSE = "credential-key-possession-confirmation";
    /* default */ static final int MAXIMUM_ENCODED_BYTES = 2_048;

    private static final byte[] MAGIC = { 'Z', 'E', 'P', 'P' };
    private static final byte[] PURPOSE_BYTES = PURPOSE.getBytes(StandardCharsets.US_ASCII);
    private static final int FIELD_COUNT = 9;
    private static final int MAXIMUM_AUDIENCE_BYTES = 512;
    private static final long MAXIMUM_EPOCH_SECOND = 253_402_300_799L;
    private static final Pattern X509_CREDENTIAL_ID = Pattern.compile("x509:[0-9a-f]{64}");

    private final ProofSuiteDescriptor descriptor;
    private final Instant expiresAt;
    private final byte[] encoded;

    /* default */ CanonicalProofTranscript(ConfirmationRealmBinding realmId,
            String serverAudience, PkiId credentialId,
            ProofSuiteDescriptor descriptor, byte[] randomChallenge, Instant expiresAt) {
        Objects.requireNonNull(realmId, "realmId");
        Objects.requireNonNull(credentialId, "credentialId");
        this.descriptor = Objects.requireNonNull(descriptor, "descriptor");
        this.expiresAt = requireExpiry(expiresAt);
        byte[] audience = requireAudience(serverAudience);
        if (!X509_CREDENTIAL_ID.matcher(credentialId.value()).matches()) {
            throw new IllegalArgumentException("Credential identity must be the SHA-256 digest of canonical X.509 DER");
        }
        if (randomChallenge == null || randomChallenge.length != descriptor.challengeBytes()) {
            throw new IllegalArgumentException("Random challenge has an invalid length");
        }
        this.encoded = encode(realmId, audience, credentialId, descriptor, randomChallenge, this.expiresAt);
    }

    /* default */ ProofSuiteDescriptor descriptor() {
        return descriptor;
    }

    /* default */ Instant expiresAt() {
        return expiresAt;
    }

    /* default */ byte[] encoded() {
        return encoded.clone();
    }

    /* default */ void clear() {
        Arrays.fill(encoded, (byte) 0);
    }

    /**
     * Decodes and canonicalizes one bounded transcript for an exact suite profile.
     *
     * <p>Every tag, length, fixed value, bounded text field, and terminal byte is
     * validated before the transcript is reconstructed. The reconstruction must
     * then reproduce the input byte for byte.</p>
     *
     * @param encodedBytes caller-owned encoded transcript; never retained or modified
     * @param expectedDescriptor exact locally configured proof-suite profile
     * @return immutable decoded transcript
     * @throws IllegalArgumentException if the transcript is malformed, noncanonical,
     *         oversized, or identifies another suite profile
     */
    /* default */ static CanonicalProofTranscript decode(byte[] encodedBytes,
            ProofSuiteDescriptor expectedDescriptor) {
        return CanonicalProofTranscriptDecoder.decode(encodedBytes, expectedDescriptor);
    }

    private static byte[] encode(ConfirmationRealmBinding realmId, byte[] audience, PkiId credentialId,
            ProofSuiteDescriptor descriptor, byte[] challenge, Instant expiresAt) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream(512);
            DataOutputStream output = new DataOutputStream(buffer);
            output.write(MAGIC);
            output.writeShort(FIELD_COUNT);
            field(output, 1, integer(VERSION));
            field(output, 2, PURPOSE_BYTES);
            field(output, 3, realmId.value().getBytes(StandardCharsets.US_ASCII));
            field(output, 4, audience);
            field(output, 5, credentialId.value().getBytes(StandardCharsets.US_ASCII));
            field(output, 6, descriptor.suiteId().value().getBytes(StandardCharsets.US_ASCII));
            field(output, 7, descriptor.configurationCommitment().bytes());
            field(output, 8, challenge);
            field(output, 9, expiry(expiresAt));
            output.flush();
            byte[] result = buffer.toByteArray();
            if (result.length > MAXIMUM_ENCODED_BYTES) {
                throw new IllegalArgumentException("Canonical proof transcript exceeds its size limit");
            }
            return result;
        } catch (IOException impossible) {
            throw new IllegalStateException("In-memory proof transcript encoding failed", impossible);
        }
    }

    private static void field(DataOutputStream output, int tag, byte[] value) throws IOException {
        output.writeByte(tag);
        output.writeInt(value.length);
        output.write(value);
    }

    private static byte[] integer(int value) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(Integer.BYTES);
        DataOutputStream output = new DataOutputStream(buffer);
        output.writeInt(value);
        output.flush();
        return buffer.toByteArray();
    }

    private static byte[] expiry(Instant value) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(Long.BYTES + Integer.BYTES);
        DataOutputStream output = new DataOutputStream(buffer);
        output.writeLong(value.getEpochSecond());
        output.writeInt(value.getNano());
        output.flush();
        return buffer.toByteArray();
    }

    private static Instant requireExpiry(Instant value) {
        Objects.requireNonNull(value, "expiresAt");
        if (value.getEpochSecond() < 0 || value.getEpochSecond() > MAXIMUM_EPOCH_SECOND || value.getNano() != 0) {
            throw new IllegalArgumentException("Proof expiry must be a whole second in the supported UTC range");
        }
        return value;
    }

    private static byte[] requireAudience(String value) {
        Objects.requireNonNull(value, "serverAudience");
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        if (encoded.length == 0 || encoded.length > MAXIMUM_AUDIENCE_BYTES
                || !StandardCharsets.UTF_8.newEncoder().canEncode(value)
                || value.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Server audience is not canonical");
        }
        return encoded;
    }
}
