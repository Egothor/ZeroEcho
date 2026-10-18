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

package zeroecho.pki.server.enrollment;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import zeroecho.pki.server.ServerControlStore;

/** Strict bounded descriptor format; all noncanonical or old-version input fails closed. */
final class EnrollmentKeygenCodec {
    private static final int VERSION = 1;
    private EnrollmentKeygenCodec() { }
    /* default */ static ServerControlStore.ProtocolRecord record(EnrollmentKeygenArtifact value) {
        byte[] payload = encode(value);
        return new ServerControlStore.ProtocolRecord(ServerControlStore.ENROLLMENT_KEYGEN, value.id(),
                EnrollmentTransactionCodec.sha256(payload), payload);
    }
    /* default */ static EnrollmentKeygenArtifact decode(ServerControlStore.ProtocolRecord record) {
        byte[] bytes = record.payload();
        if (!ServerControlStore.ENROLLMENT_KEYGEN.equals(record.namespace()) || bytes.length > EnrollmentTransactionCodec.MAXIMUM_BYTES
                || !record.commitment().equals(EnrollmentTransactionCodec.sha256(bytes))) {
            throw EnrollmentTransaction.invalid();
        }
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
            if (in.readInt() != VERSION) {
                throw EnrollmentTransaction.invalid();
            }
            String id = in.readUTF(); long revision = in.readLong();
            EnrollmentTransaction.Intent template = EnrollmentTransactionCodec.intent(in);
            String algorithm = in.readUTF(); int bits = in.readInt(); long ciphertext = in.readLong(); int csr = in.readInt();
            Instant deadline = instant(in);
            EnrollmentKeygenArtifact.State state = EnrollmentKeygenArtifact.State.valueOf(in.readUTF());
            Optional<EnrollmentTransaction.ArtifactBinding> artifact = in.readBoolean() ? Optional.of(
                    new EnrollmentTransaction.ArtifactBinding(in.readUTF(), in.readUTF(), in.readUTF(), in.readLong())) : Optional.empty();
            EnrollmentKeygenArtifact value = new EnrollmentKeygenArtifact(id, revision, template, algorithm, bits, ciphertext, csr,
                    deadline, state, artifact, in.readBoolean());
            if (in.read() != -1 || !id.equals(record.recordId()) || !Arrays.equals(bytes, encode(value))) {
                throw EnrollmentTransaction.invalid();
            }
            return value;
        } catch (IOException | IllegalArgumentException invalid) { throw EnrollmentTransaction.invalid(); } // NOPMD ExceptionAsFlowControl, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }
    /* default */ static byte[] encode(EnrollmentKeygenArtifact value) {
        return bytes(out -> {
            out.writeInt(VERSION); out.writeUTF(value.id()); out.writeLong(value.revision());
            frozen(out, value.template(), value.algorithm(), value.maximumKeySizeBits(), value.maximumCiphertextBytes(),
                    value.maximumGeneratedRequestBytes(), value.deliveryDeadline());
            out.writeUTF(value.state().name()); out.writeBoolean(value.artifact().isPresent());
            if (value.artifact().isPresent()) {
                EnrollmentTransaction.ArtifactBinding binding = value.artifact().orElseThrow();
                out.writeUTF(binding.artifactId()); out.writeUTF(binding.generationCommitment()); out.writeUTF(binding.ciphertextSha256());
                out.writeLong(binding.ciphertextBytes());
            }
            out.writeBoolean(value.bytesReleased());
        });
    }
    /* default */ static String generationCommitment(EnrollmentTransaction.Intent template, String algorithm, int bits, long ciphertext,
            int csr, Instant deadline) {
        return EnrollmentTransactionCodec.sha256(bytes(out -> {
            out.writeUTF("zeroecho.enrollment-keygen.v1"); frozen(out, template, algorithm, bits, ciphertext, csr, deadline);
        }));
    }
    private static void frozen(DataOutputStream out, EnrollmentTransaction.Intent template, String algorithm, int bits,
            long ciphertext, int csr, Instant deadline) throws IOException {
        EnrollmentTransactionCodec.intent(out, template); out.writeUTF(algorithm); out.writeInt(bits); out.writeLong(ciphertext);
        out.writeInt(csr); out.writeLong(deadline.getEpochSecond()); out.writeInt(deadline.getNano());
    }
    private static Instant instant(DataInputStream in) throws IOException {
        long seconds = in.readLong(); int nanos = in.readInt();
        if (nanos < 0 || nanos >= 1_000_000_000) {
            throw EnrollmentTransaction.invalid();
        }
        return Instant.ofEpochSecond(seconds, nanos);
    }
    private static byte[] bytes(Encoder encoder) {
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream(); DataOutputStream out = new DataOutputStream(bytes)) {
            encoder.encode(out); out.flush();
            if (bytes.size() > EnrollmentTransactionCodec.MAXIMUM_BYTES) {
                throw EnrollmentTransaction.invalid();
            }
            return bytes.toByteArray();
        } catch (IOException invalid) { throw EnrollmentTransaction.invalid(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }
    /** Encodes one canonical record into an owned output buffer. */
    @FunctionalInterface private interface Encoder {
        /**
         * Writes the canonical binary representation.
         * @param out borrowed output
         * @throws IOException if encoding fails
         */
        void encode(DataOutputStream out) throws IOException;
    }
}
