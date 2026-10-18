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

package zeroecho.pki.impl.core.continuation;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.time.Instant;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment;

/**
 * Strict version-two, big-endian managed-key proof challenge codec. UTF-8 and DER
 * fields use unsigned 32-bit byte lengths; the nonce and configuration commitment
 * each occupy exactly 32 unframed bytes. Complete input must end after SPKI DER.
 * Structure is configuration-independent; installed algorithm semantics must be
 * checked separately by preparation and terminal verification. Work and auxiliary
 * memory are O(challenge bytes), with finite bounds checked before allocation.
 */
public final class ManagedKeyProofChallenge {
    private static final int CONTEXT_PRESENT = 1;
    private static final byte[] MAGIC = "ZEROECHO-MANAGED-KEY-PROOF\0".getBytes(StandardCharsets.US_ASCII);
    private static final int VERSION = 2;
    /** Required nonce length, in bytes. */
    public static final int NONCE_BYTES = 32;

    private ManagedKeyProofChallenge() { }

    /**
     * Encodes one exact challenge after all framing and aggregate bounds checks.
     * The caller supplies a fresh SecureRandom nonce for each preparation.
     * @param operationId exact internal signing submission ID
     * @param deadline exact accepted signing deadline
     * @param context absent for standalone proof, otherwise exact parent CA context
     * @param metadata exactly fields 0 through 9 of the frozen proof command
     * @param nonce exactly 32 bytes, borrowed for this call
     * @param spki canonical SubjectPublicKeyInfo DER, borrowed for this call
     * @return independently owned complete binary challenge
     * @throws IllegalArgumentException if framing, coordinates or DER are invalid
     */
    public static byte[] encode(PkiId operationId, Instant deadline, Optional<CaContext> context,
            List<String> metadata, byte[] nonce, byte[] spki) {
        DomainCommandEncoding.Decoded command = new DomainCommandEncoding.Decoded(ManagedKeyProofCommand.OPERATION,
                metadata).requireFields(10);
        ManagedKeyProofCommand.validateMetadata(command);
        requireOperation(operationId, command.field(6));
        requireContext(operationId, deadline, context);
        if (Objects.requireNonNull(nonce, "nonce").length != NONCE_BYTES) { throw invalid(); }
        requireSpki(spki);
        byte[] algorithm = ManagedKeyProofCommand.hex(command.field(9), 1,
                ManagedKeyProofCommand.MAX_ALGORITHM_DER_BYTES);
        long size = MAGIC.length + 4L + 4L + ManagedKeyProofCommand.utf8Length(operationId.value(), 4096)
                + 12L + 1L + NONCE_BYTES + 32L + 4L + algorithm.length + 4L + spki.length;
        if (context.isPresent()) {
            size += 4L + ManagedKeyProofCommand.utf8Length(context.orElseThrow().parentId().value(), 4096) + 32L;
        }
        for (int index = 0; index <= 6; index++) {
            size += 4L + ManagedKeyProofCommand.utf8Length(command.field(index), ManagedKeyProofCommand.MAX_COMMAND_BYTES);
        }
        size += 4L + ManagedKeyProofCommand.utf8Length(command.field(8), 8192);
        if (size > ManagedKeyProofCommand.MAX_CHALLENGE_BYTES) { throw invalid(); }
        // Validate the final command bound before allocating the challenge itself.
        ManagedKeyProofCommand.validateComplete(complete(metadata, spki, (int) size, "0".repeat(64)));
        ByteBuffer output = ByteBuffer.allocate((int) size);
        output.put(MAGIC).putInt(VERSION);
        write(output, operationId.value().getBytes(StandardCharsets.UTF_8));
        output.putLong(deadline.getEpochSecond()).putInt(deadline.getNano());
        output.put((byte) (context.isPresent() ? 1 : 0));
        if (context.isPresent()) {
            write(output, context.orElseThrow().parentId().value().getBytes(StandardCharsets.UTF_8));
            output.put(HexFormat.of().parseHex(context.orElseThrow().intentCommitment().substring("ca-intent:v1:".length())));
        }
        output.put(nonce);
        for (int index = 0; index <= 6; index++) {
            write(output, command.field(index).getBytes(StandardCharsets.UTF_8));
        }
        output.put(ManagedKeyProofCommand.hex(command.field(7), 32, 32));
        write(output, command.field(8).getBytes(StandardCharsets.UTF_8));
        write(output, algorithm);
        write(output, spki);
        return output.array();
    }

    /**
     * Decodes exact framing and reconstructs all 14 command commitments.
     * No runtime provider lookup, acceptance or signature verification is performed.
     * @param challenge bounded complete binary challenge, borrowed for this call
     * @return immutable independently owned decoded challenge
     * @throws IllegalArgumentException if framing, UTF-8, schema, bounds or DER are invalid
     */
    public static Decoded decode(byte[] challenge) {
        Objects.requireNonNull(challenge, "challenge");
        if (challenge.length == 0 || challenge.length > ManagedKeyProofCommand.MAX_CHALLENGE_BYTES) { throw invalid(); }
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(challenge))) {
            if (!Arrays.equals(input.readNBytes(MAGIC.length), MAGIC) || input.readInt() != VERSION) { throw invalid(); }
            PkiId operationId = new PkiId(readText(input, 4096));
            long seconds = input.readLong();
            int nanos = input.readInt();
            if (nanos < 0 || nanos >= 1_000_000_000) { throw invalid(); }
            Instant deadline = Instant.ofEpochSecond(seconds, nanos);
            Optional<CaContext> context = readContext(input);
            requireContext(operationId, deadline, context);
            byte[] nonce = exact(input, NONCE_BYTES);
            List<String> metadata = new ArrayList<>(10);
            for (int index = 0; index <= 6; index++) {
                metadata.add(readText(input, ManagedKeyProofCommand.MAX_COMMAND_BYTES));
            }
            metadata.add(HexFormat.of().formatHex(exact(input, 32)));
            metadata.add(readText(input, 8192));
            metadata.add(HexFormat.of().formatHex(read(input, ManagedKeyProofCommand.MAX_ALGORITHM_DER_BYTES)));
            byte[] spki = read(input, ManagedKeyProofCommand.MAX_SPKI_BYTES);
            if (input.available() != 0) { throw invalid(); }
            requireSpki(spki);
            requireOperation(operationId, metadata.get(6));
            DomainCommandEncoding.Decoded command = complete(metadata, spki, challenge.length,
                    ContentCommitment.sha256(challenge).sha256());
            ManagedKeyProofCommand.validateComplete(command);
            return new Decoded(operationId, deadline, context, nonce, command, spki);
        } catch (IOException | java.time.DateTimeException malformed) {
            throw new IllegalArgumentException("Managed key proof challenge is truncated or invalid", malformed);
        }
    }

    /**
     * Exact immutable decoded challenge, with defensive byte-array copies.
     * @param operationId exact signing submission ID
     * @param deadline frozen accepted deadline
     * @param context optional internal CA context
     * @param nonce exact challenge nonce
     * @param command complete reconstructed metadata and commitments
     * @param spki canonical public-key DER
     */
    public record Decoded(PkiId operationId, Instant deadline, Optional<CaContext> context,
            byte[] nonce, DomainCommandEncoding.Decoded command, byte[] spki) {
        /** Snapshots decoded values; construct through {@link #decode(byte[])} for validation. */
        public Decoded {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(deadline, "deadline");
            Objects.requireNonNull(context, "context");
            Objects.requireNonNull(command, "command");
            nonce = nonce.clone();
            spki = spki.clone();
        }
        /** {@return a defensive copy of the challenge nonce} */
        @Override public byte[] nonce() { return nonce.clone(); }
        /** {@return a defensive copy of the subject public-key encoding} */
        @Override public byte[] spki() { return spki.clone(); }
        @Override public String toString() { return "ManagedKeyProofChallenge.Decoded[redacted]"; }
    }

    /**
     * Acyclic immutable context of an internal CA proof challenge.
     * @param parentId distinct parent signing operation
     * @param intentCommitment exact domain-separated final CA/TBS intent commitment
     */
    public record CaContext(PkiId parentId, String intentCommitment) {
        /** Validates canonical bounded context without store or algorithm lookup. */
        public CaContext {
            SigningSubmissionId parent = SigningSubmissionId.parse(Objects.requireNonNull(parentId, "parentId"));
            requireOperation(parentId, parent.namespace());
            if (intentCommitment == null || !intentCommitment.matches("ca-intent:v1:[0-9a-f]{64}")) { throw invalid(); }
        }
        @Override public String toString() { return "ManagedKeyProofChallenge.CaContext[redacted]"; }
    }

    private static void requireContext(PkiId stepId, Instant deadline, Optional<CaContext> context) {
        SigningSubmissionId step = SigningSubmissionId.parse(stepId);
        Objects.requireNonNull(context, "context");
        if (!Objects.requireNonNull(deadline, "deadline").isAfter(step.createdAt())) { throw invalid(); }
        if (context.isPresent()) {
            SigningSubmissionId parent = SigningSubmissionId.parse(context.orElseThrow().parentId());
            if (stepId.equals(parent.id()) || !step.namespace().equals(parent.namespace())
                    || !deadline.isAfter(parent.createdAt())) { throw invalid(); }
        }
    }

    private static DomainCommandEncoding.Decoded complete(List<String> metadata, byte[] spki, int length, String digest) {
        List<String> fields = new ArrayList<>(metadata);
        fields.add(Integer.toString(spki.length));
        fields.add(ContentCommitment.sha256(spki).sha256());
        fields.add(Integer.toString(length));
        fields.add(digest);
        return new DomainCommandEncoding.Decoded(ManagedKeyProofCommand.OPERATION, fields);
    }

    /* default */ static void requireOperation(PkiId id, String namespace) {
        ManagedKeyProofCommand.utf8Length(id.value(), 4096);
        SigningSubmissionId parsed = SigningSubmissionId.parse(id);
        String exact = "zsign:v1:" + parsed.namespace() + ':' + parsed.createdAt().toEpochMilli() + ':'
                + id.value().substring(id.value().lastIndexOf(':') + 1).toLowerCase(java.util.Locale.ROOT);
        if (!namespace.equals(parsed.namespace()) || !exact.equals(id.value())) { throw invalid(); }
    }

    private static void requireSpki(byte[] spki) {
        Objects.requireNonNull(spki, "spki");
        if (spki.length == 0 || spki.length > ManagedKeyProofCommand.MAX_SPKI_BYTES) { throw invalid(); }
        try {
            new StreamingDerReader().validateSubjectPublicKeyInfo(spki, ManagedKeyProofCommand.MAX_SPKI_BYTES);
        } catch (IOException malformed) {
            throw new IllegalArgumentException("Managed key proof public key is not canonical DER", malformed);
        }
    }

    private static void write(ByteBuffer output, byte[] bytes) { output.putInt(bytes.length).put(bytes); }

    private static byte[] read(DataInputStream input, int maximum) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > maximum || length > input.available()) { throw invalid(); }
        return exact(input, length);
    }

    private static byte[] exact(DataInputStream input, int length) throws IOException {
        if (length > input.available()) { throw invalid(); }
        return input.readNBytes(length);
    }

    private static String readText(DataInputStream input, int maximum) throws IOException {
        byte[] bytes = read(input, maximum);
        String value = new String(bytes, StandardCharsets.UTF_8);
        if (!Arrays.equals(bytes, value.getBytes(StandardCharsets.UTF_8))) { throw invalid(); }
        return value;
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Managed key proof challenge is invalid");
    }

    private static Optional<CaContext> readContext(DataInputStream input) throws IOException {
        int contextFlag = input.readUnsignedByte();
        if (contextFlag > CONTEXT_PRESENT) { throw invalid(); }
        return contextFlag == CONTEXT_PRESENT
                ? Optional.of(new CaContext(new PkiId(readText(input, 4096)),
                        "ca-intent:v1:" + HexFormat.of().formatHex(exact(input, 32)))) : Optional.empty();
    }
}
