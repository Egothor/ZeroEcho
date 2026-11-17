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

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Encodes and decodes the version-two, version-three and version-four managed-key proof challenges.
 *
 * <p>Integers use big-endian byte order. UTF-8 and DER fields use nonnegative
 * 32-bit byte lengths; the nonce and configuration commitment
 * each occupy exactly 32 unframed bytes. Complete input must end after SPKI DER.
 * Structure is configuration-independent; installed algorithm semantics must be
 * checked separately by preparation and terminal verification. Work and auxiliary
 * memory are O(challenge bytes), with finite bounds checked before allocation.
 */
public final class ManagedKeyProofChallenge {
    private static final String OCSP_CANDIDATE_KIND = "OCSP_RESPONDER_CANDIDATE_KEY";
    private static final int CHALLENGE_VERSION = 1;
    private static final int CONTEXT_PRESENT = 1;
    private static final byte[] MAGIC = "ZEROECHO-MANAGED-KEY-PROOF\0".getBytes(StandardCharsets.US_ASCII);
    private static final int VERSION = 2;
    private static final int ROLE_CONTEXT_VERSION = 3;
    private static final int RESPONDER_CONTEXT_VERSION = 4;
    /**
     * Required length, in bytes, of each caller-supplied challenge nonce.
     */
    public static final int NONCE_BYTES = 32;

    private ManagedKeyProofChallenge() {
    }

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
     * @throws NullPointerException if a required argument or metadata entry is null
     * @throws IllegalArgumentException if framing, coordinates or DER are invalid
     */
    public static byte[] encode(PkiId operationId, Instant deadline, Optional<CaContext> context,
            List<String> metadata, byte[] nonce, byte[] spki) {
        DomainCommandEncoding.Decoded command = new DomainCommandEncoding.Decoded(ManagedKeyProofCommand.OPERATION,
                metadata).requireFields(10);
        ManagedKeyProofCommand.validateMetadata(command);
        if (OCSP_CANDIDATE_KIND.equals(command.field(0))) {
            throw invalid();
        }
        requireOperation(operationId, command.field(6));
        requireContext(operationId, deadline, context);
        if (Objects.requireNonNull(nonce, "nonce").length != NONCE_BYTES) {
            throw invalid();
        }
        requireSpki(spki);
        byte[] algorithm = ManagedKeyProofCommand.hex(command.field(9), 1,
                ManagedKeyProofCommand.MAX_ALGORITHM_DER_BYTES);
        long size = MAGIC.length + 4L + 4L + ManagedKeyProofCommand.utf8Length(operationId.value(), 4096)
                + 12L + 1L + NONCE_BYTES + 32L + 4L + algorithm.length + 4L + spki.length;
        boolean roleContext = context.flatMap(CaContext::role).isPresent();
        if (context.isPresent()) {
            size += 4L + ManagedKeyProofCommand.utf8Length(context.orElseThrow().parentId().value(), 4096) + 32L;
            if (roleContext) {
                size += 33;
            }
        }
        for (int index = 0; index <= 6; index++) {
            size += 4L + ManagedKeyProofCommand.utf8Length(command.field(index), ManagedKeyProofCommand.MAX_COMMAND_BYTES);
        }
        size += 4L + ManagedKeyProofCommand.utf8Length(command.field(8), 8192);
        if (size > ManagedKeyProofCommand.MAX_CHALLENGE_BYTES) {
            throw invalid();
        }
        // Validate the final command bound before allocating the challenge itself.
        ManagedKeyProofCommand.validateComplete(complete(metadata, spki, (int) size, "0".repeat(64)));
        ByteBuffer output = ByteBuffer.allocate((int) size);
        output.put(MAGIC).putInt(roleContext ? ROLE_CONTEXT_VERSION : VERSION);
        write(output, operationId.value().getBytes(StandardCharsets.UTF_8));
        output.putLong(deadline.getEpochSecond()).putInt(deadline.getNano());
        output.put((byte) (context.isPresent() ? 1 : 0));
        if (context.isPresent()) {
            write(output, context.orElseThrow().parentId().value().getBytes(StandardCharsets.UTF_8));
            output.put(HexFormat.of().parseHex(context.orElseThrow().intentCommitment().substring("ca-intent:v1:".length())));
            if (roleContext) {
                output.put(
                        (byte)
                                (context.orElseThrow().role().orElseThrow()
                                                == zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole.PRIMARY
                                        ? 1
                                        : 2));
                output.put(HexFormat.of().parseHex(context.orElseThrow().lifecycleContextCommitment().orElseThrow()));
            }
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
     * Encodes a version-four proof for a managed responder key before certificate issuance.
     *
     * <p>The frozen metadata must select the same responder candidate as the supplied
     * context. The child operation must differ from its parent, share its namespace
     * and have a deadline later than both operation creation times. The caller supplies
     * a fresh random nonce; this method neither obtains randomness nor signs the challenge.
     *
     * @param operationId canonical child signing-submission identity
     * @param deadline exact signing deadline, later than child and parent creation
     * @param context frozen parent, subject-role and final-candidate context
     * @param metadata exactly the ten frozen proof-command metadata fields
     * @param nonce fresh 32-byte nonce, borrowed for this call
     * @param spki canonical managed SubjectPublicKeyInfo DER, borrowed for this call
     * @return an independently owned complete version-four binary challenge
     * @throws NullPointerException if a required argument or metadata entry is null
     * @throws IllegalArgumentException if the candidate, operation context, framing,
     *         aggregate bounds or public-key DER is inconsistent or invalid
     */
    public static byte[] encodeCandidate(PkiId operationId, Instant deadline, ResponderCandidateContext context,
            List<String> metadata, byte[] nonce, byte[] spki) {
        DomainCommandEncoding.Decoded command = new DomainCommandEncoding.Decoded(ManagedKeyProofCommand.OPERATION,
                metadata).requireFields(10);
        ManagedKeyProofCommand.validateMetadata(command);
        if (!(ManagedKeyProofCommand.decodePrefix(command)
                        instanceof zeroecho.pki.api.signing.ManagedKeyProofRequest.OcspResponderCandidate candidate)
                || !candidate.target().equals(context.target())) {
            throw invalid();
        }
        requireOperation(operationId, command.field(6));
        requireResponderContext(operationId, deadline, context);
        if (Objects.requireNonNull(nonce, "nonce").length != NONCE_BYTES) {
            throw invalid();
        }
        requireSpki(spki);
        byte[] algorithm = ManagedKeyProofCommand.hex(command.field(9), 1, ManagedKeyProofCommand.MAX_ALGORITHM_DER_BYTES);
        long size = MAGIC.length + 4L + 4L + ManagedKeyProofCommand.utf8Length(operationId.value(), 4096)
                + 12L + 1L + 4L + ManagedKeyProofCommand.utf8Length(context.parentOperationId().value(), 4096)
                + 32L + 1L + 32L + NONCE_BYTES + 32L + 4L + algorithm.length + 4L + spki.length;
        for (int index = 0; index <= 6; index++) {
            size += 4L + ManagedKeyProofCommand.utf8Length(command.field(index), ManagedKeyProofCommand.MAX_COMMAND_BYTES);
        }
        size += 4L + ManagedKeyProofCommand.utf8Length(command.field(8), 8192);
        if (size > ManagedKeyProofCommand.MAX_CHALLENGE_BYTES) {
            throw invalid();
        }
        ManagedKeyProofCommand.validateComplete(complete(metadata, spki, (int) size, "0".repeat(64)));
        ByteBuffer output = ByteBuffer.allocate((int) size);
        output.put(MAGIC).putInt(RESPONDER_CONTEXT_VERSION);
        write(output, operationId.value().getBytes(StandardCharsets.UTF_8));
        output.putLong(deadline.getEpochSecond()).putInt(deadline.getNano()).put((byte) 1);
        write(output, context.parentOperationId().value().getBytes(StandardCharsets.UTF_8));
        output.put(HexFormat.of().parseHex(context.parentIntentCommitment().substring("ocsp-intent:v1:".length())));
        output.put((byte) (context.role() == zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole.PRIMARY ? 1 : 2));
        output.put(HexFormat.of().parseHex(context.frozenTargetCommitment())).put(nonce);
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
     * @throws NullPointerException if the challenge is null
     * @throws IllegalArgumentException if framing, UTF-8, schema, bounds or DER are invalid
     */
    public static Decoded decode(byte[] challenge) {
        return Decoder.decode(challenge);
    }

    /**
     * Exact immutable decoded challenge, with defensive byte-array copies.
     * @param operationId exact signing submission ID
     * @param deadline frozen accepted deadline
     * @param context optional internal CA context
     * @param nonce exact challenge nonce
     * @param command complete reconstructed metadata and commitments
     * @param spki canonical public-key DER
     * @param candidateContext present only for version-four responder candidate proofs
     */
    public record Decoded(PkiId operationId, Instant deadline, Optional<CaContext> context,
            byte[] nonce, DomainCommandEncoding.Decoded command, byte[] spki, Optional<ResponderCandidateContext> candidateContext) {
        /**
         * Creates a decoded carrier without a version-four responder-candidate context.
         *
         * <p>The byte arrays are copied. As with the canonical constructor, this
         * overload does not validate binary framing or command commitments; callers
         * decoding untrusted bytes must use {@link ManagedKeyProofChallenge#decode(byte[])}.
         *
         * @param operationId retained proof signing-submission identity
         * @param deadline frozen signing deadline
         * @param context retained CA context, or an empty optional; must not be null
         * @param nonce challenge nonce, copied on construction
         * @param command reconstructed proof command
         * @param spki subject public-key DER, copied on construction
         * @throws NullPointerException if any argument is null
         */
        public Decoded(PkiId operationId, Instant deadline, Optional<CaContext> context, byte[] nonce,
                DomainCommandEncoding.Decoded command, byte[] spki) {
            this(operationId, deadline, context, nonce, command, spki, Optional.empty());
        }
        /**
         * Snapshots the byte arrays and requires mutually exclusive parent-context variants.
         *
         * <p>This constructor checks presence, not challenge framing or cryptographic
         * validity. Use {@link ManagedKeyProofChallenge#decode(byte[])} to obtain a
         * carrier from a validated challenge encoding.
         *
         * @throws NullPointerException if any component is null
         * @throws IllegalArgumentException if both parent-context variants are present
         * @param operationId exact signing submission ID
         * @param deadline frozen accepted deadline
         * @param context optional internal CA context
         * @param nonce exact challenge nonce
         * @param command complete reconstructed metadata and commitments
         * @param spki canonical public-key DER
         * @param candidateContext present only for version-four responder candidate proofs
         */
        public Decoded {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(deadline, "deadline");
            Objects.requireNonNull(context, "context");
            Objects.requireNonNull(command, "command");
            Objects.requireNonNull(candidateContext, "candidateContext");
            if (context.isPresent() && candidateContext.isPresent()) {
                throw invalid();
            }
            nonce = nonce.clone();
            spki = spki.clone();
        }
        /**
         * Returns a copy of the retained challenge nonce.
         *
         * @return an independently owned nonce array
         */
        @Override
        public byte[] nonce() {
            return nonce.clone();
        }
        /**
         * Returns a copy of the retained subject public-key encoding.
         *
         * @return an independently owned SubjectPublicKeyInfo byte array
         */
        @Override
        public byte[] spki() {
            return spki.clone();
        }
        /**
         * Returns a diagnostic label without disclosing the nonce or proof coordinates.
         *
         * @return the fixed redacted decoded-challenge label
         */
        @Override
        public String toString() {
            return "ManagedKeyProofChallenge.Decoded[redacted]";
        }
    }

    /**
     * Retains the parent context for an internal CA subject-key proof challenge.
     *
     * <p>Version two omits both role-specific coordinates. Version three supplies both the subject
     * role and its lifecycle commitment. Encoding or decoding the complete challenge additionally
     * checks that child and parent are distinct and share a signing namespace; this record alone
     * cannot establish that relationship.
     *
     * @param parentId canonical parent signing-operation identity
     * @param intentCommitment exact domain-separated final CA/TBS intent commitment
     * @param role absent for byte-exact v2; explicit subject role for v3
     * @param lifecycleContextCommitment absent for v2; frozen lifecycle/TBS context SHA-256 for v3
     */
    public record CaContext(
            PkiId parentId,
            String intentCommitment,
            Optional<zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole> role,
            Optional<String> lifecycleContextCommitment) {
        /**
         * Validates canonical parent identity and paired role-context commitments.
         *
         * <p>No store, provider or algorithm lookup is performed.
         *
         * @throws NullPointerException if the parent or either optional is null
         * @throws IllegalArgumentException if the parent identity or commitment encoding
         *         is invalid, or only one role-context coordinate is present
         * @param parentId canonical parent signing-operation identity
         * @param intentCommitment exact domain-separated final CA/TBS intent commitment
         * @param role absent for byte-exact v2; explicit subject role for v3
         * @param lifecycleContextCommitment absent for v2; frozen lifecycle/TBS context SHA-256 for v3
         */
        public CaContext {
            SigningSubmissionId parent =
                    SigningSubmissionId.parse(Objects.requireNonNull(parentId, "parentId"));
            requireOperation(parentId, parent.namespace());
            if (intentCommitment == null
                    || !intentCommitment.matches("ca-intent:v1:[0-9a-f]{64}")) {
                throw invalid();
            }
            Objects.requireNonNull(role, "role");
            Objects.requireNonNull(lifecycleContextCommitment, "lifecycleContextCommitment");
            if (role.isPresent() != lifecycleContextCommitment.isPresent()
                    || lifecycleContextCommitment
                            .filter(value -> !value.matches("[0-9a-f]{64}"))
                            .isPresent()) {
                throw invalid();
            }
        }
        /**
         * Creates the version-two parent context without role-specific coordinates.
         *
         * @param parentId canonical parent signing-operation identity
         * @param intentCommitment exact {@code ca-intent:v1:} commitment
         * @throws NullPointerException if the parent identity is null
         * @throws IllegalArgumentException if the parent identity or intent encoding is invalid
         */
        public CaContext(PkiId parentId, String intentCommitment) {
            this(parentId, intentCommitment, Optional.empty(), Optional.empty());
        }
        /**
         * Returns a diagnostic label without disclosing parent or commitment coordinates.
         *
         * @return the fixed redacted CA-context label
         */
        @Override
        public String toString() {
            return "ManagedKeyProofChallenge.CaContext[redacted]";
        }
    }

    /**
     * Retains the version-four responder proof context before a certificate exists.
     *
     * <p>The context binds a real parent signing operation and frozen candidate, rather than
     * representing the candidate as an already-issued responder credential.
     *
     * @param parentOperationId canonical parent signing-operation identity
     * @param parentIntentCommitment exact {@code ocsp-intent:v1:} responder-command commitment
     * @param role primary or alternative subject-key role being proved
     * @param frozenTargetCommitment final TBS and selection digest as 64 lowercase hexadecimal
     *     characters
     */
    public record ResponderCandidateContext(
            PkiId parentOperationId,
            String parentIntentCommitment,
            zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole role,
            String frozenTargetCommitment) {
        /**
         * Validates the coordinates using the managed responder proof-target contract.
         *
         * @throws NullPointerException if the parent identity or subject role is null
         * @throws IllegalArgumentException if the parent identity or commitment encoding is invalid
         * @param parentOperationId canonical parent signing-operation identity
         * @param parentIntentCommitment exact {@code ocsp-intent:v1:} responder-command commitment
         * @param role primary or alternative subject-key role being proved
         * @param frozenTargetCommitment final TBS and selection digest as 64 lowercase hexadecimal characters
         */
        public ResponderCandidateContext {
            new zeroecho.pki.api.signing.ManagedOcspResponderProofTarget(
                    parentOperationId, parentIntentCommitment, frozenTargetCommitment, role);
        }

        /**
         * Reconstructs the exact typed scope target represented by this context.
         *
         * @return a new immutable proof target with the same parent, commitments and role
         */
        public zeroecho.pki.api.signing.ManagedOcspResponderProofTarget target() {
            return new zeroecho.pki.api.signing.ManagedOcspResponderProofTarget(
                    parentOperationId, parentIntentCommitment, frozenTargetCommitment, role);
        }
    }
    private static void requireResponderContext(PkiId stepId, Instant deadline, ResponderCandidateContext context) {
        Objects.requireNonNull(context, "context");
        SigningSubmissionId step = SigningSubmissionId.parse(stepId);
        SigningSubmissionId parent = SigningSubmissionId.parse(context.parentOperationId());
        requireOperation(stepId, step.namespace());
        if (stepId.equals(parent.id()) || !step.namespace().equals(parent.namespace())
                || !deadline.isAfter(step.createdAt()) || !deadline.isAfter(parent.createdAt())) {
            throw invalid();
        }
    }


    private static void requireContext(PkiId stepId, Instant deadline, Optional<CaContext> context) {
        SigningSubmissionId step = SigningSubmissionId.parse(stepId);
        Objects.requireNonNull(context, "context");
        if (!Objects.requireNonNull(deadline, "deadline").isAfter(step.createdAt())) {
            throw invalid();
        }
        if (context.isPresent()) {
            SigningSubmissionId parent = SigningSubmissionId.parse(context.orElseThrow().parentId());
            if (stepId.equals(parent.id()) || !step.namespace().equals(parent.namespace())
                    || !deadline.isAfter(parent.createdAt())) {
                throw invalid();
            }
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

    /**
     * Requires a canonical bounded submission identity in the exact expected namespace.
     *
     * @param id submission identity bounded to 4096 UTF-8 bytes
     * @param namespace exact expected submission namespace
     * @throws IllegalArgumentException if identity syntax, canonical spelling, or namespace differs
     */
    /* default */ static void requireOperation(PkiId id, String namespace) {
        ManagedKeyProofCommand.utf8Length(id.value(), 4096);
        SigningSubmissionId parsed = SigningSubmissionId.parse(id);
        String exact =
                "zsign:v1:"
                        + parsed.namespace()
                        + ':'
                        + parsed.createdAt().toEpochMilli()
                        + ':'
                        + id.value()
                                .substring(id.value().lastIndexOf(':') + 1)
                                .toLowerCase(java.util.Locale.ROOT);
        if (!namespace.equals(parsed.namespace()) || !exact.equals(id.value())) {
            throw invalid();
        }
    }

    private static void requireSpki(byte[] spki) {
        Objects.requireNonNull(spki, "spki");
        if (spki.length == 0 || spki.length > ManagedKeyProofCommand.MAX_SPKI_BYTES) {
            throw invalid();
        }
        try {
            new StreamingDerReader().validateSubjectPublicKeyInfo(spki, ManagedKeyProofCommand.MAX_SPKI_BYTES);
        } catch (IOException malformed) {
            throw new IllegalArgumentException(
                    "Managed key proof public key is not canonical DER", malformed);
        }
    }

    private static void write(ByteBuffer output, byte[] bytes) {
        output.putInt(bytes.length).put(bytes);
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Managed key proof challenge is invalid");
    }

    private record DecodingContext(
            PkiId operationId,
            Instant deadline,
            Optional<ResponderCandidateContext> candidateContext,
            Optional<CaContext> context) {}

    /** Bounded binary challenge decoding, separate from challenge construction. */
    private static final class Decoder {
        private static DecodingContext readIdentity(DataInputStream input) throws IOException {
            if (!Arrays.equals(input.readNBytes(MAGIC.length), MAGIC)) {
                throw invalid();
            }
            int version = input.readInt();
            if (version != VERSION
                    && version != ROLE_CONTEXT_VERSION
                    && version != RESPONDER_CONTEXT_VERSION) {
                throw invalid();
            }
            PkiId operationId = new PkiId(readText(input, 4096));
            long seconds = input.readLong();
            int nanos = input.readInt();
            if (nanos < 0 || nanos >= 1_000_000_000) {
                throw invalid();
            }
            Instant deadline = Instant.ofEpochSecond(seconds, nanos);
            Optional<ResponderCandidateContext> candidateContext =
                    version == RESPONDER_CONTEXT_VERSION
                            ? Optional.of(readResponderContext(input))
                            : Optional.empty();
            Optional<CaContext> context =
                    version == RESPONDER_CONTEXT_VERSION
                            ? Optional.empty()
                            : readContext(input, version);
            if (candidateContext.isPresent()) {
                requireResponderContext(operationId, deadline, candidateContext.orElseThrow());
            } else {
                requireContext(operationId, deadline, context);
            }
            return new DecodingContext(operationId, deadline, candidateContext, context);
        }

        private static Decoded decode(byte[] challenge) {
            Objects.requireNonNull(challenge, "challenge");
            if (challenge.length == 0
                    || challenge.length > ManagedKeyProofCommand.MAX_CHALLENGE_BYTES) {
                throw invalid();
            }
            try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(challenge))) {
                DecodingContext identity = readIdentity(input);
                PkiId operationId = identity.operationId();
                Instant deadline = identity.deadline();
                Optional<ResponderCandidateContext> candidateContext = identity.candidateContext();
                Optional<CaContext> context = identity.context();
                byte[] nonce = exact(input, NONCE_BYTES);
                List<String> metadata = new ArrayList<>(10);
                for (int index = 0; index <= 6; index++) {
                    metadata.add(readText(input, ManagedKeyProofCommand.MAX_COMMAND_BYTES));
                }
                metadata.add(HexFormat.of().formatHex(exact(input, 32)));
                metadata.add(readText(input, 8192));
                metadata.add(
                        HexFormat.of()
                                .formatHex(
                                        read(
                                                input,
                                                ManagedKeyProofCommand.MAX_ALGORITHM_DER_BYTES)));
                byte[] spki = read(input, ManagedKeyProofCommand.MAX_SPKI_BYTES);
                if (input.available() != 0) {
                    throw invalid();
                }
                requireSpki(spki);
                requireOperation(operationId, metadata.get(6));
                DomainCommandEncoding.Decoded command =
                        complete(
                                metadata,
                                spki,
                                challenge.length,
                                ContentCommitment.sha256(challenge).sha256());
                ManagedKeyProofCommand.validateComplete(command);
                boolean candidate = OCSP_CANDIDATE_KIND.equals(command.field(0));
                if (candidate != candidateContext.isPresent()) {
                    throw invalid();
                }
                if (candidate
                        && !Arrays.equals(
                                challenge,
                                encodeCandidate(
                                        operationId,
                                        deadline,
                                        candidateContext.orElseThrow(),
                                        metadata,
                                        nonce,
                                        spki))) {
                    throw invalid();
                }
                return new Decoded(
                        operationId, deadline, context, nonce, command, spki, candidateContext);
            } catch (IOException | java.time.DateTimeException malformed) {
                throw new IllegalArgumentException(
                        "Managed key proof challenge is truncated or invalid", malformed);
            }
        }

        private static ResponderCandidateContext readResponderContext(DataInputStream input)
                throws IOException {
            if (input.readUnsignedByte() != CHALLENGE_VERSION) {
                throw invalid();
            }
            PkiId parent = new PkiId(readText(input, 4096));
            String intent = "ocsp-intent:v1:" + HexFormat.of().formatHex(exact(input, 32));
            zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole role =
                    switch (input.readUnsignedByte()) {
                        case 1 -> zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole.PRIMARY;
                        case 2 -> zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole.ALTERNATIVE;
                        default -> throw invalid();
                    };
            return new ResponderCandidateContext(
                    parent, intent, role, HexFormat.of().formatHex(exact(input, 32)));
        }

    private static byte[] read(DataInputStream input, int maximum) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > maximum || length > input.available()) {
            throw invalid();
        }
        return exact(input, length);
    }
    private static byte[] exact(DataInputStream input, int length) throws IOException {
        if (length > input.available()) {
            throw invalid();
        }
        return input.readNBytes(length);
    }
    private static String readText(DataInputStream input, int maximum) throws IOException {
        byte[] bytes = read(input, maximum);
        String value = new String(bytes, StandardCharsets.UTF_8);
        if (!Arrays.equals(bytes, value.getBytes(StandardCharsets.UTF_8))) {
            throw invalid();
        }
        return value;
    }
    private static Optional<CaContext> readContext(DataInputStream input, int version) throws IOException {
        int contextFlag = input.readUnsignedByte();
        if (contextFlag > CONTEXT_PRESENT || version == ROLE_CONTEXT_VERSION && contextFlag != CONTEXT_PRESENT) {
            throw invalid();
        }
        if (contextFlag == 0) {
            return Optional.empty();
        }
        PkiId parent = new PkiId(readText(input, 4096));
        String intent = "ca-intent:v1:" + HexFormat.of().formatHex(exact(input, 32));
        if (version == VERSION) {
            return Optional.of(new CaContext(parent, intent));
        }
            zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole role =
                    switch (input.readUnsignedByte()) {
                        case 1 -> zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole.PRIMARY;
                        case 2 -> zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole.ALTERNATIVE;
                        default -> throw invalid();
                    };
        return Optional.of(new CaContext(parent, intent, Optional.of(role), Optional.of(HexFormat.of().formatHex(exact(input, 32)))));
    }
    }
}
