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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.server.ApprovalService;
import zeroecho.pki.server.CertificateIdentityEvidence;
import zeroecho.pki.server.OperationSecurityDescriptors.ApprovalCategory;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.ServerControlStore;

/**
 * Bounded ordinary-v2/SDK-v3 encoding of retained enrollment references and decisions.
 *
 * <p>The codec stores no original request DER, private key or encrypted delivery
 * body. It does retain actor/policy/decision metadata and operator justification;
 * encoding and SHA-256 commitments are not redaction. Constructing or decoding a
 * record does not authenticate actors, verify SDK signatures or commit admission.
 * Text uses Java modified-UTF framing with an 8192-character bound; complete
 * encoded records are bounded to 524288 bytes.</p>
 */
public final class EnrollmentTransactionCodec {
    private static final int MAXIMUM_TEXT_LENGTH = 8_192;
    /**
     * Maximum canonical enrollment transaction record size, in bytes.
     */
    /* default */ static final int MAXIMUM_BYTES = 524_288;
    private static final int VERSION = 2;
    private EnrollmentTransactionCodec() { }

    /**
     * Encodes one transaction in the existing enrollment-request namespace without mutating persistence.
     *
     * @param value immutable transaction
     * @return new protocol record with payload and exact SHA-256 commitment
     * @throws NullPointerException if the transaction is null
     * @throws IllegalStateException if canonical encoding or aggregate byte limits fail
     */
    public static ServerControlStore.ProtocolRecord record(EnrollmentTransaction value) {
        byte[] payload = encode(value);
        return new ServerControlStore.ProtocolRecord(ServerControlStore.ENROLLMENT_REQUEST, value.id(), sha256(payload), payload);
    }

    /**
     * Decodes a closed ordinary-v2 or SDK-v3 record and requires exact canonical re-encoding.
     *
     * @param record private enrollment protocol record
     * @return independently reconstructed transaction with structural state checks
     * @throws NullPointerException if the record is null
     * @throws IllegalStateException if namespace, commitment, version, fields, bounds, identity or canonical
     *     encoding is invalid
     */
    public static EnrollmentTransaction decode(ServerControlStore.ProtocolRecord record) {
        byte[] payload = record.payload();
        if (!ServerControlStore.ENROLLMENT_REQUEST.equals(record.namespace()) || payload.length > MAXIMUM_BYTES
                || !sha256(payload).equals(record.commitment())) {
            throw invalid();
        }
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload))) {
            int version = in.readInt();
            if (version != VERSION && version != 3) {
                throw invalid();
            }
            String id = text(in); long revision = in.readLong();
            var intentFields = intentFields(in);
            // Ordinary v2 validates immediately; SDK v3 must read its mandatory
            // trailing proof before constructing the proof-bound absolute intent.
            EnrollmentTransaction.Intent intent = version == VERSION ? intentFields.apply(Optional.empty()) : null;
            EnrollmentTransaction.State state = EnrollmentTransaction.State.valueOf(text(in));
            int count = count(in, 4096);
            List<EnrollmentTransaction.Decision> decisions = new ArrayList<>(count);
            for (int index = 0; index < count; index++) {
                decisions.add(new EnrollmentTransaction.Decision(text(in), evidence(in), ApprovalService.Choice.valueOf(text(in)),
                        text(in), instant(in)));
            }
            Optional<SigningAcceptanceReceipt> receipt = in.readBoolean()
                    ? Optional.of(SigningAcceptanceReceipt.parse(new PkiId(text(in)), text(in))) : Optional.empty();
            Optional<PkiId> credential = optional(in).map(PkiId::new);
            if (version == 3) intent = intentFields.apply(Optional.of(proof(in)));
            EnrollmentTransaction value = new EnrollmentTransaction(id, revision, intent, state, decisions, receipt, credential);
            if (in.read() != -1 || !record.recordId().equals(value.id()) || !Arrays.equals(payload, encode(value))) {
                throw invalid();
            }
            return value;
        } catch (IOException | IllegalArgumentException failure) {
            throw invalid(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    /**
     * Encodes ordinary version two or proof-bound SDK version three into a new bounded byte array.
     *
     * @param value supplied immutable value
     * @return new bounded canonical bytes
     * @throws NullPointerException if a required supplied value is null
     * @throws IllegalStateException if field serialization or aggregate byte bounds fail
     */
    /* default */ static byte[] encode(EnrollmentTransaction value) {
        return bytes(out -> {
            out.writeInt(value.intent().sdkProof().isPresent() ? 3 : VERSION); text(out, value.id()); out.writeLong(value.revision()); intent(out, value.intent());
            text(out, value.state().name()); out.writeInt(value.decisions().size());
            for (EnrollmentTransaction.Decision decision : value.decisions()) {
                text(out, decision.principalId()); evidence(out, decision.evidence()); text(out, decision.choice().name());
                text(out, decision.justification()); instant(out, decision.decidedAt());
            }
            out.writeBoolean(value.receipt().isPresent());
            if (value.receipt().isPresent()) {
                text(out, value.receipt().orElseThrow().operationId().value()); text(out, value.receipt().orElseThrow().encodedCommitment());
            }
            optional(out, value.credentialId().map(PkiId::value));
            if (value.intent().sdkProof().isPresent()) proof(out, value.intent().sdkProof().orElseThrow());
        });
    }

    /**
     * Hashes the complete frozen intent using its ordinary-v2 or SDK-v3 domain discriminator.
     *
     * @param value supplied immutable value
     * @return lowercase 64-character SHA-256 digest
     * @throws NullPointerException if a required supplied value is null
     * @throws IllegalStateException if encoding bounds or SHA-256 availability fail
     */
    /* default */ static String intentCommitment(EnrollmentTransaction.Intent value) {
        return sha256(bytes(out -> {
            text(out, value.sdkProof().isPresent() ? "zeroecho.enrollment-intent.sdk.v3" : "zeroecho.enrollment-intent.v2");
            intent(out, value);
            if (value.sdkProof().isPresent()) proof(out, value.sdkProof().orElseThrow());
        }));
    }

    /**
     * Derives the stable replay identity from realm, protocol, endpoint label, requester and transaction/operation.
     *
     * @param realm owning realm
     * @param source frozen source; replay uses protocol and label, not source revision
     * @param requester frozen requester identity
     * @param transaction native logical transaction commitment
     * @param operation operation-specific replay domain
     * @return enrollment: prefixed deterministic replay identity
     * @throws NullPointerException if a required supplied value is null
     * @throws IllegalStateException if encoding bounds or SHA-256 availability fail
     */
    /* default */ static String replayId(RealmId realm, EnrollmentTransaction.Source source, EnrollmentTransaction.Requester requester,
            String transaction, EnrollmentTransaction.Operation operation) {
        return replayId(realm, source.protocol(), source.label(), requester, transaction, operation);
    }

    /**
     * Derives the stable replay identity from realm, protocol, endpoint label, requester and transaction/operation.
     *
     * @param realm owning realm
     * @param protocol native protocol
     * @param label stable endpoint label
     * @param requester frozen requester identity
     * @param transaction native logical transaction commitment
     * @param operation operation-specific replay domain
     * @return enrollment: prefixed deterministic replay identity
     * @throws NullPointerException if a required supplied value is null
     * @throws IllegalStateException if encoding bounds or SHA-256 availability fail
     */
    /* default */ static String replayId(RealmId realm, EnrollmentTransaction.Protocol protocol, String label, EnrollmentTransaction.Requester requester,
            String transaction, EnrollmentTransaction.Operation operation) {
        return replayId(realm, protocol, label, requester.type(), requester.actorId(), transaction, operation);
    }

    /**
     * Derives the stable replay identity from realm, protocol, endpoint label, requester and transaction/operation.
     *
     * @param realm owning realm
     * @param protocol native protocol
     * @param label stable endpoint label
     * @param type requester actor classification
     * @param actorId stable actor identity
     * @param transaction native logical transaction commitment
     * @param operation operation-specific replay domain
     * @return enrollment: prefixed deterministic replay identity
     * @throws NullPointerException if a required supplied value is null
     * @throws IllegalStateException if encoding bounds or SHA-256 availability fail
     */
    /* default */ static String replayId(RealmId realm, EnrollmentTransaction.Protocol protocol, String label,
            IssuanceExecutionEvidence.ActorType type, String actorId, String transaction, EnrollmentTransaction.Operation operation) {
        return "enrollment:" + sha256(bytes(out -> {
            text(out, "zeroecho.enrollment-replay.v1"); text(out, realm.value()); text(out, protocol.name());
            text(out, label); text(out, type.name()); text(out, actorId);
            text(out, transaction); text(out, operation.name());
        }));
    }

    /**
     * Writes the proof fields in their canonical record order.
     *
     * @param out borrowed output stream; not closed
     * @param value supplied immutable value
     * @throws IOException if the borrowed stream cannot complete the field read/write
     * @throws IllegalStateException if a bounded text/count representation is invalid
     */
    /* default */ static void proof(DataOutputStream out, EnrollmentTransaction.SdkProofReference value) throws IOException {
        text(out, value.intentId()); text(out, value.proofCommitment()); text(out, value.authenticationContextSha512());
        text(out, value.targetSha512()); instant(out, value.acceptedAt());
    }
    /**
     * Reads the next proof representation and applies its value-constructor checks.
     *
     * @param in borrowed input stream at the next encoded field; not closed
     * @return newly decoded immutable value
     * @throws IOException if the borrowed stream cannot complete the field read/write
     * @throws IllegalStateException if a bounded text/count representation is invalid
     * @throws IllegalArgumentException if a decoded enum or immutable value fails its constructor checks
     */
    /* default */ static EnrollmentTransaction.SdkProofReference proof(DataInputStream in) throws IOException {
        return new EnrollmentTransaction.SdkProofReference(text(in), text(in), text(in), text(in), instant(in));
    }

    /**
     * Writes the intent fields in their canonical record order.
     *
     * @param out borrowed output stream; not closed
     * @param value supplied immutable value
     * @throws IOException if the borrowed stream cannot complete the field read/write
     * @throws IllegalStateException if a bounded text/count representation is invalid
     */
    /* default */ static void intent(DataOutputStream out, EnrollmentTransaction.Intent value) throws IOException {
        text(out, value.realmId().value());
        source(out, value.source());
        requester(out, value.requester());
        text(out, value.transactionId()); text(out, value.operation().name()); text(out, value.requestId().value());
        text(out, value.requestKind().name()); text(out, value.requestSha256()); out.writeInt(value.requestBytes());
        text(out, value.authorityId().value()); text(out, value.profile().profileId()); out.writeLong(value.profile().profileVersion());
        out.write(value.profile().canonicalSha256()); text(out, value.issuerId().value()); text(out, value.pathId().value()); text(out, value.pathCommitment());
        out.writeBoolean(value.validity().isPresent());
        if (value.validity().isPresent()) { instant(out, value.validity().orElseThrow().notBefore()); instant(out, value.validity().orElseThrow().notAfter()); }
        optional(out, value.predecessorId().map(PkiId::value)); optional(out, value.predecessorSha256()); text(out, value.approvalCategory().name());
        out.writeBoolean(value.approvalPolicy().isPresent());
        if (value.approvalPolicy().isPresent()) {
            ApprovalService.Policy policy = value.approvalPolicy().orElseThrow();
            text(out, policy.policyId()); out.writeInt(policy.threshold()); strings(out, policy.eligibleApprovers()); strings(out, policy.requiredRoleTemplateIds());
            out.writeBoolean(policy.requesterSeparation()); out.writeLong(policy.lifetime().getSeconds()); out.writeInt(policy.lifetime().getNano());
            out.writeBoolean(policy.justificationRequired());
        }
        out.writeBoolean(value.artifact().isPresent());
        if (value.artifact().isPresent()) {
            EnrollmentTransaction.ArtifactBinding artifact = value.artifact().orElseThrow();
            text(out, artifact.artifactId()); text(out, artifact.generationCommitment()); text(out, artifact.ciphertextSha256()); out.writeLong(artifact.ciphertextBytes());
        }
        instant(out, value.createdAt()); instant(out, value.expiresAt());
    }

    /**
     * Writes the source fields in their canonical record order.
     *
     * @param out borrowed output stream; not closed
     * @param source frozen source; replay uses protocol and label, not source revision
     * @throws IOException if the borrowed stream cannot complete the field read/write
     * @throws IllegalStateException if a bounded text/count representation is invalid
     */
    /* default */ static void source(DataOutputStream out, EnrollmentTransaction.Source source) throws IOException {
        text(out, source.protocol().name()); text(out, source.label()); text(out, source.recordId()); out.writeLong(source.revision());
        text(out, source.commitment()); text(out, source.enrollmentProfileId()); text(out, source.enrollmentCommitment()); optional(out, source.credentialId());
    }

    /**
     * Writes the requester fields in their canonical record order.
     *
     * @param out borrowed output stream; not closed
     * @param requester frozen requester identity
     * @throws IOException if the borrowed stream cannot complete the field read/write
     * @throws IllegalStateException if a bounded text/count representation is invalid
     */
    /* default */ static void requester(DataOutputStream out, EnrollmentTransaction.Requester requester) throws IOException {
        text(out, requester.type().name()); text(out, requester.actorId()); text(out, requester.authentication().name());
        out.writeBoolean(requester.certificate().isPresent());
        if (requester.certificate().isPresent()) {
            evidence(out, requester.certificate().orElseThrow());
        }
        optional(out, requester.canonicalKeySha256()); strings(out, requester.legacySpkiSha256());
        text(out, requester.aliases().realmId().value()); strings(out, requester.aliases().principalIds());
    }

    /**
     * Reads the next intent representation and applies its value-constructor checks.
     *
     * @param in borrowed input stream at the next encoded field; not closed
     * @return newly decoded immutable value
     * @throws IOException if the borrowed stream cannot complete the field read/write
     * @throws IllegalStateException if a bounded text/count representation is invalid
     * @throws IllegalArgumentException if a decoded enum or immutable value fails its constructor checks
     */
    /* default */ static EnrollmentTransaction.Intent intent(DataInputStream in) throws IOException {
        return intentFields(in).apply(Optional.empty());
    }

    private static java.util.function.Function<Optional<EnrollmentTransaction.SdkProofReference>, EnrollmentTransaction.Intent> intentFields(DataInputStream in) throws IOException {
        RealmId realm = new RealmId(text(in));
        EnrollmentTransaction.Source source = source(in);
        EnrollmentTransaction.Requester requester = requester(in);
        String transaction = text(in); EnrollmentTransaction.Operation operation = EnrollmentTransaction.Operation.valueOf(text(in));
        PkiId request = new PkiId(text(in)); X509EnrollmentPayload.Kind kind = X509EnrollmentPayload.Kind.valueOf(text(in));
        String digest = text(in); int size = in.readInt(); PkiId authority = new PkiId(text(in));
        CertificateProfileRef profile = new CertificateProfileRef(text(in), in.readLong(), in.readNBytes(32));
        PkiId issuer = new PkiId(text(in)); PkiId path = new PkiId(text(in)); String pathDigest = text(in);
        Optional<Validity> validity = in.readBoolean() ? Optional.of(new Validity(instant(in), instant(in))) : Optional.empty();
        Optional<PkiId> predecessor = optional(in).map(PkiId::new); Optional<String> predecessorDigest = optional(in);
        ApprovalCategory category = ApprovalCategory.valueOf(text(in));
        Optional<ApprovalService.Policy> policy = in.readBoolean() ? Optional.of(new ApprovalService.Policy(text(in), in.readInt(),
                strings(in, 4096), strings(in, 4096), in.readBoolean(), Duration.ofSeconds(in.readLong(), in.readInt()), in.readBoolean())) : Optional.empty();
        Optional<EnrollmentTransaction.ArtifactBinding> artifact = in.readBoolean()
                ? Optional.of(new EnrollmentTransaction.ArtifactBinding(text(in), text(in), text(in), in.readLong())) : Optional.empty();
        Instant created = instant(in), expires = instant(in);
        return proof -> new EnrollmentTransaction.Intent(realm, source, requester, transaction, operation, request, kind, digest, size, authority,
                profile, issuer, path, pathDigest, validity, predecessor, predecessorDigest, category, policy, artifact, created, expires, proof);
    }

    private static void evidence(DataOutputStream out, CertificateIdentityEvidence value) throws IOException {
        text(out, value.realmId().value()); text(out, value.certificateSha256()); text(out, value.canonicalKeySha256());
        strings(out, value.legacySpkiSha256()); text(out, value.issuerSerialSha256());
    }
    /**
     * Reads the next source representation and applies its value-constructor checks.
     *
     * @param in borrowed input stream at the next encoded field; not closed
     * @return newly decoded immutable value
     * @throws IOException if the borrowed stream cannot complete the field read/write
     * @throws IllegalStateException if a bounded text/count representation is invalid
     * @throws IllegalArgumentException if a decoded enum or immutable value fails its constructor checks
     */
    /* default */ static EnrollmentTransaction.Source source(DataInputStream in) throws IOException {
        return new EnrollmentTransaction.Source(EnrollmentTransaction.Protocol.valueOf(text(in)), text(in), text(in),
                in.readLong(), text(in), text(in), text(in), optional(in));
    }
    /**
     * Reads the next requester representation and applies its value-constructor checks.
     *
     * @param in borrowed input stream at the next encoded field; not closed
     * @return newly decoded immutable value
     * @throws IOException if the borrowed stream cannot complete the field read/write
     * @throws IllegalStateException if a bounded text/count representation is invalid
     * @throws IllegalArgumentException if a decoded enum or immutable value fails its constructor checks
     */
    /* default */ static EnrollmentTransaction.Requester requester(DataInputStream in) throws IOException {
        IssuanceExecutionEvidence.ActorType actor = IssuanceExecutionEvidence.ActorType.valueOf(text(in));
        String actorId = text(in); IssuanceExecutionEvidence.Authentication authentication = IssuanceExecutionEvidence.Authentication.valueOf(text(in));
        Optional<CertificateIdentityEvidence> certificate = in.readBoolean() ? Optional.of(evidence(in)) : Optional.empty();
        return new EnrollmentTransaction.Requester(actor, actorId, authentication, certificate, optional(in), strings(in, 3),
                new EnrollmentIdentityAliases.Snapshot(new RealmId(text(in)), strings(in, 20_000)));
    }
    private static CertificateIdentityEvidence evidence(DataInputStream in) throws IOException {
        return new CertificateIdentityEvidence(new RealmId(text(in)), text(in), text(in), strings(in, 3), text(in));
    }
    private static void strings(DataOutputStream out, Set<String> values) throws IOException {
        out.writeInt(values.size()); for (String value : new TreeSet<>(values)) {
            text(out, value);
        }
    }
    private static Set<String> strings(DataInputStream in, int bound) throws IOException {
        int count = count(in, bound); SortedSet<String> values = new TreeSet<>();
        for (int index = 0; index < count; index++) {
            if (!values.add(text(in))) {
                throw invalid();
            }
        }
        return values;
    }
    private static int count(DataInputStream in, int bound) throws IOException {
        int value = in.readInt(); if (value < 0 || value > bound) {
            throw invalid();
        } return value;
    }
    private static void optional(DataOutputStream out, Optional<String> value) throws IOException {
        out.writeBoolean(value.isPresent()); if (value.isPresent()) {
            text(out, value.orElseThrow());
        }
    }
    private static Optional<String> optional(DataInputStream in) throws IOException { return in.readBoolean() ? Optional.of(text(in)) : Optional.empty(); }
    private static void instant(DataOutputStream out, Instant value) throws IOException { out.writeLong(value.getEpochSecond()); out.writeInt(value.getNano()); }
    private static Instant instant(DataInputStream in) throws IOException { return Instant.ofEpochSecond(in.readLong(), in.readInt()); }
    /**
     * Writes the text fields in their canonical record order.
     *
     * @param out borrowed output stream; not closed
     * @param value supplied immutable value
     * @throws IOException if the borrowed stream cannot complete the field read/write
     * @throws IllegalStateException if a bounded text/count representation is invalid
     */
    /* default */ static void text(DataOutputStream out, String value) throws IOException {
        if (value.length() > MAXIMUM_TEXT_LENGTH) {
            throw invalid();
        } out.writeUTF(value);
    }
    /**
     * Reads the next text representation and applies its value-constructor checks.
     *
     * @param in borrowed input stream at the next encoded field; not closed
     * @return newly decoded immutable value
     * @throws IOException if the borrowed stream cannot complete the field read/write
     * @throws IllegalStateException if a bounded text/count representation is invalid
     */
    /* default */ static String text(DataInputStream in) throws IOException {
        String value = in.readUTF(); if (value.length() > MAXIMUM_TEXT_LENGTH) {
            throw invalid();
        } return value;
    }
    private static byte[] bytes(Encoder encoder) {
        try (ByteArrayOutputStream bytes = new BoundedBytes(); DataOutputStream out = new DataOutputStream(bytes)) {
            encoder.write(out); out.flush(); if (bytes.size() > MAXIMUM_BYTES) {
                throw invalid();
            } return bytes.toByteArray();
        } catch (IOException failure) { throw invalid(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }
    /**
     * Rejects encoded transaction growth before the persistent record limit is exceeded.
     */
    private static final class BoundedBytes extends ByteArrayOutputStream {
        // Preserves ByteArrayOutputStream synchronization while enforcing the encoded-size bound.
        /**
         * {@inheritDoc}
         */
        @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
        @Override public synchronized void write(int value) {
            if (count == MAXIMUM_BYTES) {
                throw invalid();
            }
            super.write(value);
        }
        // Preserves ByteArrayOutputStream synchronization while enforcing the encoded-size bound.
        /**
         * {@inheritDoc}
         */
        @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
        @Override public synchronized void write(byte[] values, int offset, int length) {
            if (length > MAXIMUM_BYTES - count) {
                throw invalid();
            }
            super.write(values, offset, length);
        }
    }
    /**
     * Computes a lowercase SHA-256 digest of the exact supplied bytes.
     *
     * @param bytes borrowed byte array hashed without retention
     * @return lowercase 64-character SHA-256 digest
     * @throws NullPointerException if a required supplied value is null
     * @throws IllegalStateException if SHA-256 is unavailable
     */
    /* default */ static String sha256(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
    }
    private static IllegalStateException invalid() { return new IllegalStateException("Enrollment transaction encoding is invalid"); }
    /**
     * Encodes one canonical record into an owned output buffer.
     */
    @FunctionalInterface private interface Encoder {
        /**
         * Writes the canonical binary representation.
         *
         * @param out borrowed output
         * @throws IOException if encoding fails
         */
        void write(DataOutputStream out) throws IOException;
    }
}
