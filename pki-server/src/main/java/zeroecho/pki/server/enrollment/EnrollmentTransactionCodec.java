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

/** Strict version-two bounded encoding; no original request or secret material. */
final class EnrollmentTransactionCodec {
    private static final int MAXIMUM_TEXT_LENGTH = 8_192;
    /* default */ static final int MAXIMUM_BYTES = 524_288;
    private static final int VERSION = 2;
    private EnrollmentTransactionCodec() { }

    /* default */ static ServerControlStore.ProtocolRecord record(EnrollmentTransaction value) {
        byte[] payload = encode(value);
        return new ServerControlStore.ProtocolRecord(ServerControlStore.ENROLLMENT_REQUEST, value.id(), sha256(payload), payload);
    }

    /* default */ static EnrollmentTransaction decode(ServerControlStore.ProtocolRecord record) {
        byte[] payload = record.payload();
        if (!ServerControlStore.ENROLLMENT_REQUEST.equals(record.namespace()) || payload.length > MAXIMUM_BYTES
                || !sha256(payload).equals(record.commitment())) {
            throw invalid();
        }
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload))) {
            if (in.readInt() != VERSION) {
                throw invalid();
            }
            String id = text(in); long revision = in.readLong();
            EnrollmentTransaction.Intent intent = intent(in);
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
            EnrollmentTransaction value = new EnrollmentTransaction(id, revision, intent, state, decisions, receipt, credential);
            if (in.read() != -1 || !record.recordId().equals(value.id()) || !Arrays.equals(payload, encode(value))) {
                throw invalid();
            }
            return value;
        } catch (IOException | IllegalArgumentException failure) {
            throw invalid(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    /* default */ static byte[] encode(EnrollmentTransaction value) {
        return bytes(out -> {
            out.writeInt(VERSION); text(out, value.id()); out.writeLong(value.revision()); intent(out, value.intent());
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
        });
    }

    /* default */ static String intentCommitment(EnrollmentTransaction.Intent value) {
        return sha256(bytes(out -> { text(out, "zeroecho.enrollment-intent.v2"); intent(out, value); }));
    }

    /* default */ static String replayId(RealmId realm, EnrollmentTransaction.Source source, EnrollmentTransaction.Requester requester,
            String transaction, EnrollmentTransaction.Operation operation) {
        return replayId(realm, source.protocol(), source.label(), requester, transaction, operation);
    }

    /* default */ static String replayId(RealmId realm, EnrollmentTransaction.Protocol protocol, String label, EnrollmentTransaction.Requester requester,
            String transaction, EnrollmentTransaction.Operation operation) {
        return replayId(realm, protocol, label, requester.type(), requester.actorId(), transaction, operation);
    }

    /* default */ static String replayId(RealmId realm, EnrollmentTransaction.Protocol protocol, String label,
            IssuanceExecutionEvidence.ActorType type, String actorId, String transaction, EnrollmentTransaction.Operation operation) {
        return "enrollment:" + sha256(bytes(out -> {
            text(out, "zeroecho.enrollment-replay.v1"); text(out, realm.value()); text(out, protocol.name());
            text(out, label); text(out, type.name()); text(out, actorId);
            text(out, transaction); text(out, operation.name());
        }));
    }

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

    /* default */ static void source(DataOutputStream out, EnrollmentTransaction.Source source) throws IOException {
        text(out, source.protocol().name()); text(out, source.label()); text(out, source.recordId()); out.writeLong(source.revision());
        text(out, source.commitment()); text(out, source.enrollmentProfileId()); text(out, source.enrollmentCommitment()); optional(out, source.credentialId());
    }

    /* default */ static void requester(DataOutputStream out, EnrollmentTransaction.Requester requester) throws IOException {
        text(out, requester.type().name()); text(out, requester.actorId()); text(out, requester.authentication().name());
        out.writeBoolean(requester.certificate().isPresent());
        if (requester.certificate().isPresent()) {
            evidence(out, requester.certificate().orElseThrow());
        }
        optional(out, requester.canonicalKeySha256()); strings(out, requester.legacySpkiSha256());
        text(out, requester.aliases().realmId().value()); strings(out, requester.aliases().principalIds());
    }

    /* default */ static EnrollmentTransaction.Intent intent(DataInputStream in) throws IOException {
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
        return new EnrollmentTransaction.Intent(realm, source, requester, transaction, operation, request, kind, digest, size, authority,
                profile, issuer, path, pathDigest, validity, predecessor, predecessorDigest, category, policy, artifact, instant(in), instant(in));
    }

    private static void evidence(DataOutputStream out, CertificateIdentityEvidence value) throws IOException {
        text(out, value.realmId().value()); text(out, value.certificateSha256()); text(out, value.canonicalKeySha256());
        strings(out, value.legacySpkiSha256()); text(out, value.issuerSerialSha256());
    }
    /* default */ static EnrollmentTransaction.Source source(DataInputStream in) throws IOException {
        return new EnrollmentTransaction.Source(EnrollmentTransaction.Protocol.valueOf(text(in)), text(in), text(in),
                in.readLong(), text(in), text(in), text(in), optional(in));
    }
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
    private static void text(DataOutputStream out, String value) throws IOException {
        if (value.length() > MAXIMUM_TEXT_LENGTH) {
            throw invalid();
        } out.writeUTF(value);
    }
    private static String text(DataInputStream in) throws IOException {
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
    /** Rejects encoded transaction growth before the persistent record limit is exceeded. */
    private static final class BoundedBytes extends ByteArrayOutputStream {
        // Preserves ByteArrayOutputStream synchronization while enforcing the encoded-size bound.
        @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
        @Override public synchronized void write(int value) {
            if (count == MAXIMUM_BYTES) {
                throw invalid();
            }
            super.write(value);
        }
        // Preserves ByteArrayOutputStream synchronization while enforcing the encoded-size bound.
        @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
        @Override public synchronized void write(byte[] values, int offset, int length) {
            if (length > MAXIMUM_BYTES - count) {
                throw invalid();
            }
            super.write(values, offset, length);
        }
    }
    /* default */ static String sha256(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
    }
    private static IllegalStateException invalid() { return new IllegalStateException("Enrollment transaction encoding is invalid"); }
    /** Encodes one canonical record into an owned output buffer. */
    @FunctionalInterface private interface Encoder {
        /**
         * Writes the canonical binary representation.
         * @param out borrowed output
         * @throws IOException if encoding fails
         */
        void write(DataOutputStream out) throws IOException;
    }
}
