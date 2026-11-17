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

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.ServerControlStore;

/**
 * Closed bounded ZESI-v1 enrollment SDK representation, distinct from administrative HSI1.
 *
 * <p>Encoding stores the exact original typed request once and retains required
 * protected native wire and proof evidence. These bytes may contain confidential
 * native request attributes; canonical encoding and hashing are not redaction.
 * Codec validation establishes representation/correspondence, not caller
 * authentication, cryptographic proof validity or successful durable admission.</p>
 */
public final class EnrollmentSdkIntentCodec {
    /**
     * Closed enrollment namespace discriminator, distinct from administrative HSI1.
     */
    public static final int MAGIC = 0x5A455349;
    private static final int BOOLEAN_TRUE = 1;
    private static final int FORMAT_VERSION = 1;
    private static final int MAXIMUM_BYTES = 524_288;
    private EnrollmentSdkIntentCodec() { }
    /**
     * Encodes an immutable intent without accessing persistence or authentication.
     *
     * @param value retained intent
     * @return independent canonical bytes, bounded to the existing protocol ceiling
     * @throws NullPointerException if the intent is null
     * @throws IllegalArgumentException if target correspondence, whole-second intent times or
     * component/aggregate capacity constraints fail
     */
    // Protocol diagnostics intentionally exclude untrusted/internal causes while retaining the established safe error contract.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    public static byte[] encode(EnrollmentSdkIntent value) {
        try {
            if (!Arrays.equals(target(value.targetFrame()).value().encode(), value.admission().target().value().encode())
                    || value.issuedAt().getNano() != 0 || value.expiresAt().getNano() != 0) { throw invalid(); }
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream out = new DataOutputStream(bytes)) {
                out.writeInt(MAGIC); out.writeInt(1); Scalars.text(out, value.id()); Scalars.text(out, value.realmId().value());
                out.writeLong(value.revision()); out.writeByte(value.state() == EnrollmentSdkIntent.State.OPEN ? 0 : 1);
                EnrollmentSdkAdmission a = value.admission(); EnrollmentCoordinator.Admission nativeAdmission = a.admission();
                Scalars.text(out, nativeAdmission.protocol().name()); Scalars.text(out, nativeAdmission.endpointId());
                Scalars.text(out, a.expectedEndpointCommitment()); Scalars.text(out, a.canonicalOrigin());
                EnrollmentTransactionCodec.requester(out, nativeAdmission.requester()); Scalars.text(out, nativeAdmission.transactionId());
                Scalars.text(out, nativeAdmission.operation().name());
                out.writeBoolean(nativeAdmission.validity().isPresent());
                if (nativeAdmission.validity().isPresent()) { Scalars.instant(out, nativeAdmission.validity().orElseThrow().notBefore()); Scalars.instant(out, nativeAdmission.validity().orElseThrow().notAfter()); }
                Scalars.optional(out, nativeAdmission.predecessorId().map(PkiId::value));
                out.writeBoolean(nativeAdmission.protocolDeadline().isPresent()); if (nativeAdmission.protocolDeadline().isPresent()) { Scalars.instant(out, nativeAdmission.protocolDeadline().orElseThrow()); }
                Scalars.text(out, value.originalPayload().kind().name()); Scalars.blob(out, value.originalPayload().der());
                Scalars.optionalBlob(out, value.nativeWire());
                out.writeBoolean(a.cmpManifest().isPresent());
                if (a.cmpManifest().isPresent()) {
                    CmpTransaction.Frozen frozen = a.cmpManifest().orElseThrow();
                    CmpTransaction manifest = new CmpTransaction(CmpTransactionCodec.id(frozen.realmId(), frozen.source().label(), frozen.transactionSha256()), 1,
                            frozen, Optional.empty(), Optional.empty());
                    Scalars.blob(out, CmpTransactionCodec.encode(manifest));
                }
                Scalars.blob(out, value.primaryFrame().encode()); Scalars.blob(out, value.authenticationContext().encode()); Scalars.blob(out, value.targetFrame().encode());
                if (value.state() == EnrollmentSdkIntent.State.CONSUMED) {
                    Scalars.text(out, value.sdkRequestId().orElseThrow()); Scalars.blob(out, value.primaryProof().orElseThrow()); Scalars.blob(out, value.alternativeProof().orElseThrow());
                    Scalars.text(out, value.proofCommitment().orElseThrow()); Scalars.instant(out, value.acceptedAt().orElseThrow()); Scalars.text(out, value.enrollmentId().orElseThrow());
                }
            }
            if (bytes.size() > MAXIMUM_BYTES) { throw invalid(); }
            return bytes.toByteArray();
        } catch (IOException failure) { throw invalid(); }
    }
    /**
     * Independently decodes and canonical-reencodes one enrollment variant.
     *
     * @param record private protocol record
     * @return independently reconstructed immutable intent after exact canonical re-encoding
     * @throws NullPointerException if the record is null
     * @throws IllegalArgumentException for unknown variants, malformed data or inconsistent commitments
     */
    // Protocol diagnostics intentionally exclude untrusted/internal causes while retaining the established safe error contract.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    public static EnrollmentSdkIntent decode(ServerControlStore.ProtocolRecord record) {
        byte[] bytes = record.payload();
        if (!ServerControlStore.HYBRID_SDK_INTENT.equals(record.namespace()) || bytes.length > MAXIMUM_BYTES
                || !record.commitment().equals(EnrollmentTransactionCodec.sha256(bytes))) { throw invalid(); }
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
            return readValue(in, record, bytes);
        } catch (IOException | IllegalArgumentException failure) { throw invalid(); }
    }
    /**
     * Wraps canonical intent bytes in the existing private SDK-intent namespace.
     *
     * @param value immutable intent
     * @return independent protocol record with the exact payload SHA-256 commitment
     * @throws NullPointerException if the intent is null
     * @throws IllegalArgumentException if encoding validation or capacity fails
     */
    public static ServerControlStore.ProtocolRecord record(EnrollmentSdkIntent value) {
        byte[] bytes = encode(value);
        return new ServerControlStore.ProtocolRecord(ServerControlStore.HYBRID_SDK_INTENT, value.id(), EnrollmentTransactionCodec.sha256(bytes), bytes);
    }
    /**
     * Constructs native CMP manifest and empty response-slot mutations without reserving them.
     *
     * @param manifest exact proposed initial linked manifest
     * @return immutable native mutation set, including unchanged bounded response-slot capacity
     * @throws NullPointerException if the manifest is null
     * @throws IllegalArgumentException if the manifest cannot fit its existing native record/slot bounds
     */
    public static java.util.List<ServerControlStore.ProtocolMutation> cmpCreation(CmpTransaction manifest) {
        return CmpTransactionCodec.create(manifest);
    }
    /**
     * Encodes a native CMP manifest using its existing canonical control-record codec.
     *
     * @param manifest exact retained manifest
     * @return canonical CMP protocol record; no mutation is applied
     * @throws NullPointerException if the manifest is null
     * @throws IllegalArgumentException if native encoding or protocol-record bounds fail
     */
    public static ServerControlStore.ProtocolRecord cmpRecord(CmpTransaction manifest) { return CmpTransactionCodec.record(manifest); }

    /**
     * Rejects a native receipt whose independently encoded issuer/policy coordinates differ from F7.
     *
     * @param intent proposed native frozen intent
     * @param sdk exact retained server challenge
     * @throws NullPointerException if either required value or expected typed member is missing
     * @throws IllegalArgumentException if schema/value types or frozen target coordinates disagree
     */
    public static void requireTarget(EnrollmentTransaction.Intent intent, EnrollmentSdkIntent sdk) { TargetChecks.requireTarget(intent, sdk); }
    private static String textField(HybridSdkFrame frame, int tag) { return new String(frame.field(tag), StandardCharsets.UTF_8); }

    private static SdkEnrollmentTarget target(HybridSdkFrame frame) {
        java.util.Map<String,zeroecho.pki.api.hybrid.sdk.HybridSdkValue> wrapper = zeroecho.pki.api.hybrid.sdk.HybridSdkValue.decode(frame.field(17)).objectFields();
        if (!wrapper.keySet().equals(java.util.Set.of("version", "enrollment", "lifecycle", "bindingSetInputs")) || wrapper.get("version").integerValue() != FORMAT_VERSION) { throw invalid(); }
        zeroecho.pki.api.hybrid.sdk.HybridSdkValue value = wrapper.get("enrollment"); java.util.Map<String,zeroecho.pki.api.hybrid.sdk.HybridSdkValue> fields = value.objectFields();
        SdkEnrollmentTarget target = new SdkEnrollmentTarget(1, fields.get("protocol").textValue(), fields.get("endpointId").textValue(), fields.get("sourceRevision").integerValue(),
                fields.get("endpointCommitment").textValue(), fields.get("enrollmentPolicyId").textValue(), fields.get("enrollmentPolicyVersion").integerValue(),
                fields.get("enrollmentPolicyCommitment").textValue(), fields.get("operation").textValue(), X509EnrollmentPayload.Kind.valueOf(fields.get("requestKind").textValue()),
                fields.get("transactionIdSha256").textValue(), fields.get("authenticationContextSha512").textValue());
        if (!Arrays.equals(value.encode(), target.value().encode())) { throw invalid(); }
        return target;
    }


    private static IllegalArgumentException invalid() { return new IllegalArgumentException("SDK_ENROLLMENT_INTENT_INVALID"); }

    private static EnrollmentSdkIntent readValue(DataInputStream in, ServerControlStore.ProtocolRecord record, byte[] bytes) throws IOException {

            if (in.readInt() != MAGIC || in.readInt() != FORMAT_VERSION) { throw invalid(); }
            String id = Scalars.text(in); RealmId realm = new RealmId(Scalars.text(in)); long revision = in.readLong();
            EnrollmentSdkIntent.State state = Scalars.readState(in);
            EnrollmentTransaction.Protocol protocol = EnrollmentTransaction.Protocol.valueOf(Scalars.text(in)); String endpoint = Scalars.text(in);
            String endpointCommitment = Scalars.text(in); String origin = Scalars.text(in);
            EnrollmentTransaction.Requester requester = EnrollmentTransactionCodec.requester(in); String transaction = Scalars.text(in);
            EnrollmentTransaction.Operation operation = EnrollmentTransaction.Operation.valueOf(Scalars.text(in));
            Optional<Validity> validity = Scalars.flag(in) ? Optional.of(new Validity(Scalars.instant(in), Scalars.instant(in))) : Optional.empty();
            Optional<PkiId> predecessor = Scalars.optional(in).map(PkiId::new);
            Optional<Instant> deadline = Scalars.flag(in) ? Optional.of(Scalars.instant(in)) : Optional.empty();
            X509EnrollmentPayload payload = new X509EnrollmentPayload(X509EnrollmentPayload.Kind.valueOf(Scalars.text(in)), Scalars.blob(in));
            Optional<byte[]> wire = Scalars.optionalBlob(in);
            Optional<CmpTransaction.Frozen> manifest = readManifest(in, realm, endpoint, transaction);
            HybridSdkFrame primary = HybridSdkFrame.decode(Scalars.blob(in)); HybridSdkFrame auth = HybridSdkFrame.decode(Scalars.blob(in)); HybridSdkFrame targetFrame = HybridSdkFrame.decode(Scalars.blob(in));
            SdkEnrollmentTarget target = target(targetFrame);
            EnrollmentCoordinator.Admission admission = new EnrollmentCoordinator.Admission(protocol, endpoint, requester, transaction, operation, payload, validity, predecessor, deadline);
            EnrollmentSdkAdmission trusted = new EnrollmentSdkAdmission(admission, endpointCommitment, origin, auth, target, manifest, wire);
            boolean consumed = state == EnrollmentSdkIntent.State.CONSUMED;
            EnrollmentSdkIntent result = new EnrollmentSdkIntent(id, 1, realm, trusted, payload, wire, primary, auth, targetFrame,
                    Instant.ofEpochSecond(java.nio.ByteBuffer.wrap(primary.field(7)).getLong()),
                    Instant.ofEpochSecond(java.nio.ByteBuffer.wrap(primary.field(8)).getLong()), state, revision,
                    Scalars.consumedText(in, consumed), Scalars.consumedBlob(in, consumed),
                    Scalars.consumedBlob(in, consumed), Scalars.consumedText(in, consumed),
                    Scalars.consumedInstant(in, consumed), Scalars.consumedText(in, consumed));
            if (in.read() != -1 || !id.equals(record.recordId()) || !Arrays.equals(bytes, encode(result))) { throw invalid(); }
            return result;
    }


    private static Optional<CmpTransaction.Frozen> readManifest(DataInputStream in, RealmId realm, String endpoint, String transaction) throws IOException {
            Optional<CmpTransaction.Frozen> manifest = Optional.empty();
            if (Scalars.flag(in)) {
                byte[] encoded = Scalars.blob(in); String manifestId = CmpTransactionCodec.id(realm, endpoint, transaction);
                CmpTransaction blank = CmpTransactionCodec.decode(new ServerControlStore.ProtocolRecord(ServerControlStore.CMP_TRANSACTION,
                        manifestId, EnrollmentTransactionCodec.sha256(encoded), encoded));
                if (blank.revision() != FORMAT_VERSION || blank.enrollmentId().isPresent() || blank.response().isPresent()) { throw invalid(); }
                manifest = Optional.of(blank.frozen());
            }
        return manifest;
    }


    /** Groups one bounded protocol validation responsibility. */
    private static final class TargetChecks {
        private static void requireTarget(EnrollmentTransaction.Intent intent, EnrollmentSdkIntent sdk) {
            HybridSdkFrame frame = sdk.targetFrame();
            java.util.Map<String,zeroecho.pki.api.hybrid.sdk.HybridSdkValue> effective = zeroecho.pki.api.hybrid.sdk.HybridSdkValue.decode(frame.field(15)).objectFields();
            Validity validity = new Validity(Instant.parse(effective.get("notBefore").textValue()), Instant.parse(effective.get("notAfter").textValue()));
            String policy = intent.approvalPolicy().map(zeroecho.pki.server.ApprovalService.Policy::commitment)
                    .orElseGet(() -> zeroecho.pki.server.ApprovalService.digest(""));
            String operation = switch (intent.operation()) {
                case ISSUE -> "credential.issue"; case RENEW -> "credential.renew"; case REPLACE -> "credential.replace";
                case SERVER_KEYGEN -> throw invalid();
            };
            requireTargetCoordinates(intent, frame, operation, policy, validity);

            java.util.Map<String,zeroecho.pki.api.hybrid.sdk.HybridSdkValue> wrapper = zeroecho.pki.api.hybrid.sdk.HybridSdkValue.decode(frame.field(17)).objectFields();
            zeroecho.pki.api.hybrid.sdk.HybridSdkValue inputs = wrapper.get("bindingSetInputs");
            java.util.Map<String,zeroecho.pki.api.hybrid.sdk.HybridSdkValue> bindingFields = inputs.objectFields();
            if (!bindingFields.keySet().equals(java.util.Set.of("issuerBinding", "provider", "path"))
                    || !bindingFields.get("path").textValue().equals(intent.pathCommitment())
                    || !textField(frame, 13).equals("sha512:" + java.util.HexFormat.of().formatHex(HybridSdkFrame.hash(inputs.encode())))) { throw invalid(); }
            String issuerBinding = bindingFields.get("issuerBinding").textValue();
            String provider = bindingFields.get("provider").textValue();
            if (!issuerBinding.matches("[0-9a-f]{64}") || provider.isEmpty() || provider.length() > 8192) { throw invalid(); }
            java.util.Map<String,zeroecho.pki.api.hybrid.sdk.HybridSdkValue> lifecycle = wrapper.get("lifecycle").objectFields();
            requireLifecycle(intent, lifecycle);

        }

        private static void requireTargetCoordinates(EnrollmentTransaction.Intent intent, HybridSdkFrame frame, String operation,
                String policy, Validity validity) {
            if (!textField(frame, 1).equals(operation) || !textField(frame, 3).equals(intent.requester().actorId())
                    || !textField(frame, 4).equals(intent.authorityId().value()) || !textField(frame, 5).equals(intent.issuerId().value())
                    || !textField(frame, 6).equals(intent.pathId().value()) || !textField(frame, 10).equals(intent.profile().profileId())
                    || java.nio.ByteBuffer.wrap(frame.field(11)).getLong() != intent.profile().profileVersion()
                    || !textField(frame, 12).equals("sha256:" + java.util.HexFormat.of().formatHex(intent.profile().canonicalSha256()))
                    || !textField(frame, 14).equals("sha256:" + policy) || !intent.validity().equals(Optional.of(validity))) { throw invalid(); }    }

        private static void requireLifecycle(EnrollmentTransaction.Intent intent, java.util.Map<String,zeroecho.pki.api.hybrid.sdk.HybridSdkValue> lifecycle) {
            if (intent.operation() == EnrollmentTransaction.Operation.ISSUE) {
                if (!lifecycle.isEmpty() || intent.predecessorId().isPresent() || intent.predecessorSha256().isPresent()) { throw invalid(); }
            } else {
                if (intent.predecessorId().isEmpty() || intent.predecessorSha256().isEmpty()
                        || !lifecycle.get("predecessorId").textValue().equals(intent.predecessorId().orElseThrow().value())
                        || !lifecycle.get("predecessorSha256").textValue().equals("sha256:" + intent.predecessorSha256().orElseThrow())) { throw invalid(); }
            }    }
    }


    /** Groups one bounded protocol validation responsibility. */
    private static final class Scalars {
        private static void text(DataOutputStream out, String text) throws IOException { EnrollmentTransactionCodec.text(out, text); }

        private static String text(DataInputStream in) throws IOException { return EnrollmentTransactionCodec.text(in); }

        private static boolean flag(DataInputStream in) throws IOException { int value = in.readUnsignedByte(); if (value > BOOLEAN_TRUE) { throw invalid(); } return value == 1; }

        private static void blob(DataOutputStream out, byte[] bytes) throws IOException { if (bytes.length > MAXIMUM_BYTES) { throw invalid(); } out.writeInt(bytes.length); out.write(bytes); }

        private static byte[] blob(DataInputStream in) throws IOException { int size = in.readInt(); if (size < 0 || size > MAXIMUM_BYTES || size > in.available()) { throw invalid(); } return in.readNBytes(size); }

        private static void optional(DataOutputStream out, Optional<String> value) throws IOException { out.writeBoolean(value.isPresent()); if (value.isPresent()) { text(out, value.orElseThrow()); } }

        private static Optional<String> optional(DataInputStream in) throws IOException { return flag(in) ? Optional.of(text(in)) : Optional.empty(); }

        private static void optionalBlob(DataOutputStream out, Optional<byte[]> value) throws IOException { out.writeBoolean(value.isPresent()); if (value.isPresent()) { blob(out, value.orElseThrow()); } }

        private static Optional<byte[]> optionalBlob(DataInputStream in) throws IOException { return flag(in) ? Optional.of(blob(in)) : Optional.empty(); }

        private static void instant(DataOutputStream out, Instant value) throws IOException { out.writeLong(value.getEpochSecond()); out.writeInt(value.getNano()); }

        private static Instant instant(DataInputStream in) throws IOException { return Instant.ofEpochSecond(in.readLong(), in.readInt()); }

        private static Optional<String> consumedText(DataInputStream in, boolean consumed) throws IOException {
            return consumed ? Optional.of(text(in)) : Optional.empty();
        }

        private static Optional<byte[]> consumedBlob(DataInputStream in, boolean consumed) throws IOException {
            return consumed ? Optional.of(blob(in)) : Optional.empty();
        }

        private static Optional<Instant> consumedInstant(DataInputStream in, boolean consumed) throws IOException {
            return consumed ? Optional.of(instant(in)) : Optional.empty();
        }

        private static EnrollmentSdkIntent.State readState(DataInputStream in) throws IOException {
            int stateCode = in.readUnsignedByte();
            if (stateCode > BOOLEAN_TRUE) { throw invalid(); }
            return stateCode == 0 ? EnrollmentSdkIntent.State.OPEN : EnrollmentSdkIntent.State.CONSUMED;
        }
    }

}
