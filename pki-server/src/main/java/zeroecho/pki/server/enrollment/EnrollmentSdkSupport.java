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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import zeroecho.pki.api.*;
import zeroecho.pki.api.audit.*;
import zeroecho.pki.api.hybrid.sdk.*;
import zeroecho.pki.api.issuance.*;
import zeroecho.pki.server.ApprovalService;

/**
 * Pure bounded shared SDK enrollment frame/context transformations; no authentication or persistence.
 */
final class EnrollmentSdkSupport {
    private EnrollmentSdkSupport() { }
    /**
     * Projects the admitted enrollment requester into domain audit/access coordinates.
     *
     * @param admission trusted enrollment admission
     * @param intent frozen enrollment authorization intent
     * @return access context bound to the predecessor credential or original request identity
     */
    static AccessContext access(EnrollmentCoordinator.Admission admission, EnrollmentTransaction.Intent intent) {
        return new AccessContext(new Principal(admission.requester().type().name(), admission.requester().actorId()),
                new Purpose("ENROLLMENT"), Optional.of(intent.predecessorId().orElse(intent.requestId())), Optional.empty());
    }
    /**
     * Resolves the exact SDK issuance preview for the admitted enrollment operation.
     *
     * @param signing authoritative semantic signing service
     * @param admission trusted protocol admission and original request payload
     * @param intent frozen authorization and issuer/profile coordinates
     * @param parsed parsed original hybrid certificate request
     * @param frozen exact retained absolute validity, or empty before first preview
     * @param target protocol-specific SDK enrollment target binding
     * @return authoritative issuer/profile/subject preview
     * @throws IllegalArgumentException if the operation is server key generation or inputs violate enrollment
     *         invariants
     */
    static SdkIssuancePreview preview(SemanticSigningService signing, EnrollmentCoordinator.Admission admission,
            EnrollmentTransaction.Intent intent, ParsedHybridSdkRequest parsed, Optional<Validity> frozen, SdkEnrollmentTarget target) {
        var access = access(admission, intent);
        return switch (admission.operation()) {
            case ISSUE -> signing.previewSdk(access, new EndEntityIssuanceRequest(intent.authorityId(), admission.payload(), intent.profile().profileId(), admission.validity()), parsed, frozen, Optional.of(target), zeroecho.core.io.CancellationSignal.NONE);
            case RENEW -> signing.previewSdk(access, new EndEntityRenewalRequest(admission.predecessorId().orElseThrow(), admission.validity()), parsed, frozen, Optional.of(target), zeroecho.core.io.CancellationSignal.NONE);
            case REPLACE -> signing.previewSdk(access, new EndEntityReplacementRequest(admission.predecessorId().orElseThrow(), admission.payload(), intent.profile().profileId()), parsed, frozen, Optional.of(target), zeroecho.core.io.CancellationSignal.NONE);
            case SERVER_KEYGEN -> throw EnrollmentTransaction.invalid();
        };
    }
    /**
     * Builds the exact kind-seven SDK target from frozen enrollment and authoritative issuance coordinates.
     *
     * @param admission trusted enrollment operation/requester context
     * @param intent frozen authorization, profile and approval-policy snapshot
     * @param preview authoritative issuance preview
     * @return semantic target frame with canonical arguments, issuer bindings, subject and disclosure policy
     * @throws IllegalArgumentException if the admitted operation is outside the supported issuance family
     */
    static HybridSdkFrame target(EnrollmentCoordinator.Admission admission, EnrollmentTransaction.Intent intent, SdkIssuancePreview preview) {
        var arguments = new TreeMap<String, HybridSdkValue>(); String operation;
        switch (admission.operation()) {
            case ISSUE -> { operation = "credential.issue"; arguments.put("issuerCaId", HybridSdkValue.text(intent.authorityId().value())); arguments.put("requestId", HybridSdkValue.text(intent.requestId().value())); arguments.put("profileId", HybridSdkValue.text(intent.profile().profileId())); }
            case RENEW -> { operation = "credential.renew"; arguments.put("credentialId", HybridSdkValue.text(intent.predecessorId().orElseThrow().value())); }
            case REPLACE -> { operation = "credential.replace"; arguments.put("existingCredentialId", HybridSdkValue.text(intent.predecessorId().orElseThrow().value())); arguments.put("requestId", HybridSdkValue.text(intent.requestId().value())); arguments.put("profileId", HybridSdkValue.text(intent.profile().profileId())); }
            case SERVER_KEYGEN -> throw EnrollmentTransaction.invalid();
            default -> throw EnrollmentTransaction.invalid();
        }
        var fields = new TreeMap<Integer, byte[]>(); fields.put(1, text(operation)); fields.put(2, HybridSdkValue.object(arguments).encode()); fields.put(3, text(admission.requester().actorId()));
        fields.put(4, text(preview.issuerCaId().value())); fields.put(5, text(preview.issuerId().value())); fields.put(6, text(preview.chainPathId().value()));
        fields.put(7, text("sha512:" + preview.issuerCertificateSha512())); fields.put(8, preview.primaryIssuerBindingFrame().encode()); fields.put(9, preview.alternativeIssuerBindingFrame().map(HybridSdkFrame::encode).orElseGet(() -> new byte[0]));
        fields.put(10, text(preview.profile().profileId())); fields.put(11, time(preview.profile().profileVersion())); fields.put(12, text("sha256:" + HexFormat.of().formatHex(preview.profile().canonicalSha256())));
        fields.put(13, text(preview.bindingSetCommitment())); fields.put(14, text("sha256:" + intent.approvalPolicy().map(ApprovalService.Policy::commitment).orElseGet(() -> ApprovalService.digest(""))));
        fields.put(15, preview.effectiveSubjectValue().encode()); fields.put(16, preview.disclosurePolicy().encode()); fields.put(17, preview.targetExtensionValue().encode());
        return new HybridSdkFrame(7, fields);
    }
    /**
     * Recovers absolute validity from a semantic target without rebasing to the current clock.
     *
     * @param target retained semantic target with an encoded effective subject
     * @return exact retained not-before/not-after instants
     * @throws IllegalArgumentException if the subject value or timestamp encoding is invalid
     */
    static Validity validity(HybridSdkFrame target) {
        var value = HybridSdkValue.decode(target.field(15)).objectFields();
        return new Validity(Instant.parse(value.get("notBefore").textValue()), Instant.parse(value.get("notAfter").textValue()));
    }
    /**
     * Copies an enrollment intent with exact absolute validity and its accepted SDK proof reference.
     *
     * @param intent original frozen enrollment intent
     * @param validity exact effective validity captured by the SDK target
     * @param proof accepted SDK proof reference, or empty before acceptance
     * @return replacement retaining all other intent coordinates
     */
    static EnrollmentTransaction.Intent frozen(EnrollmentTransaction.Intent intent, Validity validity,
            Optional<EnrollmentTransaction.SdkProofReference> proof) {
        return new EnrollmentTransaction.Intent(intent.realmId(), intent.source(), intent.requester(), intent.transactionId(), intent.operation(), intent.requestId(), intent.requestKind(), intent.requestSha256(), intent.requestBytes(),
                intent.authorityId(), intent.profile(), intent.issuerId(), intent.pathId(), intent.pathCommitment(), Optional.of(validity), intent.predecessorId(), intent.predecessorSha256(), intent.approvalCategory(), intent.approvalPolicy(), intent.artifact(), intent.createdAt(), intent.expiresAt(), proof);
    }
    /**
     * Checks exact protocol authentication, endpoint, policy and original-message bindings.
     *
     * @param supplied server-resolved SDK enrollment admission
     * @param intent frozen enrollment authorization intent
     * @param policyVersion exact enrollment-policy version
     * @throws IllegalArgumentException if any actor, endpoint, policy, key or native-message binding differs
     */
    static void requireContext(EnrollmentSdkAdmission supplied, EnrollmentTransaction.Intent intent, long policyVersion) {
        var a = supplied.admission(); var target = supplied.target(); var source = intent.source(); var auth = supplied.authenticationContext();
        String carrier = a.protocol().name().toLowerCase(Locale.ROOT) + "-v1";
        if (!new String(auth.field(1), StandardCharsets.UTF_8).equals(a.requester().actorId())
                || !new String(auth.field(4), StandardCharsets.UTF_8).equals(carrier)
                || !target.authenticationContextSha512().equals(hash(auth.encode())) || !source.label().equals(target.endpointId())
                || !source.commitment().equals(target.endpointCommitment()) || source.revision() != target.sourceRevision()
                || !source.enrollmentProfileId().equals(target.enrollmentPolicyId()) || policyVersion != target.enrollmentPolicyVersion()
                || !source.enrollmentCommitment().equals(target.enrollmentPolicyCommitment())) throw EnrollmentTransaction.invalid();
        var nativeContext = HybridSdkValue.decode(auth.field(5)).objectFields();
        if (!nativeContext.get("endpointId").textValue().equals(source.label())
                || !nativeContext.get("endpointCommitment").textValue().equals(source.commitment())
                || !nativeContext.get("requestKind").textValue().equals(a.payload().kind().name())) throw EnrollmentTransaction.invalid();
        if (a.protocol() == EnrollmentTransaction.Protocol.ACME
                && (!nativeContext.get("accountId").textValue().equals(a.requester().actorId())
                        || !a.requester().canonicalKeySha256().equals(Optional.of(nativeContext.get("accountKeySha256").textValue())))) throw EnrollmentTransaction.invalid();
        if (supplied.nativeWire().isPresent()) {
            String key = a.protocol() == EnrollmentTransaction.Protocol.CMP ? "originalWireSha512" : "nativeMessageSha512";
            if (!nativeContext.get(key).textValue().equals(hash(supplied.nativeWire().orElseThrow()))) throw EnrollmentTransaction.invalid();
            if (supplied.cmpManifest().isPresent() && !supplied.cmpManifest().orElseThrow().originalWireSha256()
                    .equals(EnrollmentTransactionCodec.sha256(supplied.nativeWire().orElseThrow()))) throw EnrollmentTransaction.invalid();
        }
        Optional<String> anchor = a.protocol() == EnrollmentTransaction.Protocol.ACME ? a.requester().canonicalKeySha256()
                : a.requester().certificate().map(zeroecho.pki.server.CertificateIdentityEvidence::certificateSha256);
        if (anchor.isPresent() && !Arrays.equals(auth.field(3), HybridSdkFrame.hash(text("sha256:" + anchor.orElseThrow())))) throw EnrollmentTransaction.invalid();
    }
    /**
     * Compares immutable accepted ownership and original-request coordinates for replay.
     *
     * <p>ACME ownership follows account identity; certificate/PBM protocols additionally
     * bind the original authentication credential. Current mutable policy is not compared here.</p>
     *
     * @param retained original accepted server-resolved admission
     * @param supplied current authenticated replay admission
     * @return whether actor, protocol, transaction, payload, validity and native wire match the accepted request
     */
    static boolean sameAcceptedOwnerAndRequest(EnrollmentSdkAdmission retained, EnrollmentSdkAdmission supplied) {
        var a = retained.admission(); var b = supplied.admission();
        var owner = a.requester(); var current = b.requester();
        if (owner.type() != current.type() || owner.authentication() != current.authentication()
                || !owner.actorId().equals(current.actorId()) || !owner.aliases().realmId().equals(current.aliases().realmId())) return false;
        if (a.protocol() != EnrollmentTransaction.Protocol.ACME) {
            if (!owner.canonicalKeySha256().equals(current.canonicalKeySha256())
                    || owner.certificate().isPresent() != current.certificate().isPresent()
                    || owner.certificate().isPresent() && !owner.certificate().orElseThrow().sameCredential(current.certificate().orElseThrow())) return false;
            if (owner.type() == zeroecho.pki.application.IssuanceExecutionEvidence.ActorType.CMP_PBM) {
                var oldAuth = HybridSdkValue.decode(retained.authenticationContext().field(5)).objectFields();
                var newAuth = HybridSdkValue.decode(supplied.authenticationContext().field(5)).objectFields();
                if (!oldAuth.get("authenticationCredentialId").textValue().equals(newAuth.get("authenticationCredentialId").textValue())
                        || oldAuth.get("authenticationCredentialRevision").integerValue() != newAuth.get("authenticationCredentialRevision").integerValue()) return false;
            }
        }
        return a.protocol() == b.protocol() && a.endpointId().equals(b.endpointId()) && a.transactionId().equals(b.transactionId())
                && a.operation() == b.operation() && a.payload().kind() == b.payload().kind() && Arrays.equals(a.payload().der(), b.payload().der())
                && a.validity().equals(b.validity()) && a.predecessorId().equals(b.predecessorId())
                && retained.nativeWire().isPresent() == supplied.nativeWire().isPresent()
                && (retained.nativeWire().isEmpty() || Arrays.equals(retained.nativeWire().orElseThrow(), supplied.nativeWire().orElseThrow()));
    }

    /**
     * Compares complete server-resolved SDK admissions before proof acceptance.
     *
     * @param left first resolved admission
     * @param right second resolved admission
     * @return whether actor, endpoint, deadlines, original bytes, target, authentication and CMP context match
     */
    static boolean sameAdmission(EnrollmentSdkAdmission left, EnrollmentSdkAdmission right) {
        var a = left.admission(); var b = right.admission();
        return a.protocol() == b.protocol() && a.endpointId().equals(b.endpointId()) && a.requester().equals(b.requester())
                && a.transactionId().equals(b.transactionId()) && a.operation() == b.operation() && a.payload().kind() == b.payload().kind()
                && Arrays.equals(a.payload().der(), b.payload().der()) && a.validity().equals(b.validity()) && a.predecessorId().equals(b.predecessorId())
                && a.protocolDeadline().equals(b.protocolDeadline()) && left.expectedEndpointCommitment().equals(right.expectedEndpointCommitment())
                && left.canonicalOrigin().equals(right.canonicalOrigin()) && Arrays.equals(left.authenticationContext().encode(), right.authenticationContext().encode())
                && Arrays.equals(left.target().value().encode(), right.target().value().encode()) && left.cmpManifest().equals(right.cmpManifest())
                && left.nativeWire().isPresent() == right.nativeWire().isPresent()
                && (left.nativeWire().isEmpty() || Arrays.equals(left.nativeWire().orElseThrow(), right.nativeWire().orElseThrow()));
    }
    /**
     * Computes the domain's textual SHA-512 binding for exact protocol bytes.
     *
     * @param bytes original message or canonical frame bytes
     * @return {@code sha512:} followed by lowercase hexadecimal digest
     * @throws NullPointerException if bytes is null
     */
    static String hash(byte[] bytes) { return "sha512:" + HexFormat.of().formatHex(HybridSdkFrame.hash(bytes)); }
    /**
     * Encodes canonical frame text as UTF-8 without adding a terminator.
     *
     * @param value validated canonical frame text
     * @return newly allocated UTF-8 bytes
     * @throws NullPointerException if value is null
     */
    static byte[] text(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    /**
     * Encodes a signed 64-bit frame coordinate in canonical big-endian order.
     *
     * @param value coordinate value, such as a profile version or epoch-second timestamp
     * @return newly allocated eight-byte encoding
     */
    static byte[] time(long value) { return ByteBuffer.allocate(8).putLong(value).array(); }
}
