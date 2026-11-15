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

import java.util.Objects;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole;

/** Pure exact parent/subject-role checks for the new managed responder carrier, never a CA purpose. */
public final class OcspResponderSubjectProofBindings {
    private OcspResponderSubjectProofBindings() { }
    /** @param envelope immutable domain envelope @return whether the exact dedicated operation is selected */
    public static boolean supports(zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceEnvelope envelope) {
        return envelope.outer().filter(outer -> outer.kind() == zeroecho.pki.spi.store.DomainContinuationStore.Kind.ISSUANCE
                && DomainCommandEncoding.operation(outer.command()).equals(OcspResponderCertificateCommand.OPERATION)).isPresent();
    }
    /**
     * Validates captured subject proof metadata without resolving live keys or content.
     * @param envelope dedicated accepted parent @param role selected proof role
     * @return exact retained proof command @throws IllegalArgumentException for any binding mismatch
     */
    public static DomainCommandEncoding.Decoded requireEnvelope(zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceEnvelope envelope,
            SubjectKeyRole role) {
        if (!supports(envelope) || envelope.proofStep().isEmpty() || envelope.alternativeProofStep().isEmpty()) throw invalid();
        var outer = envelope.outer().orElseThrow();
        var command = OcspResponderCertificateCommand.decode(outer.command());
        if (!outer.commandCommitment().equals(DomainContinuationTemplate.commitment(outer.command()))
                || !outer.correlationId().equals(zeroecho.pki.impl.core.CorrelatedIssuanceIdentity.correlationId(
                        new PkiId(command.fields().get(1)), command.fields().get(17)))
                || !envelope.fairnessAuthorityId().value().equals(command.fields().get(1))) throw invalid();
        var step = (role == SubjectKeyRole.PRIMARY ? envelope.proofStep() : envelope.alternativeProofStep()).orElseThrow();
        var proof = requireCommand(command, envelope.operationId(), role);
        if (step.role() != role || !step.operationId().value().equals(command.fields().get(role == SubjectKeyRole.PRIMARY ? 20 : 22))
                || !step.subjectKeyRef().value().equals(proof.field(5)) || !step.algorithmId().equals(proof.field(8))
                || !proof.field(6).equals(envelope.providerNamespace())
                || !proof.field(7).equals(java.util.HexFormat.of().formatHex(envelope.providerConfigurationCommitment().bytes()))) throw invalid();
        ManagedKeyProofBindings.requireCandidate(proof, step.challenge());
        if (envelope.candidate().encoding() != zeroecho.pki.api.Encoding.DER
                || !envelope.candidate().sha256().equals(command.fields().get(16))) throw invalid();
        return proof;
    }
    /**
     * Checks both bounded live proof challenges and their final certificate TBS role bindings.
     * @param store owning staged-content store @param envelope exact prospective or retained acceptance
     * @throws java.io.IOException for unavailable or corrupt public staged content
     */
    public static void requireLiveCandidates(zeroecho.pki.spi.store.StagedContentStore store,
            zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceEnvelope envelope) throws java.io.IOException {
        var command = OcspResponderCertificateCommand.decode(envelope.outer().orElseThrow().command());
        byte[] tbs;
        try (var content = store.openContent(envelope.candidate()); var input = content.openStream()) {
            if (envelope.candidate().length() > 1_048_576) throw invalid();
            tbs = input.readNBytes(Math.toIntExact(envelope.candidate().length()));
            if (tbs.length != envelope.candidate().length() || input.read() != -1
                    || !zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment.sha256(tbs).sha256().equals(command.fields().get(16))) throw invalid();
        }
        new zeroecho.pki.impl.framework.x509.StreamingDerReader().inspectUnsignedCertificateTbs(tbs, 1_048_576);
        var certificate = zeroecho.pkix.Pkix.parseCertificate(zeroecho.pkix.Pkix.assembleCertificateOrCrl(tbs, new byte[]{0}, false));
        if (!certificate.getSerialNumber().toString().equals(command.fields().get(24))) throw invalid();
        for (var role : SubjectKeyRole.values()) {
            var proof = requireEnvelope(envelope, role);
            var step = (role == SubjectKeyRole.PRIMARY ? envelope.proofStep() : envelope.alternativeProofStep()).orElseThrow();
            byte[] challenge = ManagedKeyProofBindings.readChallenge(store, step.operationId(), envelope.deadline(),
                    java.util.Optional.empty(), proof, step.challenge());
            var decoded = ManagedKeyProofChallenge.decode(challenge);
            requireChallenge(command, envelope.operationId(), role, decoded);
            byte[] actual = role == SubjectKeyRole.PRIMARY ? zeroecho.pkix.Pkix.subjectPublicKeyInfo(certificate)
                    : zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(certificate, "2.5.29.72");
            if (!java.util.Arrays.equals(actual, decoded.spki())) throw invalid();
        }
    }
    /**
     * Validates a retained proof descriptor against its actual parent and captured subject role.
     * @param command complete responder certificate command @param parentOperationId actual parent operation
     * @param role required subject role @return exact nested proof metadata
     * @throws IllegalArgumentException for a changed purpose, role, key, profile or target
     */
    public static DomainCommandEncoding.Decoded requireCommand(OcspResponderCertificateCommand command,
            PkiId parentOperationId, SubjectKeyRole role) {
        Objects.requireNonNull(role, "role"); var proof = command.proofCommand(role);
        if (!(ManagedKeyProofCommand.decodePrefix(proof) instanceof ManagedKeyProofRequest.OcspResponderCandidate candidate)) throw invalid();
        var target = candidate.target(); var subject = command.subjectBinding(role);
        if (!candidate.authorityId().value().equals(command.fields().get(1)) || !candidate.profileRef().equals(command.profile())
                || !candidate.keyRef().equals(subject.keyRef()) || !target.parentOperationId().equals(parentOperationId)
                || target.role() != role || !target.parentIntentCommitment().equals(command.intentCommitment())
                || !target.frozenTargetCommitment().equals(command.frozenTargetCommitment())
                || !proof.field(8).equals(subject.signatureAlgorithm().canonicalForm())
                || !proof.field(9).equals(java.util.HexFormat.of().formatHex(subject.signatureAlgorithmIdentifier().bytes()))
                || !proof.field(11).equals(subject.subjectSpkiSha256())) throw invalid();
        return proof;
    }
    /**
     * Checks the actual decoded version-four challenge against the exact retained descriptor.
     * @param command complete parent command @param parentOperationId parent signing identity
     * @param role required subject role @param challenge bounded decoded live challenge
     * @throws IllegalArgumentException if challenge or descriptor coordinates differ
     */
    public static void requireChallenge(OcspResponderCertificateCommand command, PkiId parentOperationId,
            SubjectKeyRole role, ManagedKeyProofChallenge.Decoded challenge) {
        var proof = requireCommand(command, parentOperationId, role);
        if (challenge.context().isPresent() || challenge.candidateContext().isEmpty()
                || !challenge.operationId().value().equals(command.fields().get(role == SubjectKeyRole.PRIMARY ? 20 : 22))
                || !challenge.command().equals(proof)) throw invalid();
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Responder subject proof binding invalid"); }
}
