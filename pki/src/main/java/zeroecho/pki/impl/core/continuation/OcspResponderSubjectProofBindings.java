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

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Objects;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.api.signing.ManagedOcspResponderProofTarget;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole;

/**
 * Checks the exact parent and subject-role bindings of managed responder possession proofs.
 *
 * <p>Responder candidate proofs use their dedicated pre-certificate purpose, not a
 * CA-subject purpose or a fabricated existing credential. Retained metadata checks
 * are separate from bounded live-content checks. Neither path authenticates a caller,
 * grants key-use permission or replaces cryptographic proof/signature verification.
 */
public final class OcspResponderSubjectProofBindings {
    private OcspResponderSubjectProofBindings() {
    }
    /**
     * Identifies the dedicated issuance discriminator in an envelope's outer command.
     *
     * <p>This is a dispatch predicate, not complete envelope or proof validation.
     * An absent outer command or another domain operation returns false.
     *
     * @param envelope immutable signing envelope; must not be null
     * @return whether the exact managed responder certificate operation is selected
     * @throws NullPointerException if the envelope is null
     * @throws IllegalArgumentException if the encoded discriminator cannot be read
     */
    public static boolean supports(zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceEnvelope envelope) {
        return envelope.outer().filter(outer -> outer.kind() == zeroecho.pki.spi.store.DomainContinuationStore.Kind.ISSUANCE
                && DomainCommandEncoding.operation(outer.command()).equals(OcspResponderCertificateCommand.OPERATION)).isPresent();
    }
    /**
     * Validates captured subject proof metadata without resolving live keys or content.
     *
     * <p>Both proof steps must be present. The selected step, canonical outer
     * correlation, provider namespace/configuration, subject-key role, candidate
     * digest and retained proof command must agree. No challenge bytes or current
     * managed public keys are read, and no cryptographic signature is verified here.
     *
     * @param envelope dedicated accepted parent envelope
     * @param role explicit primary or alternative subject-proof role
     * @return exact retained nested proof-command metadata for that role
     * @throws NullPointerException if the envelope or role is null
     * @throws IllegalArgumentException if the operation, canonical correlation, role,
     *         provider, key or candidate metadata differs
     */
    public static DomainCommandEncoding.Decoded requireEnvelope(zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceEnvelope envelope,
            SubjectKeyRole role) {
        if (!supports(envelope) || envelope.proofStep().isEmpty() || envelope.alternativeProofStep().isEmpty()) {
            throw invalid();
        }
        SignWorkflowStore.OuterCommand outer = envelope.outer().orElseThrow();
        OcspResponderCertificateCommand command = OcspResponderCertificateCommand.decode(outer.command());
        if (!outer.commandCommitment().equals(DomainContinuationTemplate.commitment(outer.command()))
                || !outer.correlationId().equals(zeroecho.pki.impl.core.CorrelatedIssuanceIdentity.correlationId(
                        new PkiId(command.fields().get(1)), command.fields().get(17)))
                || !envelope.fairnessAuthorityId().value().equals(command.fields().get(1))) {
            throw invalid();
        }
        SignWorkflowStore.CaSubjectProofStep step = (role == SubjectKeyRole.PRIMARY
                ? envelope.proofStep() : envelope.alternativeProofStep()).orElseThrow();
        DomainCommandEncoding.Decoded proof = requireCommand(command, envelope.operationId(), role);
        if (step.role() != role || !step.operationId().value().equals(command.fields().get(role == SubjectKeyRole.PRIMARY ? 20 : 22))
                || !step.subjectKeyRef().value().equals(proof.field(5)) || !step.algorithmId().equals(proof.field(8))
                || !proof.field(6).equals(envelope.providerNamespace())
                || !proof.field(7).equals(java.util.HexFormat.of().formatHex(envelope.providerConfigurationCommitment().bytes()))) {
            throw invalid();
        }
        ManagedKeyProofBindings.requireCandidate(proof, step.challenge());
        if (envelope.candidate().encoding() != zeroecho.pki.api.Encoding.DER
                || !envelope.candidate().sha256().equals(command.fields().get(16))) {
            throw invalid();
        }
        return proof;
    }
    /**
     * Checks both bounded live proof challenges and their final certificate TBS role bindings.
     *
     * <p>The final TBS is limited to one MiB and must match its retained digest and
     * serial. Both decoded version-four challenges must match the parent, role,
     * frozen target and actual subject SPKI. A temporary certificate wrapper is
     * used only to inspect structure; no dummy signature is trusted. Content
     * handles and streams opened here are closed before return or failure.
     * This check neither invokes a signing provider nor verifies proof signatures.
     *
     * @param store owning staged-content store
     * @param envelope exact prospective or retained dedicated acceptance envelope
     * @throws java.io.IOException for unavailable or corrupt public staged content
     * @throws NullPointerException if the store or envelope is null
     * @throws java.util.NoSuchElementException if the required outer command is absent
     * @throws IllegalArgumentException if a digest, serial, proof challenge or subject-key binding differs
     */
    public static void requireLiveCandidates(zeroecho.pki.spi.store.StagedContentStore store,
            zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceEnvelope envelope) throws java.io.IOException {
        OcspResponderCertificateCommand command = OcspResponderCertificateCommand.decode(
                envelope.outer().orElseThrow().command());
        byte[] tbs;
        try (RepeatableContent content = store.openContent(envelope.candidate()); InputStream input = content.openStream()) {
            if (envelope.candidate().length() > 1_048_576) {
                throw invalid();
            }
            tbs = input.readNBytes(Math.toIntExact(envelope.candidate().length()));
            if (tbs.length != envelope.candidate().length() || input.read() != -1
                    || !zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment.sha256(tbs).sha256()
                            .equals(command.fields().get(16))) {
                throw invalid();
            }
        }
        new zeroecho.pki.impl.framework.x509.StreamingDerReader().inspectUnsignedCertificateTbs(tbs, 1_048_576);
        X509Certificate certificate = zeroecho.pkix.Pkix.parseCertificate(
                zeroecho.pkix.Pkix.assembleCertificateOrCrl(tbs, new byte[] {0}, false));
        if (!certificate.getSerialNumber().toString().equals(command.fields().get(24))) {
            throw invalid();
        }
        for (SubjectKeyRole role : SubjectKeyRole.values()) {
            DomainCommandEncoding.Decoded proof = requireEnvelope(envelope, role);
            SignWorkflowStore.CaSubjectProofStep step = (role == SubjectKeyRole.PRIMARY
                    ? envelope.proofStep() : envelope.alternativeProofStep()).orElseThrow();
            byte[] challenge = ManagedKeyProofBindings.readChallenge(store, step.operationId(), envelope.deadline(),
                    java.util.Optional.empty(), proof, step.challenge());
            ManagedKeyProofChallenge.Decoded decoded = ManagedKeyProofChallenge.decode(challenge);
            requireChallenge(command, envelope.operationId(), role, decoded);
            byte[] actual = role == SubjectKeyRole.PRIMARY ? zeroecho.pkix.Pkix.subjectPublicKeyInfo(certificate)
                    : zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(certificate, "2.5.29.72");
            if (!java.util.Arrays.equals(actual, decoded.spki())) {
                throw invalid();
            }
        }
    }
    /**
     * Validates a retained proof descriptor against its actual parent and captured subject role.
     *
     * <p>The dedicated proof request must select the retained authority, profile,
     * managed subject key, parent intent, final candidate target and role. Its
     * algorithm and SPKI commitments must match that role's captured binding.
     * Validation uses only retained coordinates and does not resolve a provider.
     *
     * @param command complete validated responder certificate command
     * @param parentOperationId actual parent signing-operation identity
     * @param role required primary or alternative subject role
     * @return exact nested proof-command metadata for the selected role
     * @throws NullPointerException if the command or role is null
     * @throws IllegalArgumentException for a changed purpose, role, key, profile or target
     */
    public static DomainCommandEncoding.Decoded requireCommand(OcspResponderCertificateCommand command,
            PkiId parentOperationId, SubjectKeyRole role) {
        Objects.requireNonNull(role, "role");
        DomainCommandEncoding.Decoded proof = command.proofCommand(role);
        if (!(ManagedKeyProofCommand.decodePrefix(proof) instanceof ManagedKeyProofRequest.OcspResponderCandidate candidate)) {
            throw invalid();
        }
        ManagedOcspResponderProofTarget target = candidate.target();
        IssuerKeyBinding subject = command.subjectBinding(role);
        if (!candidate.authorityId().value().equals(command.fields().get(1)) || !candidate.profileRef().equals(command.profile())
                || !candidate.keyRef().equals(subject.keyRef()) || !target.parentOperationId().equals(parentOperationId)
                || target.role() != role || !target.parentIntentCommitment().equals(command.intentCommitment())
                || !target.frozenTargetCommitment().equals(command.frozenTargetCommitment())
                || !proof.field(8).equals(subject.signatureAlgorithm().canonicalForm())
                || !proof.field(9).equals(java.util.HexFormat.of().formatHex(subject.signatureAlgorithmIdentifier().bytes()))
                || !proof.field(11).equals(subject.subjectSpkiSha256())) {
            throw invalid();
        }
        return proof;
    }
    /**
     * Checks the actual decoded version-four challenge against the exact retained descriptor.
     *
     * <p>A CA context is forbidden and the dedicated responder candidate context
     * must be present. The child identity and complete proof metadata must equal
     * the selected retained command. Cryptographic challenge verification remains
     * the consuming proof verifier's responsibility.
     *
     * @param command complete validated responder certificate command
     * @param parentOperationId exact parent signing identity
     * @param role required primary or alternative subject role
     * @param challenge bounded decoded live proof challenge
     * @throws NullPointerException if a required command, role or challenge is null
     * @throws IllegalArgumentException if challenge or descriptor coordinates differ
     */
    public static void requireChallenge(OcspResponderCertificateCommand command, PkiId parentOperationId,
            SubjectKeyRole role, ManagedKeyProofChallenge.Decoded challenge) {
        DomainCommandEncoding.Decoded proof = requireCommand(command, parentOperationId, role);
        if (challenge.context().isPresent() || challenge.candidateContext().isEmpty()
                || !challenge.operationId().value().equals(command.fields().get(role == SubjectKeyRole.PRIMARY ? 20 : 22))
                || !challenge.command().equals(proof)) {
            throw invalid();
        }
    }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Responder subject proof binding invalid");
    }
}
