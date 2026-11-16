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

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;

/**
 * Validates the binding between retained CA subject-key proofs and their parent candidate.
 *
 * <p>Metadata checks bind each selected role to its exact command, algorithm, managed
 * key and public-key commitment. Live-candidate checks additionally read the staged
 * challenge and certificate TBS. These checks do not verify a signature, contact a
 * signing provider or grant authority to use a key.
 */
public final class CaSubjectProofBindings {
    private CaSubjectProofBindings() {
    }

    /**
     * Checks the retained primary-role metadata without opening staged content.
     *
     * <p>This is the primary-role convenience form of
     * {@link #requireEnvelope(SignWorkflowStore.AcceptanceEnvelope, SignWorkflowStore.SubjectKeyRole)}.
     * Domain descriptors are decoded, but no configured certificate codec or provider
     * is resolved and no live candidate bytes are opened.
     *
     * @param envelope accepted composite CA envelope
     * @return exact frozen proof command
     * @throws NullPointerException if the envelope is null
     * @throws IllegalArgumentException if the envelope, nested command or retained proof binding is invalid
     */
    public static DomainCommandEncoding.Decoded requireEnvelope(SignWorkflowStore.AcceptanceEnvelope envelope) {
        return requireEnvelope(envelope, SignWorkflowStore.SubjectKeyRole.PRIMARY);
    }

    /**
     * Validates exact descriptor, algorithm and SPKI commitments for a selected subject role.
     *
     * <p>The outer command, child identity, provider commitment and challenge metadata
     * must describe the same role. Extended commands also distinguish the child's
     * outgoing subject-key algorithm from the parent's incoming certificate signature.
     * No staged content or current authority state is read by this method.
     *
     * @param envelope complete admitted intermediate-command envelope
     * @param role required primary or alternative subject-key role; must not be null
     * @return exact nested command for that role
     * @throws NullPointerException if the envelope is null
     * @throws IllegalArgumentException if the requested role is absent or any retained
     *         descriptor, identity, key, algorithm, provider or challenge commitment differs
     */
    public static DomainCommandEncoding.Decoded requireEnvelope(SignWorkflowStore.AcceptanceEnvelope envelope,
            SignWorkflowStore.SubjectKeyRole role) {
        IntermediateSigningCommand.requireEnvelope(envelope);
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(envelope.outer().orElseThrow().command());
        if (IntermediateSigningCommand.alternativeProof(command).isPresent() != envelope.alternativeProofStep().isPresent()) {
            throw invalid();
        }
        SignWorkflowStore.CaSubjectProofStep step = (role == SignWorkflowStore.SubjectKeyRole.PRIMARY
                ? envelope.proofStep() : envelope.alternativeProofStep())
                .orElseThrow(CaSubjectProofBindings::invalid);
        DomainCommandEncoding.Decoded proof = role == SignWorkflowStore.SubjectKeyRole.PRIMARY
                ? IntermediateSigningCommand.validate(command)
                : IntermediateSigningCommand.alternativeProof(command).orElseThrow(CaSubjectProofBindings::invalid);
        if (step.role() != role || !proof.field(5).equals(step.subjectKeyRef().value())
                || !proof.field(8).equals(step.algorithmId())
                || !proof.field(6).equals(envelope.providerNamespace())
                || !proof.field(7).equals(java.util.HexFormat.of().formatHex(envelope.providerConfigurationCommitment().bytes()))) {
            throw invalid();
        }
        if (role == SignWorkflowStore.SubjectKeyRole.PRIMARY && !command.field(18).equals(step.operationId().value())) {
            throw invalid();
        }
        if (role == SignWorkflowStore.SubjectKeyRole.ALTERNATIVE && !IntermediateSigningCommand.alternativeProofId(command)
                .orElseThrow(CaSubjectProofBindings::invalid).equals(step.operationId())) {
            throw invalid();
        }
        if (command.fields().size() == 23 && !envelope.algorithmId().equals(step.algorithmId())) {
            throw invalid();
        }
        if (command.fields().size() >= 25) {
            CaOutgoingBinding outgoing = CaOutgoingBinding.decodeForSubject(command.field(23), new KeyRef(command.field(6)));
            CaOutgoingBinding incoming = CaOutgoingBinding.decodeForSubject(command.field(24), new KeyRef(command.field(14)));
            IssuerKeyBinding selected = role == SignWorkflowStore.SubjectKeyRole.PRIMARY ? outgoing.primary()
                    : outgoing.alternative().orElseThrow(CaSubjectProofBindings::invalid);
            if (!incoming.primary().signatureAlgorithm().canonicalForm().equals(envelope.algorithmId())
                    || !selected.keyRef().equals(step.subjectKeyRef())
                    || !selected.signatureAlgorithm().canonicalForm().equals(step.algorithmId())
                    || !java.util.HexFormat.of().formatHex(selected.signatureAlgorithmIdentifier().bytes()).equals(proof.field(9))
                    || !selected.subjectSpkiSha256().equals(proof.field(11))) {
                throw invalid();
            }
        }
        ManagedKeyProofBindings.requireCandidate(proof, step.challenge());
        return proof;
    }

    /**
     * Derives the exact signed proof role/context without reading current authority state.
     *
     * <p>The caller must supply an already validated composite envelope. A dual-proof
     * envelope carries an explicit role and lifecycle commitment; an older single-proof
     * envelope retains its version-two context. This method does not independently
     * authorize the parent or verify a signature.
     *
     * @param envelope immutable admitted parent envelope with its outer command present
     * @param role selected child subject role; required when the envelope has dual proofs
     * @return byte-exact v2 context for single proof, explicit v3 context for dual proof
     * @throws NullPointerException if the envelope is null or a dual-proof role is null
     * @throws java.util.NoSuchElementException if the envelope has no outer command
     * @throws IllegalArgumentException if a command, parent identity or retained context is malformed
     */
    public static ManagedKeyProofChallenge.CaContext context(SignWorkflowStore.AcceptanceEnvelope envelope,
            SignWorkflowStore.SubjectKeyRole role) {
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(envelope.outer().orElseThrow().command());
        String intent = CaSigningIntent.commitmentOfCanonicalAlgorithm(command, envelope.algorithmId());
        if (envelope.alternativeProofStep().isEmpty()) {
            return new ManagedKeyProofChallenge.CaContext(envelope.operationId(), intent);
        }
        String lifecycle = command.fields().size() == 26
                ? CaLifecycleContextCodec.commitment(CaLifecycleContextCodec.decode(command.field(25)))
                : intent.substring("ca-intent:v1:".length());
        return new ManagedKeyProofChallenge.CaContext(envelope.operationId(), intent, Optional.of(role), Optional.of(lifecycle));
    }

    /**
     * Reads the staged certificate TBS and required proof challenges to reject substitution.
     *
     * <p>Checks challenge, intent, algorithm,
     * SPKI or final-TBS substitution. Current commands independently bind the
     * child's outgoing proof and the parent's incoming certificate algorithm.
     * No signature verification or provider call occurs. Streams and content handles
     * opened here are closed before return, including on failure; staged content is
     * not mutated or adopted by this check.
     * @param store owning content store
     * @param envelope accepted/prospective composite envelope
     * @throws IOException if content integrity or canonical DER validation fails
     * @throws NullPointerException if the store or envelope is null
     * @throws IllegalArgumentException if retained metadata, content digest, subject key
     *         or algorithm does not match the frozen parent and proof coordinates
     * @throws java.util.NoSuchElementException if the envelope has no outer command
     */
    public static void requireLiveCandidates(StagedContentStore store, SignWorkflowStore.AcceptanceEnvelope envelope) throws IOException {
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(envelope.outer().orElseThrow().command());
        byte[] tbs;
        try (RepeatableContent content = store.openContent(envelope.candidate()); InputStream input = content.openStream()) {
            int length = Math.toIntExact(envelope.candidate().length());
            tbs = input.readNBytes(length);
            if (tbs.length != length || input.read() != -1
                    || !ContentCommitment.sha256(tbs).sha256().equals(command.field(22))) {
                throw invalid();
            }
        }
        StreamingDerReader.CertificateTbsLayout layout = new StreamingDerReader()
                .inspectUnsignedCertificateTbs(tbs, 1_048_576);
        requireLiveRole(store, envelope, SignWorkflowStore.SubjectKeyRole.PRIMARY, command, tbs, layout);
        if (envelope.alternativeProofStep().isPresent()) {
            requireLiveRole(store, envelope, SignWorkflowStore.SubjectKeyRole.ALTERNATIVE, command, tbs, layout);
        }
    }

    private static void requireLiveRole(StagedContentStore store, SignWorkflowStore.AcceptanceEnvelope envelope,
            SignWorkflowStore.SubjectKeyRole role, DomainCommandEncoding.Decoded command, byte[] tbs,
            StreamingDerReader.CertificateTbsLayout layout) throws IOException {
        DomainCommandEncoding.Decoded proof = requireEnvelope(envelope, role);
        SignWorkflowStore.CaSubjectProofStep step = (role == SignWorkflowStore.SubjectKeyRole.PRIMARY
                ? envelope.proofStep() : envelope.alternativeProofStep()).orElseThrow();
        byte[] challenge = ManagedKeyProofBindings.readChallenge(store, step.operationId(), envelope.deadline(),
                Optional.of(context(envelope, role)), proof, step.challenge());
        byte[] spki = ManagedKeyProofChallenge.decode(challenge).spki();
        if (role == SignWorkflowStore.SubjectKeyRole.PRIMARY) {
            byte[] algorithm = command.fields().size() >= 25
                    ? CaOutgoingBinding.decodeForSubject(command.field(24), new KeyRef(command.field(14)))
                            .primary().signatureAlgorithmIdentifier().bytes()
                    : ManagedKeyProofCommand.hex(proof.field(9), 1, ManagedKeyProofCommand.MAX_ALGORITHM_DER_BYTES);
            if (!Arrays.equals(tbs, layout.subjectPublicKeyInfoOffset(),
                        Math.addExact(layout.subjectPublicKeyInfoOffset(), layout.subjectPublicKeyInfoLength()), spki, 0, spki.length)
                    || !Arrays.equals(tbs, layout.algorithmOffset(), Math.addExact(layout.algorithmOffset(), layout.algorithmLength()),
                        algorithm, 0, algorithm.length)) {
                throw invalid();
            }
        } else {
            // The temporary SIGNED wrapper is only a structural view of the already bounded TBS.
            // No signature is trusted or published through this parsing path.
            X509Certificate certificate = zeroecho.pkix.Pkix.parseCertificate(
                    zeroecho.pkix.Pkix.assembleCertificateOrCrl(tbs, new byte[] {0}, false));
            byte[] exact = zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(certificate, "2.5.29.72");
            if (!Arrays.equals(exact, spki)) {
                throw invalid();
            }
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("CA subject proof binding differs");
    }
}
