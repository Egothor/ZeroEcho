/*******************************************************************************
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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Optional;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.common.sig.SignatureInteropProfile;
import zeroecho.core.alg.common.sig.SignatureInteropProfiles;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.err.VerificationException;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability.Direction;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509SuiteCompatibility;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.impl.framework.x509.bc.BcX509PublicKeyAdapter;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pkix.Pkix;
import zeroecho.sdk.ZeroEchoSession;

/** Verifies bounded proof challenges without publishing any PKI artifact. */
final class ManagedKeyProofVerifier {
    private final PkiStore store;
    private final X509AuthoritySnapshot authority;
    private final BcX509VerificationExecutor executor;
    private final long pureEdDsaMaximum;

    /* default */ ManagedKeyProofVerifier(PkiStore store, X509AuthoritySnapshot authority,
            BcX509VerificationExecutor executor, long maximum) {
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.authority = java.util.Objects.requireNonNull(authority, "authority");
        this.executor = java.util.Objects.requireNonNull(executor, "executor");
        this.pureEdDsaMaximum = maximum;
    }

    /* default */ EncodedObject verify(DomainContinuationStore.Record domain, SignWorkflowStore.Workflow workflow) {
        DomainCommandEncoding.Decoded command = ManagedKeyProofBindings.requireWorkflow(workflow, domain);
        EncodedObject signature = workflow.result().orElseThrow();
        if (signature.encoding() != Encoding.BINARY || signature.byteLength() > 1_048_576) { throw invalid(); }
        FullCrlSigningCommand.requireAdmission(command.field(8), workflow.envelope().candidate().length(), pureEdDsaMaximum);
        try {
            byte[] challenge = ManagedKeyProofBindings.readChallenge(store.stagedContent(), domain.operationId(), workflow.deadline(), Optional.empty(), command,
                    workflow.envelope().candidate());
            verify(command, challenge, signature);
            return ManagedKeyProofBindings.result(domain);
        } catch (IOException | GeneralSecurityException failure) {
            // Read failures, missing engines and key-store/provider infrastructure are retryable.
            throw new PkiException("Managed key proof verification is temporarily unavailable", failure);
        }
    }

    /* default */ void verifyComposite(SignWorkflowStore.Workflow workflow) {
        if (workflow.state() != SignWorkflowStore.State.DISPATCHED
                || workflow.stage() != SignWorkflowStore.Stage.CA_PROOF_VERIFYING
                || workflow.leaseUntil().isEmpty()) {
            throw new IllegalArgumentException("CA proof is not claimed for verification");
        }
        DomainCommandEncoding.Decoded command = CaSubjectProofBindings.requireEnvelope(workflow.envelope());
        SignWorkflowStore.CaSubjectProofStep step = workflow.envelope().proofStep().orElseThrow();
        EncodedObject signature = workflow.result().orElseThrow();
        if (signature.encoding() != Encoding.BINARY || signature.byteLength() > 1_048_576) { throw invalid(); }
        FullCrlSigningCommand.requireAdmission(step.algorithmId(), step.challenge().length(), pureEdDsaMaximum);
        try {
            CaSubjectProofBindings.requireLiveCandidates(store.stagedContent(), workflow.envelope());
            DomainCommandEncoding.Decoded ca = DomainCommandEncoding.decode(workflow.envelope().outer().orElseThrow().command());
            String intent = CaSigningIntent.commitmentOfCanonicalAlgorithm(ca, workflow.envelope().algorithmId());
            byte[] challenge = ManagedKeyProofBindings.readChallenge(store.stagedContent(), step.operationId(), workflow.deadline(),
                    Optional.of(new ManagedKeyProofChallenge.CaContext(workflow.operationId(), intent)), command, step.challenge());
            verify(command, challenge, signature);
        } catch (IOException | GeneralSecurityException failure) {
            throw new PkiException("Managed key proof verification is temporarily unavailable", failure);
        }
    }

    private void verify(DomainCommandEncoding.Decoded command, byte[] challenge, EncodedObject signature)
            throws IOException, GeneralSecurityException {
        ManagedKeyProofChallenge.Decoded decoded = ManagedKeyProofChallenge.decode(challenge);
        AlgorithmIdentity identity = ManagedKeyProofCommand.validateAlgorithm(command, authority);
        byte[] spki = decoded.spki();
        AlgorithmIdentity keyIdentity = new BcX509AlgorithmAdapter(authority.bindings()).decode(
                Pkix.subjectPublicKeyAlgorithm(spki), X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        X509SuiteCompatibility.requireCompatible(identity, keyIdentity);
        X509ExecutionPlan<BcX509VerificationExecutor> plan = authority.plan(identity, keyIdentity, Direction.VERIFY,
                Optional.empty(), "managed-key-proof", BcX509VerificationExecutor.class);
        authority.authorize(plan, executor, Direction.VERIFY);
        byte[] algorithm = Pkix.encodeAlgorithmIdentifier(BcX509AlgorithmAdapter.toLib(plan.selection().binding()));
        if (!HexFormat.of().formatHex(algorithm).equals(command.field(9))) {
            throw new IllegalStateException("Managed key proof verification binding differs");
        }
        SignatureInteropProfile profile = SignatureInteropProfiles.resolve(identity.canonicalForm())
                .orElseThrow(() -> new IllegalStateException("Managed key proof verification profile unavailable"));
        byte[] nativeSpki = new BcX509PublicKeyAdapter(authority.bindings()).unwrap(spki);
        // Parse through the same provider-neutral PKIX boundary as certificate
        // verification. The default JCA ML-DSA factory may return a JDK key that
        // cannot be used by the installed ZeroEcho verification context.
        PublicKey key = Pkix.publicKeyFromSubjectPublicKeyInfo(nativeSpki);
        verify(profile, key, challenge, signature.bytes());
    }

    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    private static void verify(SignatureInteropProfile profile, PublicKey key, byte[] challenge, byte[] signature)
            throws IOException, GeneralSecurityException {
        byte[] expected;
        try { expected = profile.externalToInternalSignature(signature); }
        catch (IllegalArgumentException malformed) { throw invalid(); }
        try (SignatureContext verifier = new ZeroEchoSession().createContext(profile.contextAlgorithmId(),
                    KeyUsage.VERIFY, key, profile.contextSpec())) {
            verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
            verifier.setExpectedTag(expected);
            try (InputStream input = verifier.wrap(new ByteArrayInputStream(challenge))) {
                input.transferTo(OutputStream.nullOutputStream());
            } catch (IOException failure) {
                if (failure.getCause() instanceof VerificationException mismatch
                        && (mismatch.getCause() == null || mismatch.getCause() instanceof SignatureException)) {
                    // Only final verification wraps SignatureException in VerificationException;
                    // update failures have a direct SignatureException cause and remain retryable.
                    // Do not retain a mismatch exception: its diagnostic may contain signature bytes.
                    throw invalid();
                }
                throw failure;
            }
        } finally {
            Arrays.fill(expected, (byte) 0);
            Arrays.fill(signature, (byte) 0);
        }
    }

    private static DomainContinuationPublisher.PostconditionFailure invalid() {
        return new DomainContinuationPublisher.PostconditionFailure("MANAGED_KEY_PROOF_SIGNATURE_INVALID");
    }
}
