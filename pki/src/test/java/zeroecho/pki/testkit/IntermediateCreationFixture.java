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

package zeroecho.pki.testkit;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spi.AlgorithmExecutionCapability.Direction;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IntermediateCreateCommand;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.impl.core.IntermediateSigningPreparation;
import zeroecho.pki.impl.core.ManagedKeyProofPreparation;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.impl.core.continuation.SigningOuterTerminalDriver;
import zeroecho.pki.impl.framework.x509.ImmutableX509AlgorithmBindingRegistry;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.Pkix;

/** Real parent credential and internal proof fixture; execution remains test-controlled. */
public final class IntermediateCreationFixture {
    public static final Instant NOW = Instant.parse("2026-09-21T12:00:00Z");
    public static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    public static final Duration TTL = Duration.ofMinutes(1);
    public static final String ALGORITHM = BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm();
    public static final PkiId CA = new PkiId("parent-authority");
    public static final KeyRef PARENT_KEY = new KeyRef("parent-key");
    public static final KeyRef CHILD_KEY = new KeyRef("child-key");
    public static final KeyRef ROTATED_KEY = new KeyRef("rotated-child-key");
    public static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "actor"), new Purpose("CREATE"),
            Optional.empty(), Optional.empty());
    public final KeyPair parentKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    public final KeyPair childKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    public final KeyPair rotatedKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    public final Provider provider = new Provider();
    public final X509AuthoritySnapshot signing = PkiTestRuntime.signingAuthority(provider);
    public final BcX509VerificationExecutor verifier = new BcX509VerificationExecutor();
    public final X509AuthoritySnapshot verification = X509AuthoritySnapshot.compose(List.of(), List.of(verifier),
            List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID, Direction.VERIFY, verifier)),
            (suite, direction) -> direction == Direction.VERIFY);
    public final ImmutableX509AlgorithmBindingRegistry bindings = ImmutableX509AlgorithmBindingRegistry.create(StandardX509Bindings.descriptors());

    public IntermediateCreationFixture() throws Exception { }

    public void initialize(PkiStore store, int pathLength) throws Exception {
        for (BuiltInCertificateProfileTemplate template : BuiltInCertificateProfileCatalog.load(getClass().getClassLoader())) {
            CertificateProfileDefinition definition = template.definition();
            CertificateProfileRef reference = new CertificateProfileRef(definition.profileId(), definition.profileVersion(), template.canonicalSha256());
            store.importProfileVersion(new ImportedCertificateProfileVersion(reference, CertificateProfileDefinition.SCHEMA_VERSION,
                    definition, template.canonicalJson(), NOW));
            store.activateProfile(definition.profileId(), definition.profileVersion());
        }
        CertificateProfileRef profile = store.requireActiveProfile("root-ca").reference();
        byte[] tbs = Pkix.certificateBuilder().serialNumber(BigInteger.ONE).issuer(new X500Principal("CN=Parent"))
                .subject(new X500Principal("CN=Parent")).publicKeyInfo(parentKey.getPublic().getEncoded())
                .validity(NOW.minusSeconds(3600), NOW.plus(Duration.ofDays(365))).basicConstraints(BasicConstraints.ca(pathLength), true)
                .keyUsage(Set.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN), true)
                .buildTbs(Pkix.subjectPublicKeyAlgorithm(parentKey.getPublic().getEncoded()));
        byte[] der = Pkix.assembleCertificateOrCrl(tbs, signature(tbs, PARENT_KEY).bytes(), false);
        PkiId credentialId = new PkiId("x509:" + hash(der));
        PkiId generation = IssuerGeneration.idFor(CA, credentialId);
        IssuerChainPath path = IssuerChainPath.create(CA, generation, List.of(credentialId));
        store.putCredential(new Credential(credentialId, new FormatId("x509"), new IssuerRef(CA, generation, path.pathId()),
                new SubjectRef("CN=Parent"), new Validity(NOW.minusSeconds(3600), NOW.plus(Duration.ofDays(365))), "1",
                new PkiId("spki:" + hash(parentKey.getPublic().getEncoded())), new CaProfileBinding(profile), CredentialStatus.ISSUED,
                PkiTestRuntime.stageCredential(store, der), new SimpleAttributeSet()));
        String commitment = java.util.HexFormat.of().formatHex(profile.canonicalSha256());
        store.putIssuerGeneration(new IssuerGeneration(generation, CA, credentialId, PARENT_KEY, IssuerGenerationState.ACTIVE,
                commitment, commitment));
        store.putIssuerChainPath(path);
        store.putCa(new CaRecord(CA, CaKind.ROOT, CaState.ACTIVE, PARENT_KEY, new SubjectRef("CN=Parent"),
                List.of(generation), generation, path.pathId()));
    }

    public SigningSubmissionId submission(PkiStore store) {
        return SigningSubmissionId.create(store.signingNamespace() + "." + provider.id(), NOW, new SecureRandom());
    }
    public IntermediateSigningPreparation preparer(PkiStore store) {
        return new IntermediateSigningPreparation(store, CLOCK, provider, signing, bindings, ALGORITHM,
                ManagedKeyProofCommand.MAX_CHALLENGE_BYTES, proofPreparation(store));
    }
    public ManagedKeyProofPreparation proofPreparation(PkiStore store) {
        return new ManagedKeyProofPreparation(store, provider, signing, verification, verifier,
                ALGORITHM, new SecureRandom(), ManagedKeyProofCommand.MAX_CHALLENGE_BYTES);
    }
    public IntermediateCreateCommand command(String subject) {
        return new IntermediateCreateCommand(new FormatId("x509"), CA, new SubjectRef(subject), "intermediate-ca",
                CHILD_KEY, new SimpleAttributeSet());
    }

    /** Adds a real parent-to-anchor chain for an internally proved child. */
    public IntermediateCreateCommand intermediateParent(PkiStore store, int pathLength, boolean selfIssued) throws Exception {
        PkiId middle = new PkiId("middle-authority");
        KeyRef middleKey = new KeyRef("middle-key");
        KeyPair middlePair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String subject = selfIssued ? "CN=Parent" : "CN=Middle";
        CaRecord root = store.getCa(CA).orElseThrow();
        IssuerChainPath rootPath = store.getIssuerChainPath(root.issuanceChainPathId()).orElseThrow();
        byte[] tbs = Pkix.certificateBuilder().serialNumber(BigInteger.TWO).issuer(new X500Principal("CN=Parent"))
                .subject(new X500Principal(subject)).publicKeyInfo(middlePair.getPublic().getEncoded())
                .validity(NOW.minusSeconds(3600), NOW.plus(Duration.ofDays(180))).basicConstraints(BasicConstraints.ca(pathLength), true)
                .keyUsage(Set.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN), true)
                .buildTbs(Pkix.subjectPublicKeyAlgorithm(parentKey.getPublic().getEncoded()));
        byte[] der = Pkix.assembleCertificateOrCrl(tbs, signature(tbs, PARENT_KEY).bytes(), false);
        PkiId credentialId = new PkiId("x509:" + hash(der));
        PkiId generation = IssuerGeneration.idFor(middle, credentialId);
        IssuerChainPath path = IssuerChainPath.create(middle, generation, List.of(credentialId, rootPath.orderedCredentialIds().getFirst()));
        CertificateProfileRef profile = store.requireActiveProfile("intermediate-ca").reference();
        store.putCredential(new Credential(credentialId, new FormatId("x509"),
                new IssuerRef(CA, root.currentIssuanceIssuerId(), rootPath.pathId()), new SubjectRef(subject),
                new Validity(NOW.minusSeconds(3600), NOW.plus(Duration.ofDays(180))), "2",
                new PkiId("spki:" + hash(middlePair.getPublic().getEncoded())), new CaProfileBinding(profile), CredentialStatus.ISSUED,
                PkiTestRuntime.stageCredential(store, der), new SimpleAttributeSet()));
        String commitment = java.util.HexFormat.of().formatHex(profile.canonicalSha256());
        store.putIssuerGeneration(new IssuerGeneration(generation, middle, credentialId, middleKey, IssuerGenerationState.ACTIVE,
                commitment, commitment));
        store.putIssuerChainPath(path);
        store.putCa(new CaRecord(middle, CaKind.INTERMEDIATE, CaState.ACTIVE, middleKey, new SubjectRef(subject),
                List.of(generation), generation, path.pathId()));
        return new IntermediateCreateCommand(new FormatId("x509"), middle, new SubjectRef("CN=Grandchild"), "intermediate-ca",
                CHILD_KEY, new SimpleAttributeSet());
    }
    public void accept(PkiStore store, DomainSigningRequest request) {
        DomainContinuationTemplate template = request.domainTemplate();
        SignWorkflowStore.AcceptanceResult accepted = store.acceptSign(new SignWorkflowStore.AcceptanceCommand(request.operationId(), store.signingNamespace() + "." + provider.id(),
                provider.configurationCommitment(), request.accessContext(), request.keyRef(),
                new PkiId(DomainCommandEncoding.decode(template.command()).field(1)), ALGORITHM, Encoding.BINARY,
                NOW, NOW.plus(TTL), request.content(), Optional.of(new SignWorkflowStore.OuterCommand(template.kind(),
                        template.correlationId().orElseThrow(), template.command(), template.commandCommitment())),
                        SignWorkflowStore.Mode.NORMAL, request.proofStep()));
        if (accepted != SignWorkflowStore.AcceptanceResult.ACCEPTED) { throw new AssertionError("Expected one new acceptance: " + accepted); }
    }
    /** Retains the real proof signature for verification, without a child workflow. */
    public void checkpointProof(PkiStore store, PkiId operation) throws Exception {
        SignWorkflowStore.Workflow workflow = store.getSignWorkflow(operation).orElseThrow();
        SignWorkflowStore.CaSubjectProofStep proof = workflow.envelope().proofStep().orElseThrow();
        SignWorkflowStore.Workflow claimed = store.claimSignStep(operation, workflow.revision(), Duration.ofSeconds(10)).orElseThrow();
        store.checkpointCaProof(operation, claimed.revision(), claimed.fence(), new SignWorkflowStore.CaSubjectProofOutcome(
                SigningProvider.ObservationState.SUCCEEDED, SigningProvider.DetailCode.SIGNED, Optional.of(store.signingNow())),
                Optional.of(signature(PkiTestRuntime.readContent(store, proof.challenge()), proof.subjectKeyRef()))).orElseThrow();
    }
    /** Completes proof verification and final certificate signing, leaving publication to the caller. */
    public void signCertificate(PkiStore store, PkiId operation) throws Exception {
        SignWorkflowStore.Workflow workflow = store.getSignWorkflow(operation).orElseThrow();
        if (workflow.stage() == SignWorkflowStore.Stage.CA_PROOF) { checkpointProof(store, operation); }
        workflow = store.getSignWorkflow(operation).orElseThrow();
        if (workflow.stage() == SignWorkflowStore.Stage.CA_PROOF_VERIFYING) {
            SignWorkflowStore.Workflow verifierClaim = store.claimSignStep(operation, workflow.revision(), Duration.ofSeconds(10)).orElseThrow();
            new SigningOuterTerminalDriver(store, verification, verifier, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES).advance(verifierClaim);
        }
        workflow = store.getSignWorkflow(operation).orElseThrow();
        byte[] bytes = PkiTestRuntime.readContent(store, workflow.envelope().candidate());
        SignWorkflowStore.Workflow claimed = store.claimSignStep(operation, workflow.revision(), Duration.ofSeconds(10)).orElseThrow();
        if (store.transitionSign(operation, claimed.revision(), claimed.fence(), SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"),
                Optional.of(signature(bytes, workflow.envelope().keyRef())), Optional.of(store.signingNow())).isEmpty()) {
            throw new AssertionError("Test certificate completion was not committed");
        }
    }
    public void finish(PkiStore store, PkiId operation) throws Exception {
        signCertificate(store, operation);
        new SigningOuterTerminalDriver(store, verification, verifier, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES)
                .advance(store.getSignWorkflow(operation).orElseThrow());
    }
    public EncodedObject signature(byte[] input, KeyRef key) throws Exception {
        Signature engine = Signature.getInstance("Ed25519");
        engine.initSign((key.equals(PARENT_KEY) ? parentKey : key.equals(ROTATED_KEY) ? rotatedKey : childKey).getPrivate());
        engine.update(input);
        return new EncodedObject(Encoding.BINARY, engine.sign());
    }
    public static String hash(byte[] bytes) { return SigningProvider.ContentCommitment.sha256(bytes).sha256(); }

    public final class Provider implements SigningProvider, PublicKeyInfoSource {
        public int dispatches;
        public int lookups;
        @Override public String id() { return "intermediate-test"; }
        @Override public ConfigurationCommitment configurationCommitment() { return new ConfigurationCommitment(new byte[32]); }
        @Override public Set<String> supportedAlgorithms() { return Set.of(ALGORITHM); }
        @Override public SigningInputCapabilities inputCapabilities() { return new SigningInputCapabilities(4_000_000, Map.of()); }
        @Override public EncodedObject resolvePublicKeyInfo(KeyRef key) {
            lookups++;
            if (!key.equals(CHILD_KEY) && !key.equals(ROTATED_KEY)) { throw new AssertionError("Only a proven subject key may be exported"); }
            return new EncodedObject(Encoding.DER, (key.equals(ROTATED_KEY) ? rotatedKey : childKey).getPublic().getEncoded());
        }
        @Override public OperationObservation dispatch(SignRequest request, CallControl control) {
            dispatches++;
            throw new AssertionError("Preparation must not dispatch");
        }
        @Override public OperationObservation reconcile(PkiId operation, CallControl control) { throw new AssertionError("No reconcile"); }
        @Override public OperationObservation cancel(PkiId operation, long fence, CancellationReason reason, CallControl control) {
            throw new AssertionError("No provider cancellation");
        }
        @Override public void close() { }
    }
}
