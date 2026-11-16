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

package zeroecho.pki.impl.core;

import java.nio.file.*;
import java.math.BigInteger;
import java.lang.reflect.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.*;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.audit.*;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.ca.*;
import zeroecho.pki.api.credential.*;
import zeroecho.pki.api.issuance.*;
import zeroecho.pki.api.profile.*;
import zeroecho.pki.impl.audit.InMemoryAuditSink;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.continuation.*;
import zeroecho.pki.impl.core.signing.*;
import zeroecho.pki.impl.fs.*;
import zeroecho.pki.spi.store.*;
import zeroecho.pki.testkit.*;
import zeroecho.pkix.Pkix;

/**
 * Actual-store regressions proving lifecycle input validation cannot stage or sign.
 */
class PureInputValidationTest {
    /**
     * Validates root and intermediate lifecycle without side effects.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void validatesRootAndIntermediateLifecycleWithoutSideEffects(@TempDir Path root) throws Exception { caLifecycle(root); }
    /**
     * Validates leaf issuance and lifecycle without side effects.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void validatesLeafIssuanceAndLifecycleWithoutSideEffects(@TempDir Path root) throws Exception { leafLifecycle(root); }

    /**
     * Wraps a test store with mutation-rejecting proxies while preserving delegated read access.
     *
     * @param store borrowed test store used for fixture state, staging, and persisted assertions
     * @return borrowed-store view that raises AssertionError on a forbidden mutation
     */
    static PkiStore readOnly(PkiStore store) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[]{PkiStore.class}, (proxy, method, args) -> {
            if (method.getName().equals("stagedContent")) {
                return Proxy.newProxyInstance(StagedContentStore.class.getClassLoader(), new Class<?>[]{StagedContentStore.class}, (content, call, values) -> {
                    if (!call.getName().equals("openContent")) throw new AssertionError("Validation reached content mutation: " + call.getName());
                    try { return call.invoke(store.stagedContent(), values); } catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
            }
            if (method.getName().matches("(put|replace|activate|accept|transition|retire|revoke|begin).*|signingNow"))
                throw new AssertionError("Validation reached mutation/allocation boundary: " + method.getName());
            try { return method.invoke(store, args); } catch (InvocationTargetException failure) { throw failure.getCause(); }
        });
    }
    /**
     * Requires a fixture invariant without relying on enabled JVM assertions.
     *
     * @param condition condition that must hold for the fixture assertion to succeed
     * @param message diagnostic attached to a failed fixture assertion
     * @throws AssertionError if the required condition is false
     */
    static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
    /**
     * Checked test operation used to assert input rejection without mutation.
     */
    interface Action {
        /**
         * Executes the checked test action supplied by an input-validation case.
         *
         * @throws Exception if fixture construction, execution, or cleanup fails
         */
        void run() throws Exception; }
    /**
     * Requires the supplied invalid-input action to throw a runtime exception.
     *
     * @param action checked operation that must reject the supplied invalid input
     * @throws Exception if fixture construction, execution, or cleanup fails
     * @throws AssertionError if the action returns normally instead of rejecting input
     */
    static void rejected(Action action) throws Exception {
        try { action.run(); throw new AssertionError("Invalid input accepted"); } catch (RuntimeException expected) { }
    }
    /**
     * Exercises pure authority validation while rejecting mutation and signing callbacks.
     *
     * @param directory temporary directory used by the lifecycle fixture
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    static void caLifecycle(Path directory) throws Exception {
        try (var store = new FilesystemPkiStore(directory.resolve("root"), FsPkiStoreOptions.defaults(), RootCreationFixture.CLOCK)) {
            var fixture = new RootCreationFixture(); fixture.initialize(store);
            var semantic = fixture.semantic(store);
            var operation = semantic.accept(semantic.prepareRootCreation(RootCreationFixture.ACCESS, fixture.command(), CancellationSignal.NONE)).receipt().operationId();
            var workflow = store.getSignWorkflow(operation).orElseThrow();
            var claimed = store.claimSignStep(operation, workflow.revision(), Duration.ofSeconds(10)).orElseThrow();
            store.transitionSign(operation, claimed.revision(), claimed.fence(), SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"),
                    Optional.of(fixture.signature(PkiTestRuntime.readContent(store, workflow.envelope().candidate()), workflow.envelope().keyRef())), Optional.of(store.signingNow()));
            new SigningOuterTerminalDriver(store, fixture.verification, fixture.verifier, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES)
                    .advance(store.getSignWorkflow(operation).orElseThrow());
            var ca = store.getCa(DomainCommandEncoding.rootAuthorityId(operation)).orElseThrow();
            int dispatches = fixture.provider.dispatches.get();
            var pure = fixture.preparer(readOnly(store));
            pure.validateExisting(RootCreationFixture.ACCESS, new CaRolloverCommand.Root(ca.caId(), Optional.empty(), new SimpleAttributeSet()), CancellationSignal.NONE);
            pure.validateExisting(RootCreationFixture.ACCESS, new CaKeyRotationCommand.Root(ca.caId(), RootCreationFixture.REPLACEMENT_KEY, new SimpleAttributeSet()), CancellationSignal.NONE);
            rejected(() -> pure.validateExisting(RootCreationFixture.ACCESS, new CaKeyRotationCommand.Root(ca.caId(), new KeyRef("missing"), new SimpleAttributeSet()), CancellationSignal.NONE));
            var semanticPure = fixture.semantic(readOnly(store));
            semanticPure.validateRootCreation(RootCreationFixture.ACCESS, fixture.command(), CancellationSignal.NONE);
            semanticPure.validateCaRollover(RootCreationFixture.ACCESS, new CaRolloverCommand.Root(ca.caId(), Optional.empty(), new SimpleAttributeSet()), CancellationSignal.NONE);
            semanticPure.validateCaKeyRotation(RootCreationFixture.ACCESS, new CaKeyRotationCommand.Root(ca.caId(), RootCreationFixture.REPLACEMENT_KEY, new SimpleAttributeSet()), CancellationSignal.NONE);
            check(fixture.provider.dispatches.get() == dispatches && store.listCas().size() == 1, "Root validation mutated state");
        }
        try (var store = new FilesystemPkiStore(directory.resolve("intermediate"), FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK)) {
            var fixture = new IntermediateIssuanceFixture(); fixture.initialize(store);
            var pure = fixture.preparer(readOnly(store), IntermediateCreationFixture.CLOCK);
            pure.validateExisting(IntermediateCreationFixture.ACCESS, fixture.command(), CancellationSignal.NONE);
            pure.validateExisting(IntermediateCreationFixture.ACCESS, new CaRolloverCommand.Intermediate(IntermediateIssuanceFixture.SUBJECT,
                    IntermediateCreationFixture.CA, IntermediateCreationFixture.CHILD_KEY, Optional.empty(), new SimpleAttributeSet()), CancellationSignal.NONE);
            pure.validateExisting(IntermediateCreationFixture.ACCESS, new CaKeyRotationCommand.Intermediate(IntermediateIssuanceFixture.SUBJECT,
                    IntermediateCreationFixture.CHILD_KEY, IntermediateCreationFixture.CA, new SimpleAttributeSet()), CancellationSignal.NONE);
            var bad = fixture.command();
            rejected(() -> pure.validateExisting(IntermediateCreationFixture.ACCESS, new IntermediateCertIssueCommand(bad.formatId(), bad.issuerCaId(),
                    bad.subjectCaId(), "missing", bad.keyRef(), bad.requestedValidity(), bad.attributes()), CancellationSignal.NONE));
            var semanticPure = fixture.semantic(readOnly(store), IntermediateCreationFixture.CLOCK);
            semanticPure.validateIntermediateCreation(IntermediateCreationFixture.ACCESS, fixture.base.command("CN=Additional Child"), CancellationSignal.NONE);
            semanticPure.validateIntermediateIssuance(IntermediateCreationFixture.ACCESS, fixture.command(), CancellationSignal.NONE);
            semanticPure.validateCaRollover(IntermediateCreationFixture.ACCESS, new CaRolloverCommand.Intermediate(IntermediateIssuanceFixture.SUBJECT,
                    IntermediateCreationFixture.CA, IntermediateCreationFixture.CHILD_KEY, Optional.empty(), new SimpleAttributeSet()), CancellationSignal.NONE);
            semanticPure.validateCaKeyRotation(IntermediateCreationFixture.ACCESS, new CaKeyRotationCommand.Intermediate(IntermediateIssuanceFixture.SUBJECT,
                    IntermediateCreationFixture.CHILD_KEY, IntermediateCreationFixture.CA, new SimpleAttributeSet()), CancellationSignal.NONE);
            check(fixture.base.provider.dispatches == 0 && store.listCas().size() == 2, "Intermediate validation mutated state");
        }
    }
    private static final Instant NOW = Instant.parse("2026-09-20T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final PkiId CA = new PkiId("ca:test");
    private static final KeyRef KEY = new KeyRef("key:issuer");
    private static final String PROFILE = "h7-no-san-eku";
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "issuer"), new Purpose("ISSUE"), Optional.empty(), Optional.empty());
    private static FilesystemPkiStore leafFixture(Path root, KeyPair key) throws Exception {
        FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK);
        DefaultProfileService profiles = new DefaultProfileService(store, CLOCK, new InMemoryAuditSink());
        profiles.importProfile(H7ProfileDocuments.noSanOrEkuProfile());
        profiles.activateProfile(PROFILE, 1L);
        X500Name subject = new X500Name("CN=Issuer");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
                Date.from(NOW.minusSeconds(60)), Date.from(NOW.plusSeconds(800L * 86400)), subject, key.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        byte[] encoded = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded();
        PkiId credentialId = new PkiId("credential:issuer");
        PkiId rootIssuer = IssuerGeneration.idFor(CA, credentialId);
        Credential credential = new Credential(credentialId, new FormatId("x509"),
                new IssuerRef(CA, rootIssuer, IssuerChainPath.create(CA, rootIssuer, List.of(credentialId)).pathId()),
                new SubjectRef("CN=Issuer"), new Validity(NOW.minusSeconds(60), NOW.plusSeconds(800L * 86400)),
                "1", new PkiId("public:issuer"), new CaProfileBinding(new CertificateProfileRef("root", 1, new byte[32])),
                CredentialStatus.ISSUED, PkiTestRuntime.stageCredential(store, encoded), SimpleAttributeSet.builder().build());
        IssuerGeneration generation = new IssuerGeneration(IssuerGeneration.idFor(CA, credentialId), CA, credentialId,
                KEY, IssuerGenerationState.ACTIVE, "00".repeat(32), zeroecho.pki.testkit.IssuerBindingFixture.BINDING_SET_COMMITMENT);
        IssuerChainPath path = IssuerChainPath.create(CA, generation.issuerId(), List.of(credentialId));
        store.putCredential(credential);
        zeroecho.pki.testkit.IssuerBindingFixture.put(store, generation, zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256);
        store.putIssuerChainPath(path);
        store.putCa(new CaRecord(CA, CaKind.ROOT, CaState.ACTIVE, KEY, credential.subjectRef(), List.of(generation.issuerId()),
                generation.issuerId(), path.pathId()));
        return store;
    }

    /**
     * Exercises pure leaf issuance validation while rejecting mutation and signing callbacks.
     *
     * @param directory temporary directory used by the lifecycle fixture
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    static void leafLifecycle(Path directory) throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); var key = generator.generateKeyPair();
        try (var store = leafFixture(directory.resolve("leaf"), key)) {
            var csr = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Applicant"), key.getPublic())
                    .build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded();
            var issuer = store.getCa(CA).orElseThrow();
            var validity = new Validity(NOW.minusSeconds(60), NOW.plusSeconds(86400));
            var builder = new JcaX509v3CertificateBuilder(new X500Name("CN=Issuer"), BigInteger.TWO,
                    Date.from(validity.notBefore()), Date.from(validity.notAfter()), new X500Name("CN=Applicant"), key.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            byte[] der = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded();
            var id = new PkiId("x509:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(der)));
            store.putCredential(new Credential(id, new FormatId("x509"), new IssuerRef(CA, issuer.currentIssuanceIssuerId(), issuer.issuanceChainPathId()),
                    new SubjectRef("CN=Applicant"), validity, "2", new PkiId("spki:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key.getPublic().getEncoded()))), new EndEntityProfileBinding(store.getActiveProfileRef(PROFILE).orElseThrow()),
                    CredentialStatus.ISSUED, PkiTestRuntime.stageCredential(store, der), new SimpleAttributeSet()));
            var pure = PkiTestRuntime.endEntityPreparation(readOnly(store), CLOCK);
            pure.validate(ACCESS, new EndEntityIssuanceRequest(CA, csr, PROFILE, Optional.empty()), Optional.empty(), CancellationSignal.NONE);
            pure.validate(ACCESS, new EndEntityRenewalRequest(id, Optional.empty()), Optional.empty(), CancellationSignal.NONE);
            pure.validate(ACCESS, new EndEntityReplacementRequest(id, csr, PROFILE), Optional.empty(), CancellationSignal.NONE);
            pure.validate(ACCESS, new EndEntityReissueRequest(id), Optional.empty(), CancellationSignal.NONE);
            rejected(() -> pure.validate(ACCESS, new EndEntityIssuanceRequest(CA, new byte[]{5,0}, PROFILE, Optional.empty()), Optional.empty(), CancellationSignal.NONE));
            rejected(() -> pure.validate(ACCESS, new EndEntityReissueRequest(new PkiId("missing")), Optional.empty(), CancellationSignal.NONE));
            rejected(() -> pure.validate(ACCESS, new EndEntityIssuanceRequest(CA, csr, "missing", Optional.empty()), Optional.empty(), CancellationSignal.NONE));
            var semanticPure = leafSemantic(readOnly(store), pure, Long.MAX_VALUE);
            semanticPure.validateEndEntity(ACCESS, new EndEntityIssuanceRequest(CA, csr, PROFILE, Optional.empty()), Optional.empty(), CancellationSignal.NONE);
            semanticPure.validateRenewal(ACCESS, new EndEntityRenewalRequest(id, Optional.empty()), Optional.empty(), CancellationSignal.NONE);
            semanticPure.validateReplacement(ACCESS, new EndEntityReplacementRequest(id, csr, PROFILE), Optional.empty(), CancellationSignal.NONE);
            semanticPure.validateReissue(ACCESS, new EndEntityReissueRequest(id), Optional.empty(), CancellationSignal.NONE);
            rejected(() -> leafSemantic(readOnly(store), pure, 1).validateEndEntity(ACCESS,
                    new EndEntityIssuanceRequest(CA, csr, PROFILE, Optional.empty()), Optional.empty(), CancellationSignal.NONE));
            check(store.listCas().size() == 1 && store.getRevocation(id).isEmpty(), "Leaf validation mutated state");
        }
    }
    private static DefaultSemanticSigningService leafSemantic(PkiStore store, EndEntitySigningPreparation pure, long maximum) {
        String algorithm = BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm();
        var provider = (zeroecho.pki.spi.crypto.SigningProvider) Proxy.newProxyInstance(
                zeroecho.pki.spi.crypto.SigningProvider.class.getClassLoader(), new Class<?>[]{zeroecho.pki.spi.crypto.SigningProvider.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "id" -> "pure-leaf";
                    case "supportedAlgorithms" -> Set.of(algorithm);
                    case "inputCapabilities" -> new zeroecho.pki.spi.crypto.SigningInputCapabilities(maximum, Map.of());
                    case "validateSigningDomain", "close" -> null;
                    case "configurationCommitment" -> new zeroecho.pki.spi.crypto.SigningProvider.ConfigurationCommitment(new byte[32]);
                    default -> throw new AssertionError("Pure leaf validation reached provider operation: " + method.getName());
                });
        var signing = new DefaultSigningService(store, provider, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, Duration.ofMinutes(1),
                new SecureRandom(), () -> { }, (command, custody) -> { throw new AssertionError("Unexpected acceptance"); }, () -> { },
                (id, cancellation) -> { throw new AssertionError("Unexpected signing wait"); });
        return new DefaultSemanticSigningService(store, signing, pure);
    }

    /**
     * Runs the standalone fixture scenario using a newly created temporary directory.
     *
     * @param args unused console arguments; the fixture creates its own temporary root
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("zeroecho-pure-lifecycle-"); caLifecycle(root); leafLifecycle(root);
        System.out.println("PASS pure CA issuance/rollover/rotation and leaf issue/renew/replace/reissue; invalid references/CSR rejected; mutation/sign/allocation boundaries blocked");
    }
}
