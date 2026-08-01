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

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.core.spi.AlgorithmExecutionCapabilityProvider;
import zeroecho.pki.api.CaService;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.StatusObjectService;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.impl.audit.InMemoryAuditSink;
import zeroecho.pki.impl.core.DefaultCaService;
import zeroecho.pki.impl.core.DefaultCertificationRequestService;
import zeroecho.pki.impl.core.DefaultIssuanceService;
import zeroecho.pki.impl.core.DefaultProfileService;
import zeroecho.pki.impl.core.DefaultRevocationService;
import zeroecho.pki.impl.core.DefaultStatusObjectService;
import zeroecho.pki.impl.core.StoreBackedEffectiveCredentialStatusResolver;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialIssuerBackend;
import zeroecho.pki.impl.framework.x509.bc.BcX509StatusObjectGenerator;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProofOfPossessionVerifier;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.framework.CredentialIssuerBackend;
import zeroecho.pki.spi.framework.ProofOfPossessionVerifier;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.StagedContentStore;

/**
 * Test-only PKI runtime wiring helper.
 *
 * <p>
 * This class centralizes construction of PKI services for tests so that
 * individual tests do not need to reference internal framework adapters
 * directly.
 * </p>
 */
public final class PkiTestRuntime implements AutoCloseable {

    /**
     * Stages one small test payload through the production streaming boundary.
     *
     * @param bus owning signing bus
     * @param payload small test payload
     * @return durable operation-content reference
     * @throws IOException if staging fails
     */
    public static DurableContentReference stage(PkiSigningBus bus, EncodedObject payload) throws IOException {
        try (ContentSink sink = bus.beginSigningContent(payload.encoding());
                OutputStream output = sink.outputStream()) {
            output.write(payload.bytes());
            return sink.complete();
        }
    }

    /**
     * Materializes one test fixture from runtime-owned staged content.
     *
     * @param bus owning signing bus
     * @param reference content reference
     * @return fixture bytes
     * @throws IOException if reading fails
     */
    public static byte[] readContent(PkiSigningBus bus, DurableContentReference reference) throws IOException {
        try (zeroecho.core.io.RepeatableContent content = bus.openContent(reference);
                java.io.InputStream input = content.openStream()) {
            return input.readAllBytes();
        }
    }

    /**
     * Stages one small credential fixture in the supplied test store.
     *
     * @param store owning test store
     * @param encoded encoded fixture bytes
     * @return durable credential-content reference
     * @throws IOException if staging fails
     */
    public static DurableContentReference stageCredential(PkiStore store, byte[] encoded) throws IOException {
        try (ContentSink sink = store.stagedContent().beginContent(Encoding.DER, DurableContentReference.Lifecycle.PERSISTED);
                OutputStream output = sink.outputStream()) {
            output.write(encoded);
            return sink.complete();
        }
    }

    /**
     * Creates payload-free metadata for tests that exercise value semantics only.
     *
     * <p>
     * The returned reference is intentionally not resolvable. Tests that read
     * content must stage it through an owning store instead.
     * </p>
     *
     * @param encoding fixture encoding
     * @param bytes fixture bytes used only to derive immutable metadata
     * @return non-resolvable fixture reference
     */
    public static DurableContentReference fixtureReference(StagedContentStore store, Encoding encoding, byte[] bytes)
            throws IOException {
        try (ContentSink sink = store.beginContent(encoding, DurableContentReference.Lifecycle.PERSISTED);
                OutputStream output = sink.outputStream()) {
            output.write(bytes);
            return sink.complete();
        }
    }

    /**
     * Creates an explicitly untrusted reference implementation for hostile tests.
     *
     * @param source source metadata
     * @param encoding substituted encoding
     * @return non-store-issued reference that an owning store must reject
     */
    public static DurableContentReference untrustedReference(DurableContentReference source, Encoding encoding) {
        return new UntrustedReference(source.storeId(), source.contentId(), encoding, source.length(), source.sha256(),
                source.lifecycle());
    }

    /**
     * Materializes one small fixture from store-owned content.
     *
     * @param store owning test store
     * @param reference content reference
     * @return fixture bytes
     * @throws IOException if reading fails
     */
    public static byte[] readContent(PkiStore store, DurableContentReference reference) throws IOException {
        try (zeroecho.core.io.RepeatableContent content = store.stagedContent().openContent(reference);
                java.io.InputStream input = content.openStream()) {
            return input.readAllBytes();
        }
    }

    public DurableContentReference stageCredential(byte[] encoded) throws IOException {
        return stageCredential(store, encoded);
    }

    public byte[] credentialBytes(zeroecho.pki.api.credential.Credential credential) throws IOException {
        return readContent(store, credential.content());
    }

    public Credential caCredential(zeroecho.pki.api.ca.CaRecord ca, int index) {
        PkiId credentialId = ca.credentialIds().get(index);
        return store.getCredential(credentialId).orElseThrow();
    }

    private record UntrustedReference(String storeId, String contentId, Encoding encoding, long length, String sha256,
            DurableContentReference.Lifecycle lifecycle) implements DurableContentReference {
    }

    private final FilesystemPkiStore store;
    private final PkiSigningBus signingBus;
    private final SignatureWorkflow signatureWorkflow;
    private final InMemoryAuditSink auditSink;

    private final CredentialFramework framework;
    private final CredentialIssuerBackend issuerBackend;
    private final EffectiveCredentialStatusResolver statusResolver;
    private final ProfileService profileService;

    private final CaService caService;
    private final CertificationRequestService certificationRequestService;
    private final IssuanceService issuanceService;
    private final RevocationService revocationService;
    private final StatusObjectService statusObjectService;

    private final Map<String, PublicKey> publicKeysByKeyRef;
    private Runnable publicKeyResolveHook;
    private boolean caProfilesProvisioned;

    private PkiTestRuntime(FilesystemPkiStore store, PkiSigningBus signingBus, SignatureWorkflow signatureWorkflow,
            CredentialFramework framework, CredentialIssuerBackend issuerBackend,
            Map<String, PublicKey> publicKeysByKeyRef, Duration signingTtl) {
        this.store = store;
        this.signingBus = signingBus;
        this.signatureWorkflow = signatureWorkflow;
        this.auditSink = new InMemoryAuditSink();
        this.framework = framework;
        this.issuerBackend = issuerBackend;
        Clock clock = Clock.systemUTC();
        this.statusResolver = new StoreBackedEffectiveCredentialStatusResolver(store, clock);
        this.profileService = new DefaultProfileService(store, clock, auditSink);
        this.publicKeysByKeyRef = publicKeysByKeyRef;
        this.publicKeyResolveHook = () -> {
        };

        this.certificationRequestService = new DefaultCertificationRequestService(store, framework);
        importAndActivate(H7ProfileDocuments.defaultProfile());
        this.issuanceService = new DefaultIssuanceService(store, framework, issuerBackend, auditSink, statusResolver,
                profileService, clock);
        this.revocationService = new DefaultRevocationService(store, clock, auditSink);
        this.statusObjectService = new DefaultStatusObjectService(store, framework, auditSink, statusResolver,
                signingBus.authority());

        this.caService = new DefaultCaService(store, framework, issuerBackend, this::resolvePublicKeyInfo, signingBus,
                auditSink, statusResolver, profileService, clock, "SHA256withRSA", signingTtl);
    }

    /**
     * Creates a test runtime.
     *
     * @param rootDir  working root for the filesystem store
     * @param busFile  durable bus line store file path
     * @param keyPairs key material indexed by KeyRef value
     * @return runtime
     */
    public static PkiTestRuntime create(Path rootDir, Path busFile, Map<KeyRef, KeyPair> keyPairs) {
        Map<KeyRef, PublicKey> publicKeys = new HashMap<>();
        for (Map.Entry<KeyRef, KeyPair> entry : keyPairs.entrySet()) {
            publicKeys.put(entry.getKey(), entry.getValue().getPublic());
        }
        return create(rootDir, busFile, keyPairs, publicKeys, Optional.empty());
    }

    /**
     * Creates a test runtime with independently controlled signing keys, resolved
     * public keys, and proof verifier.
     *
     * @param rootDir       working root for the filesystem store
     * @param busFile       durable bus line store file path
     * @param signingKeys   signing workflow key pairs indexed by key reference
     * @param resolvedKeys  public keys returned by managed-key resolution
     * @param proofVerifier proof verifier used by the credential framework
     * @return runtime
     */
    public static PkiTestRuntime create(Path rootDir, Path busFile, Map<KeyRef, KeyPair> signingKeys,
            Map<KeyRef, PublicKey> resolvedKeys, ProofOfPossessionVerifier proofVerifier) {
        return create(rootDir, busFile, signingKeys, resolvedKeys, Optional.of(proofVerifier));
    }

    private static PkiTestRuntime create(Path rootDir, Path busFile, Map<KeyRef, KeyPair> keyPairs,
            Map<KeyRef, PublicKey> resolvedKeys, Optional<ProofOfPossessionVerifier> proofVerifier) {
        Objects.requireNonNull(rootDir, "rootDir");
        Objects.requireNonNull(busFile, "busFile");
        Objects.requireNonNull(keyPairs, "keyPairs");
        Objects.requireNonNull(resolvedKeys, "resolvedKeys");
        Objects.requireNonNull(proofVerifier, "proofVerifier");

        FsPkiStoreOptions opts = FsPkiStoreOptions.defaults();

        Path storeRoot = rootDir.resolve("store");
        FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, opts);

        Map<String, KeyPair> byRef = new HashMap<>();
        for (Map.Entry<KeyRef, KeyPair> e : keyPairs.entrySet()) {
            byRef.put(e.getKey().value(), e.getValue());
        }
        Map<String, PublicKey> publicByRef = new HashMap<>();
        for (Map.Entry<KeyRef, PublicKey> entry : resolvedKeys.entrySet()) {
            publicByRef.put(entry.getKey().value(), entry.getValue());
        }

        SignatureWorkflow signer = new InMemorySignatureWorkflow(byRef);
        BcX509VerificationExecutor verificationExecutor = new BcX509VerificationExecutor();
        X509AuthoritySnapshot authority = signingAuthority(signer, List.of(verificationExecutor),
                List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                        AlgorithmExecutionCapability.Direction.VERIFY, verificationExecutor)));
        PkiSigningBus signingBus = new PkiSigningBus(store, signer, busFile, authority);

        BcX509CredentialIssuerBackend issuerBackend = new BcX509CredentialIssuerBackend(signingBus, "SHA256withRSA",
                Duration.ofSeconds(2));
        BcX509StatusObjectGenerator statusGen = new BcX509StatusObjectGenerator(signingBus, "SHA256withRSA",
                Duration.ofSeconds(2));
        BcX509CredentialFramework baseFramework = new BcX509CredentialFramework(authority, verificationExecutor);
        ProofOfPossessionVerifier effectiveVerifier = proofVerifier
                .orElseGet(() -> new BcX509ProofOfPossessionVerifier(authority, verificationExecutor));
        CredentialFramework framework = baseFramework.wired(statusGen, effectiveVerifier);

        return new PkiTestRuntime(store, signingBus, signer, framework, issuerBackend, publicByRef,
                Duration.ofSeconds(2));
    }

    public static PkiTestRuntime createWithPendingSigner(Path rootDir, Path busFile, Map<KeyRef, KeyPair> keyPairs,
            Duration signingTtl) {
        Objects.requireNonNull(signingTtl, "signingTtl");
        FsPkiStoreOptions opts = FsPkiStoreOptions.defaults();
        FilesystemPkiStore store = new FilesystemPkiStore(rootDir.resolve("store"), opts);
        Map<String, KeyPair> byRef = new HashMap<>();
        Map<String, PublicKey> publicByRef = new HashMap<>();
        for (Map.Entry<KeyRef, KeyPair> entry : keyPairs.entrySet()) {
            byRef.put(entry.getKey().value(), entry.getValue());
            publicByRef.put(entry.getKey().value(), entry.getValue().getPublic());
        }
        SignatureWorkflow signer = new InMemorySignatureWorkflow(byRef, false);
        BcX509VerificationExecutor verificationExecutor = new BcX509VerificationExecutor();
        X509AuthoritySnapshot authority = signingAuthority(signer, List.of(verificationExecutor),
                List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                        AlgorithmExecutionCapability.Direction.VERIFY, verificationExecutor)));
        PkiSigningBus signingBus = new PkiSigningBus(store, signer, busFile, authority);
        BcX509CredentialIssuerBackend issuerBackend = new BcX509CredentialIssuerBackend(signingBus, "SHA256withRSA",
                signingTtl);
        BcX509StatusObjectGenerator statusGen = new BcX509StatusObjectGenerator(signingBus, "SHA256withRSA",
                signingTtl);
        CredentialFramework framework = new BcX509CredentialFramework(authority, verificationExecutor).wired(statusGen,
                new BcX509ProofOfPossessionVerifier(authority, verificationExecutor));
        return new PkiTestRuntime(store, signingBus, signer, framework, issuerBackend, publicByRef, signingTtl);
    }

    /**
     * Composes a test authority that owns the exact supplied signing workflow.
     *
     * <p>
     * This test helper makes runtime composition explicit. The returned snapshot
     * binds only the signing identities declared by {@code workflow}, contains no
     * key material, and cannot authorize a different workflow instance.
     * </p>
     *
     * @param workflow exact test signing workflow
     * @return immutable authority snapshot owning {@code workflow}
     * @throws NullPointerException if {@code workflow} or its supported-algorithm
     *                              set is {@code null}
     */
    public static X509AuthoritySnapshot signingAuthority(SignatureWorkflow workflow) {
        return signingAuthority(workflow, List.of(), List.of());
    }

    private static X509AuthoritySnapshot signingAuthority(SignatureWorkflow workflow,
            List<AlgorithmExecutionCapabilityProvider> additionalCapabilities,
            List<X509AuthoritySnapshot.ExecutorBinding> additionalExecutors) {
        Objects.requireNonNull(workflow, "workflow");
        Objects.requireNonNull(additionalCapabilities, "additionalCapabilities");
        Objects.requireNonNull(additionalExecutors, "additionalExecutors");
        Set<String> supported = Set.copyOf(
                Objects.requireNonNull(workflow.supportedAlgorithms(), "workflow.supportedAlgorithms"));
        Set<AlgorithmIdentity> exact = BootstrapAlgorithmIdentities.catalog().identities().stream()
                .filter(identity -> identity.kind() == AlgorithmIdentity.Kind.SIGNATURE)
                .filter(identity -> supported.contains(identity.canonicalForm())
                        || BootstrapAlgorithmIdentities.compatibilityAliases().entrySet().stream()
                                .anyMatch(entry -> entry.getValue().equals(identity)
                                        && supported.contains(entry.getKey())))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        AlgorithmExecutionCapability capability = new AlgorithmExecutionCapability() {
            @Override
            public String implementationId() {
                return workflowImplementationId(workflow);
            }

            @Override
            public String domainFingerprint() {
                return "test-workflow-v1:" + workflow.id() + ":" + exact.stream()
                        .map(AlgorithmIdentity::canonicalForm).sorted().reduce("", (left, right) -> left + right);
            }

            @Override
            public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                return direction == Direction.SIGN && exact.contains(identity) && identity.equals(suite.signature());
            }
        };
        AlgorithmExecutionCapabilityProvider provider = () -> List.of(capability);
        X509AlgorithmResolver.Policy policy = new X509AlgorithmResolver.Policy() {
            @Override
            public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) {
                return true;
            }

            @Override
            public String semanticFingerprint() {
                return "pki-test-runtime-policy-v1:allow-authorized-capability";
            }
        };
        List<AlgorithmExecutionCapabilityProvider> providers = new ArrayList<>();
        providers.add(provider);
        providers.addAll(additionalCapabilities);
        List<X509AuthoritySnapshot.ExecutorBinding> executors = new ArrayList<>();
        executors.add(X509AuthoritySnapshot.bindExecutor(capability.implementationId(),
                AlgorithmExecutionCapability.Direction.SIGN, workflow));
        executors.addAll(additionalExecutors);
        return X509AuthoritySnapshot.compose(List.of(), providers, executors, policy);
    }

    private static String workflowImplementationId(SignatureWorkflow workflow) {
        return "workflow." + workflow.id();
    }

    private EncodedObject resolvePublicKeyInfo(KeyRef keyRef) {
        publicKeyResolveHook.run();
        PublicKey publicKey = publicKeysByKeyRef.get(keyRef.value());
        if (publicKey == null) {
            throw new IllegalArgumentException("Unknown keyRef");
        }
        return new EncodedObject(Encoding.DER, publicKey.getEncoded());
    }

    public PkiStore store() {
        return store;
    }

    public PkiSigningBus signingBus() {
        return signingBus;
    }

    public SignatureWorkflow signatureWorkflow() {
        return signatureWorkflow;
    }

    public int submittedSignCount() {
        return ((InMemorySignatureWorkflow) signatureWorkflow).submittedSignCount();
    }

    public void replaceManagedKey(KeyRef keyRef, KeyPair keyPair) {
        publicKeysByKeyRef.put(keyRef.value(), keyPair.getPublic());
        ((InMemorySignatureWorkflow) signatureWorkflow).putKeyPair(keyRef, keyPair);
    }

    /**
     * Replaces only the public key returned by the managed-key resolver.
     *
     * @param keyRef    managed key reference
     * @param publicKey replacement resolved public key
     */
    public void replaceResolvedKey(KeyRef keyRef, PublicKey publicKey) {
        publicKeysByKeyRef.put(keyRef.value(), Objects.requireNonNull(publicKey, "publicKey"));
    }

    public void onPublicKeyResolve(Runnable hook) {
        this.publicKeyResolveHook = Objects.requireNonNull(hook, "hook");
    }

    public boolean hasRunningSignatureOperations() {
        return ((InMemorySignatureWorkflow) signatureWorkflow).hasRunningOperations();
    }

    /**
     * Returns the deterministic audit sink shared by the test runtime services.
     *
     * @return in-memory audit sink
     */
    public InMemoryAuditSink auditSink() {
        return auditSink;
    }

    public CredentialFramework framework() {
        return framework;
    }

    public CredentialIssuerBackend issuerBackend() {
        return issuerBackend;
    }

    public EffectiveCredentialStatusResolver statusResolver() {
        return statusResolver;
    }

    /** @return production profile lifecycle service */
    public ProfileService profileService() {
        return profileService;
    }

    /**
     * Imports and activates one strict JSON test document through production APIs.
     */
    public void importAndActivate(byte[] document) {
        zeroecho.pki.api.profile.CertificateProfileRef reference = profileService.importProfile(document);
        profileService.activateProfile(reference.profileId(), reference.profileVersion());
    }

    public CaService caService() {
        provisionCaProfiles();
        return caService;
    }

    public CaService caService(CredentialFramework credentialFramework) {
        provisionCaProfiles();
        return new DefaultCaService(store, Objects.requireNonNull(credentialFramework, "credentialFramework"),
                issuerBackend, this::resolvePublicKeyInfo, signingBus, auditSink, statusResolver, profileService,
                Clock.systemUTC(), "SHA256withRSA", Duration.ofSeconds(2));
    }

    public CaService caService(CredentialIssuerBackend backend) {
        provisionCaProfiles();
        return new DefaultCaService(store, framework, Objects.requireNonNull(backend, "backend"),
                this::resolvePublicKeyInfo, signingBus, auditSink, statusResolver, profileService, Clock.systemUTC(),
                "SHA256withRSA", Duration.ofSeconds(2));
    }

    public CaService caService(CredentialIssuerBackend backend, EffectiveCredentialStatusResolver resolver) {
        provisionCaProfiles();
        return new DefaultCaService(store, framework, Objects.requireNonNull(backend, "backend"),
                this::resolvePublicKeyInfo, signingBus, auditSink, Objects.requireNonNull(resolver, "resolver"),
                profileService, Clock.systemUTC(), "SHA256withRSA", Duration.ofSeconds(2));
    }

    public CaService caService(ProfileService profiles) {
        provisionCaProfiles();
        return new DefaultCaService(store, framework, issuerBackend, this::resolvePublicKeyInfo, signingBus, auditSink,
                statusResolver, Objects.requireNonNull(profiles, "profiles"), Clock.systemUTC(), "SHA256withRSA",
                Duration.ofSeconds(2));
    }

    private synchronized void provisionCaProfiles() {
        if (caProfilesProvisioned) {
            return;
        }
        BuiltInCertificateProfileCatalog.load(PkiTestRuntime.class.getClassLoader()).stream()
                .filter(template -> template.definition().profileId().equals("root-ca")
                        || template.definition().profileId().equals("intermediate-ca"))
                .forEach(template -> {
                    zeroecho.pki.api.profile.CertificateProfileRef reference = profileService.importBuiltIn(template);
                    profileService.activateProfile(reference.profileId(), reference.profileVersion());
                });
        caProfilesProvisioned = true;
    }

    public CertificationRequestService certificationRequestService() {
        return certificationRequestService;
    }

    public IssuanceService issuanceService() {
        return issuanceService;
    }

    public IssuanceService issuanceService(CredentialIssuerBackend backend,
            EffectiveCredentialStatusResolver resolver) {
        return new DefaultIssuanceService(store, framework, Objects.requireNonNull(backend, "backend"), auditSink,
                Objects.requireNonNull(resolver, "resolver"), profileService, Clock.systemUTC());
    }

    public RevocationService revocationService() {
        return revocationService;
    }

    public StatusObjectService statusObjectService() {
        return statusObjectService;
    }

    public StatusObjectService statusObjectService(EffectiveCredentialStatusResolver resolver) {
        return new DefaultStatusObjectService(store, framework, auditSink,
                Objects.requireNonNull(resolver, "resolver"), signingBus.authority());
    }

    /**
     * Returns a new empty attribute set suitable for test commands.
     *
     * @return empty attributes
     */
    public SimpleAttributeSet emptyAttributes() {
        return new SimpleAttributeSet();
    }

    @Override
    public void close() throws IOException {
        try {
            signingBus.close();
        } finally {
            try {
                signatureWorkflow.close();
            } finally {
                store.close();
            }
        }
    }
}
