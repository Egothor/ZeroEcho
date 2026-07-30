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
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.CaService;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.StatusObjectService;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.impl.core.DefaultCaService;
import zeroecho.pki.impl.core.DefaultCertificationRequestService;
import zeroecho.pki.impl.core.DefaultIssuanceService;
import zeroecho.pki.impl.core.DefaultRevocationService;
import zeroecho.pki.impl.core.DefaultStatusObjectService;
import zeroecho.pki.impl.core.StoreBackedEffectiveCredentialStatusResolver;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.audit.InMemoryAuditSink;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialIssuerBackend;
import zeroecho.pki.impl.framework.x509.bc.BcX509StatusObjectGenerator;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.framework.CredentialIssuerBackend;
import zeroecho.pki.spi.framework.ProofOfPossessionVerifier;
import zeroecho.pki.spi.store.PkiStore;

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

    private final FilesystemPkiStore store;
    private final PkiSigningBus signingBus;
    private final SignatureWorkflow signatureWorkflow;
    private final InMemoryAuditSink auditSink;

    private final CredentialFramework framework;
    private final CredentialIssuerBackend issuerBackend;
    private final EffectiveCredentialStatusResolver statusResolver;

    private final CaService caService;
    private final CertificationRequestService certificationRequestService;
    private final IssuanceService issuanceService;
    private final RevocationService revocationService;
    private final StatusObjectService statusObjectService;

    private final Map<String, PublicKey> publicKeysByKeyRef;
    private Runnable publicKeyResolveHook;

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
        this.publicKeysByKeyRef = publicKeysByKeyRef;
        this.publicKeyResolveHook = () -> {
        };

        this.certificationRequestService = new DefaultCertificationRequestService(store, framework);
        this.issuanceService = new DefaultIssuanceService(store, framework, issuerBackend, auditSink, statusResolver);
        this.revocationService = new DefaultRevocationService(store, clock, auditSink);
        this.statusObjectService = new DefaultStatusObjectService(store, framework, auditSink, statusResolver);

        this.caService = new DefaultCaService(store, framework, issuerBackend, this::resolvePublicKeyInfo, signingBus,
                auditSink, statusResolver, "SHA256withRSA", signingTtl);
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
        PkiSigningBus signingBus = new PkiSigningBus(store, signer, busFile);

        BcX509CredentialIssuerBackend issuerBackend = new BcX509CredentialIssuerBackend(signingBus, "SHA256withRSA",
                Duration.ofSeconds(2));
        BcX509StatusObjectGenerator statusGen = new BcX509StatusObjectGenerator(signingBus, "SHA256withRSA",
                Duration.ofSeconds(2));
        BcX509CredentialFramework baseFramework = new BcX509CredentialFramework();
        CredentialFramework framework = proofVerifier
                .map(verifier -> baseFramework.wired(statusGen, verifier))
                .orElseGet(() -> baseFramework.wired(statusGen));

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
        PkiSigningBus signingBus = new PkiSigningBus(store, signer, busFile);
        BcX509CredentialIssuerBackend issuerBackend = new BcX509CredentialIssuerBackend(signingBus,
                "SHA256withRSA", signingTtl);
        BcX509StatusObjectGenerator statusGen = new BcX509StatusObjectGenerator(signingBus, "SHA256withRSA",
                signingTtl);
        CredentialFramework framework = new BcX509CredentialFramework().wired(statusGen);
        return new PkiTestRuntime(store, signingBus, signer, framework, issuerBackend, publicByRef, signingTtl);
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
     * @param keyRef managed key reference
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

    public CaService caService() {
        return caService;
    }

    public CaService caService(CredentialFramework credentialFramework) {
        return new DefaultCaService(store, Objects.requireNonNull(credentialFramework, "credentialFramework"),
                issuerBackend, this::resolvePublicKeyInfo, signingBus, auditSink, statusResolver, "SHA256withRSA",
                Duration.ofSeconds(2));
    }

    public CaService caService(CredentialIssuerBackend backend) {
        return new DefaultCaService(store, framework, Objects.requireNonNull(backend, "backend"),
                this::resolvePublicKeyInfo, signingBus, auditSink, statusResolver, "SHA256withRSA",
                Duration.ofSeconds(2));
    }

    public CaService caService(CredentialIssuerBackend backend, EffectiveCredentialStatusResolver resolver) {
        return new DefaultCaService(store, framework, Objects.requireNonNull(backend, "backend"),
                this::resolvePublicKeyInfo, signingBus, auditSink, Objects.requireNonNull(resolver, "resolver"),
                "SHA256withRSA", Duration.ofSeconds(2));
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
                Objects.requireNonNull(resolver, "resolver"));
    }

    public RevocationService revocationService() {
        return revocationService;
    }

    public StatusObjectService statusObjectService() {
        return statusObjectService;
    }

    public StatusObjectService statusObjectService(EffectiveCredentialStatusResolver resolver) {
        return new DefaultStatusObjectService(store, framework, auditSink, Objects.requireNonNull(resolver,
                "resolver"));
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
