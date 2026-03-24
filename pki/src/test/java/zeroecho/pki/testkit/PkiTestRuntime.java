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
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import zeroecho.pki.api.CaService;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.StatusObjectService;
import zeroecho.pki.impl.core.DefaultCaService;
import zeroecho.pki.impl.core.DefaultCertificationRequestService;
import zeroecho.pki.impl.core.DefaultIssuanceService;
import zeroecho.pki.impl.core.DefaultRevocationService;
import zeroecho.pki.impl.core.DefaultStatusObjectService;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialIssuerBackend;
import zeroecho.pki.impl.framework.x509.bc.BcX509StatusObjectGenerator;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.framework.CredentialFramework;
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

    private final CredentialFramework framework;

    private final CaService caService;
    private final CertificationRequestService certificationRequestService;
    private final IssuanceService issuanceService;
    private final RevocationService revocationService;
    private final StatusObjectService statusObjectService;

    private final Map<String, KeyPair> keyPairsByKeyRef;

    private PkiTestRuntime(FilesystemPkiStore store, PkiSigningBus signingBus, SignatureWorkflow signatureWorkflow,
            CredentialFramework framework, Map<String, KeyPair> keyPairsByKeyRef) {
        this.store = store;
        this.signingBus = signingBus;
        this.signatureWorkflow = signatureWorkflow;
        this.framework = framework;
        this.keyPairsByKeyRef = keyPairsByKeyRef;

        this.certificationRequestService = new DefaultCertificationRequestService(store, framework);
        this.issuanceService = new DefaultIssuanceService(store, framework);
        this.revocationService = new DefaultRevocationService(store);
        this.statusObjectService = new DefaultStatusObjectService(store, framework);

        this.caService = new DefaultCaService(store, framework, this::resolvePublicKeyInfo, signingBus, "SHA256withRSA",
                Duration.ofSeconds(2));
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
        Objects.requireNonNull(rootDir, "rootDir");
        Objects.requireNonNull(busFile, "busFile");
        Objects.requireNonNull(keyPairs, "keyPairs");

        FsPkiStoreOptions opts = FsPkiStoreOptions.defaults();

        Path storeRoot = rootDir.resolve("store");
        FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, opts);

        Map<String, KeyPair> byRef = new HashMap<>();
        for (Map.Entry<KeyRef, KeyPair> e : keyPairs.entrySet()) {
            byRef.put(e.getKey().value(), e.getValue());
        }

        SignatureWorkflow signer = new InMemorySignatureWorkflow(byRef);
        PkiSigningBus signingBus = new PkiSigningBus(store, signer, busFile);

        BcX509CredentialIssuerBackend issuerBackend = new BcX509CredentialIssuerBackend(signingBus, "SHA256withRSA",
                Duration.ofSeconds(2));
        BcX509StatusObjectGenerator statusGen = new BcX509StatusObjectGenerator(signingBus, "SHA256withRSA",
                Duration.ofSeconds(2));
        CredentialFramework framework = new BcX509CredentialFramework().wired(issuerBackend, statusGen);

        return new PkiTestRuntime(store, signingBus, signer, framework, byRef);
    }

    private EncodedObject resolvePublicKeyInfo(KeyRef keyRef) {
        KeyPair kp = keyPairsByKeyRef.get(keyRef.value());
        if (kp == null) {
            throw new IllegalArgumentException("Unknown keyRef");
        }
        return new EncodedObject(Encoding.DER, kp.getPublic().getEncoded());
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

    public CredentialFramework framework() {
        return framework;
    }

    public CaService caService() {
        return caService;
    }

    public CertificationRequestService certificationRequestService() {
        return certificationRequestService;
    }

    public IssuanceService issuanceService() {
        return issuanceService;
    }

    public RevocationService revocationService() {
        return revocationService;
    }

    public StatusObjectService statusObjectService() {
        return statusObjectService;
    }

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
