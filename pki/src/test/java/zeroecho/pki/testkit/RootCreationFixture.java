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

package zeroecho.pki.testkit;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
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
import java.util.concurrent.atomic.AtomicInteger;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spi.AlgorithmExecutionCapability.Direction;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.profile.CaCertificatePolicy;
import zeroecho.pki.api.profile.CaKeyUsage;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.profile.SubjectPolicy;
import zeroecho.pki.api.profile.SubjectRdnRule;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.impl.core.RootSigningPreparation;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.core.signing.DefaultSigningService;
import zeroecho.pki.impl.framework.x509.ImmutableX509AlgorithmBindingRegistry;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Real root key/profile fixture shared by preparation, custody and reactor tests.
 */
public final class RootCreationFixture {
    /**
     * Fixed reference instant shared by the fixture and its expected evidence.
     */
    public static final Instant NOW = Instant.parse("2026-09-21T12:00:00.450Z");
    /**
     * Fixed authoritative clock used to make fixture timestamps deterministic.
     */
    public static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    /**
     * Lifetime assigned to prepared fixture signing submissions.
     */
    public static final Duration TTL = Duration.ofMinutes(1);
    /**
     * Canonical signature identity used by this fixture.
     */
    public static final String ALGORITHM = BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm();
    /**
     * Logical reference of the fixture signing key.
     */
    public static final KeyRef KEY = new KeyRef("root-key");
    /**
     * Logical reference used when the fixture selects its replacement root key.
     */
    public static final KeyRef REPLACEMENT_KEY = new KeyRef("replacement-root-key");
    /**
     * Authenticated actor and purpose attached to fixture signing requests.
     */
    public static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "root-actor"),
            new Purpose("CREATE_ROOT"), Optional.empty(), Optional.empty());
    /**
     * Real key pair retained for certificate construction and verification.
     */
    public final KeyPair key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    /**
     * Unrelated key pair used to detect mismatched signing-key selection.
     */
    public final KeyPair otherKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    /**
     * Signing/public-key provider fixture with observable calls and injectable failures.
     */
    public final Provider provider = new Provider();
    /**
     * Composed X.509 signing executors bound to the fixture provider.
     */
    public final X509AuthoritySnapshot signing = PkiTestRuntime.signingAuthority(provider);
    /**
     * Independent Bouncy Castle X.509 signature verifier.
     */
    public final BcX509VerificationExecutor verifier = new BcX509VerificationExecutor();
    /**
     * Composed verification-only X.509 authority snapshot.
     */
    public final X509AuthoritySnapshot verification = X509AuthoritySnapshot.compose(List.of(), List.of(verifier),
            List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID, Direction.VERIFY, verifier)),
            (suite, direction) -> direction == Direction.VERIFY);
    /**
     * Immutable registry of the standard X.509 algorithm bindings.
     */
    public final ImmutableX509AlgorithmBindingRegistry bindings = ImmutableX509AlgorithmBindingRegistry.create(StandardX509Bindings.descriptors());
    /**
     * Public-key information returned by the fixture provider; replaceable by negative tests.
     */
    public EncodedObject exported = new EncodedObject(Encoding.DER, key.getPublic().getEncoded());
    /**
     * Whether the fixture intentionally signs using the unrelated key.
     */
    public boolean wrongSigningKey;
    /**
     * Maximum accepted signing-content length in bytes advertised by the fixture provider.
     */
    public long inputMaximum = 4_000_000;

    /**
     * Creates real Ed25519 root and replacement keys with composed signing/verification executors.
     *
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    public RootCreationFixture() throws Exception { }

    /**
     * Builds the fixture certificate profile with the selected kind, validity, and binding policy.
     *
     * @param id profile, attribute, or credential identifier selected by the fixture
     * @param kind certificate-profile kind selected for this fixture
     * @param validity optional requested validity bounds
     * @param bindings X.509 algorithm-binding policy retained in the fixture profile
     * @return version-one profile definition with the fixture subject requirements
     */
    public static CertificateProfileDefinition definition(String id, CertificateProfileKind kind, Duration validity,
            X509AlgorithmBindingPolicy bindings) {
        return new CertificateProfileDefinition(kind, id, 1, new FormatId("x509"), "Root test profile", validity,
                new SubjectPolicy(false, List.of(
                        new SubjectRdnRule(SubjectRdnType.COMMON_NAME, 1, 1, 128, Optional.empty(), true),
                        new SubjectRdnRule(SubjectRdnType.COUNTRY_NAME, 1, 1, 2, Optional.empty(), true),
                        new SubjectRdnRule(SubjectRdnType.ORGANIZATION_NAME, 1, 1, 128, Optional.of("Frozen Organization"), false))),
                new CaCertificatePolicy(true, 2, true, Set.of(CaKeyUsage.KEY_CERT_SIGN, CaKeyUsage.CRL_SIGN), Set.of("Ed25519")), bindings);
    }
    /**
     * Imports and activates the fixture root certificate profile.
     *
     * @param store borrowed test store used for fixture state, staging, and persisted assertions
     * @return exact activated root profile reference
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    public CertificateProfileRef initialize(PkiStore store) throws Exception {
        return install(store, definition("root-test", CertificateProfileKind.ROOT_CA, Duration.ofDays(100),
                X509AlgorithmBindingPolicy.standardOnly()));
    }
    /**
     * Canonically imports and activates the supplied certificate-profile version.
     *
     * @param store borrowed test store used for fixture state, staging, and persisted assertions
     * @param definition profile definition imported canonically and activated by the fixture
     * @return exact activated profile reference including its canonical digest
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    public static CertificateProfileRef install(PkiStore store, CertificateProfileDefinition definition) throws Exception {
        byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(definition);
        CertificateProfileRef reference = new CertificateProfileRef(definition.profileId(), definition.profileVersion(),
                MessageDigest.getInstance("SHA-256").digest(canonical));
        store.importProfileVersion(new ImportedCertificateProfileVersion(reference, CertificateProfileDefinition.SCHEMA_VERSION,
                definition, canonical, NOW));
        store.activateProfile(definition.profileId(), definition.profileVersion());
        return reference;
    }
    /**
     * Creates the fixture command with the selected authority, key, and profile bindings.
     *
     * @return typed command ready for the test preparation or acceptance path
     */
    public CaCreateCommand command() {
        return new CaCreateCommand(new FormatId("x509"), new SubjectRef("CN=Prepared Root,C=cz"), "root-test", KEY, new SimpleAttributeSet());
    }
    /**
     * Creates a fresh submission identity bound to the fixture store namespace and provider.
     *
     * @param store borrowed test store used for fixture state, staging, and persisted assertions
     * @return new signing submission identity at the fixed fixture instant
     */
    public SigningSubmissionId submission(PkiStore store) {
        return SigningSubmissionId.create(store.signingNamespace() + "." + provider.id(), NOW, new SecureRandom());
    }
    /**
     * Composes the fixture authority-signing preparer with its exact key/profile executors.
     *
     * @param store borrowed test store used for fixture state, staging, and persisted assertions
     * @return signing preparer borrowing the fixture store and authoritative clock
     */
    public RootSigningPreparation preparer(PkiStore store) {
        return new RootSigningPreparation(store, CLOCK, provider, signing, bindings, ALGORITHM, ManagedKeyProofCommand.MAX_CHALLENGE_BYTES);
    }
    /**
     * Composes the fixture semantic signing service over the selected store and signing collaborators.
     *
     * @param store borrowed test store used for fixture state, staging, and persisted assertions
     * @return semantic service borrowing the fixture store, clock, and provider
     */
    public DefaultSemanticSigningService semantic(PkiStore store) {
        DefaultSigningService service = new DefaultSigningService(store, provider, signing.resolveIdentity(ALGORITHM), TTL, new SecureRandom(), () -> { },
                (command, custody) -> { custody.run(); return store.acceptSign(command); }, () -> { },
                (boundedWaitId, boundedWaitCancellation) -> { throw new UnsupportedOperationException("Fixture has no reactor wait"); });
        return new DefaultSemanticSigningService(store, service, PkiTestRuntime.endEntityPreparation(store, CLOCK),
                ManagedKeyProofCommand.MAX_CHALLENGE_BYTES, Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(preparer(store)));
    }
    /**
     * Signs the supplied bytes with the fixture key selected by its logical reference.
     *
     * @param bytes content bytes to hash or sign; borrowed without modification
     * @return independently owned encoded signature
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    public EncodedObject signature(byte[] bytes) throws Exception { return signature(bytes, KEY); }
    /**
     * Signs the supplied bytes with the fixture key selected by its logical reference.
     *
     * @param bytes content bytes to hash or sign; borrowed without modification
     * @param reference logical root or replacement-key reference selecting the fixture signer
     * @return independently owned encoded signature
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    public EncodedObject signature(byte[] bytes, KeyRef reference) throws Exception {
        KeyPair selected = REPLACEMENT_KEY.equals(reference) ? otherKey : key;
        KeyPair incorrect = REPLACEMENT_KEY.equals(reference) ? key : otherKey;
        Signature engine = Signature.getInstance("Ed25519");
        engine.initSign((wrongSigningKey ? incorrect : selected).getPrivate());
        engine.update(bytes);
        return new EncodedObject(Encoding.BINARY, engine.sign());
    }

    /**
     * Real signing provider fixture with public-key lookups and dispatch counters.
     */
    public final class Provider implements SigningProvider, PublicKeyInfoSource {
        /**
         * Number of signing-provider dispatches observed by the fixture.
         */
        public final AtomicInteger dispatches = new AtomicInteger();
        /**
         * Number of public-key-information lookups observed by the fixture.
         */
        public final AtomicInteger lookups = new AtomicInteger();
        /**
         * {@inheritDoc}
         */
        @Override public String id() { return "root-test"; }
        /**
         * {@inheritDoc}
         */
        @Override public ConfigurationCommitment configurationCommitment() { return new ConfigurationCommitment(new byte[32]); }
        /**
         * {@inheritDoc}
         */
        @Override public Set<String> supportedAlgorithms() { return Set.of(ALGORITHM); }
        /**
         * {@inheritDoc}
         */
        @Override public SigningInputCapabilities inputCapabilities() { return new SigningInputCapabilities(inputMaximum, Map.of()); }
        /**
         * {@inheritDoc}
         */
        @Override public EncodedObject resolvePublicKeyInfo(KeyRef reference) {
            lookups.incrementAndGet();
            if (REPLACEMENT_KEY.equals(reference)) return new EncodedObject(Encoding.DER, otherKey.getPublic().getEncoded());
            if (!KEY.equals(reference)) throw new IllegalArgumentException("Unknown fixture key");
            return exported;
        }
        /**
         * {@inheritDoc}
         */
        @Override public OperationObservation dispatch(SignRequest request, CallControl control) {
            dispatches.incrementAndGet();
            try (InputStream input = request.content().openStream()) {
                return new OperationObservation(request.operationId(), ObservationState.SUCCEEDED, NOW, DetailCode.SIGNED,
                        Optional.of(signature(input.readAllBytes(), request.keyRef())));
            } catch (Exception failure) { throw new AssertionError("Fixture signature failed", failure); }
        }
        /**
         * {@inheritDoc}
         */
        @Override public OperationObservation reconcile(PkiId operation, CallControl control) { throw new AssertionError("Unexpected reconcile"); }
        /**
         * {@inheritDoc}
         */
        @Override public OperationObservation cancel(PkiId operation, long fence, CancellationReason reason, CallControl control) {
            throw new AssertionError("Unexpected provider cancellation");
        }
        /**
         * {@inheritDoc}
         */
        @Override public void close() { }
    }
}
