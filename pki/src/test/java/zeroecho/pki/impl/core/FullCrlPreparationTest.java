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

package zeroecho.pki.impl.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.lang.reflect.RecordComponent;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.core.spi.AlgorithmExecutionCapabilityProvider;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
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
import zeroecho.pki.api.status.FullCrlRequest;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.ImmutableX509AlgorithmBindingRegistry;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509BindingRule;
import zeroecho.pki.impl.framework.x509.X509BindingRuleProvider;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.StagedContentStore;

class FullCrlPreparationTest {
    private static final Instant NOW = Instant.parse("2026-09-20T12:00:00Z");
    private static final Instant BEFORE = NOW.minusSeconds(60);
    private static final Instant AFTER = NOW.plus(Duration.ofDays(4000));
    private static final PkiId CA = new PkiId("ca:crl");
    private static final PkiId CREDENTIAL = new PkiId("credential:historical");
    private static final PkiId GENERATION = IssuerGeneration.idFor(CA, CREDENTIAL);
    private static final PkiId CURRENT = IssuerGeneration.idFor(CA, new PkiId("credential:current"));
    private static final KeyRef KEY = new KeyRef("key:historical");
    private static final AlgorithmIdentity SIGNATURE = BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256;
    private static KeyPair key;
    private static byte[] certificate;

    @BeforeAll static void certificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        key = generator.generateKeyPair();
        certificate = certificate(true, KeyUsage.keyCertSign | KeyUsage.cRLSign);
    }

    @Test void requestRejectsMissingAndNonpositiveValues() {
        assertThrows(NullPointerException.class, () -> new FullCrlRequest(null, Duration.ofDays(1)));
        assertThrows(NullPointerException.class, () -> new FullCrlRequest(GENERATION, null));
        assertThrows(IllegalArgumentException.class, () -> new FullCrlRequest(GENERATION, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new FullCrlRequest(GENERATION, Duration.ofNanos(-1)));
        assertEquals(Duration.ofSeconds(Long.MAX_VALUE), new FullCrlRequest(GENERATION,
                Duration.ofSeconds(Long.MAX_VALUE)).validity());
    }

    @Test void activeAndRetiredHistoricalGenerationsFreezeExactInputsWithoutWrites() throws Exception {
        for (CaState caState : List.of(CaState.ACTIVE, CaState.RETIRED)) {
            for (IssuerGenerationState state : List.of(IssuerGenerationState.ACTIVE, IssuerGenerationState.RETIRED)) {
                Fixture fixture = new Fixture();
                fixture.ca = ca(caState, List.of(GENERATION, CURRENT));
                fixture.generation = generation(state, fixture.commitment(), fixture.commitment());
                AtomicInteger clockReads = new AtomicInteger();
                Instant evaluation = NOW.plusNanos(750_000_000);
                Clock clock = new Clock() {
                    @Override public ZoneId getZone() { return ZoneOffset.UTC; }
                    @Override public Clock withZone(ZoneId zone) { return this; }
                    @Override public Instant instant() { clockReads.incrementAndGet(); return evaluation; }
                };
                FullCrlPreparation.Prepared prepared = fixture.preparer(clock, true, true, SIGNATURE)
                        .prepare(request(Duration.ofSeconds(90)), CancellationSignal.NONE);
                assertEquals(1, clockReads.get());
                assertEquals(CA, prepared.authorityId());
                assertSame(fixture.ca, prepared.authority());
                assertEquals(fixture.generation, prepared.generation());
                assertEquals(KEY, prepared.generation().signingKeyRef());
                assertEquals(CREDENTIAL, prepared.credentialId());
                assertEquals(fixture.profile.reference(), prepared.profile());
                assertEquals(fixture.credential.content(), prepared.issuerContent());
                assertEquals(evaluation, prepared.evaluationTime());
                assertEquals(NOW, prepared.thisUpdate());
                assertEquals(NOW.plusSeconds(90), prepared.nextUpdate());
                assertEquals(X509AlgorithmBinding.Role.CRL_SIGNATURE, prepared.signatureBinding().role());
                assertEquals(SIGNATURE, prepared.signatureBinding().algorithmIdentity());
                assertEquals(X509AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11"), prepared.signatureIdentifier());
                assertEquals("cn=issuer", prepared.scope().canonicalIssuerName());
                assertEquals(5, fixture.reads.get());
                byte[] copy = prepared.issuerDer();
                copy[0] ^= 1;
                assertArrayEquals(certificate, prepared.issuerDer());
                assertEquals("PreparedFullCrl[redacted]", prepared.toString());
            }
        }
    }

    @Test void compromisedAndDisabledCaOrGenerationAreRejected() throws Exception {
        for (CaState state : List.of(CaState.COMPROMISED, CaState.DISABLED)) {
            Fixture fixture = new Fixture();
            fixture.ca = ca(state, List.of(GENERATION, CURRENT));
            assertRejected(fixture, "ISSUER_UNAVAILABLE");
        }
        for (IssuerGenerationState state : List.of(IssuerGenerationState.COMPROMISED, IssuerGenerationState.DISABLED)) {
            Fixture fixture = new Fixture();
            fixture.generation = generation(state, fixture.commitment(), fixture.commitment());
            assertRejected(fixture, "ISSUER_UNAVAILABLE");
        }
    }

    @Test void durationIsCheckedAfterWholeSecondNormalizationAndAgainstIssuerNotAfter() throws Exception {
        Fixture fixture = new Fixture();
        FullCrlPreparation preparation = fixture.preparer(Clock.fixed(NOW.plusNanos(900_000_000), ZoneOffset.UTC),
                true, true, SIGNATURE);
        for (Duration invalid : List.of(Duration.ofNanos(1), Duration.ofNanos(999_999_999),
                Duration.ofSeconds(Long.MAX_VALUE), Duration.between(NOW, AFTER).plusNanos(1))) {
            assertThrows(PkiException.class, () -> preparation.prepare(request(invalid), CancellationSignal.NONE));
        }
        assertEquals(NOW.plusSeconds(1), preparation.prepare(request(Duration.ofSeconds(1)),
                CancellationSignal.NONE).nextUpdate());
        assertEquals(NOW.plusSeconds(1), preparation.prepare(request(Duration.ofNanos(1_999_999_999)),
                CancellationSignal.NONE).nextUpdate());
        assertEquals(AFTER, preparation.prepare(request(Duration.between(NOW, AFTER)), CancellationSignal.NONE).nextUpdate());
        assertEquals(NOW.plus(Duration.ofDays(1000)), preparation.prepare(request(Duration.ofDays(1000)),
                CancellationSignal.NONE).nextUpdate());
        assertThrows(PkiException.class, () -> fixture.preparer(Clock.fixed(BEFORE.minusNanos(1), ZoneOffset.UTC),
                true, true, SIGNATURE).prepare(request(Duration.ofHours(1)), CancellationSignal.NONE));
        assertThrows(PkiException.class, () -> fixture.preparer(Clock.fixed(AFTER, ZoneOffset.UTC), true, true, SIGNATURE)
                .prepare(request(Duration.ofSeconds(1)), CancellationSignal.NONE));
    }

    @Test void frozenProfileBindingIsUsedWithoutConsultingActiveProfile() throws Exception {
        Fixture fixture = new Fixture();
        fixture.installProfile(privatePolicy());
        FullCrlPreparation.Prepared prepared = fixture.prepare();
        assertEquals(PrivateBinding.DESCRIPTOR, prepared.signatureBinding());
        assertEquals(PrivateBinding.DESCRIPTOR.oid(), prepared.signatureIdentifier().oid());
        // Every active-profile read fails the fixture. Its immutable version is sufficient even if inactive.
        assertEquals(1, prepared.profile().profileVersion());
    }

    @Test void currentRuntimePolicyExecutorAndKeyCompatibilityRestrictFrozenProfile() throws Exception {
        Fixture fixture = new Fixture();
        fixture.installProfile(privatePolicy());
        assertThrows(PkiException.class, () -> fixture.preparer(fixed(), false, true, SIGNATURE)
                .prepare(request(Duration.ofHours(1)), CancellationSignal.NONE));
        assertThrows(PkiException.class, () -> fixture.preparer(fixed(), true, false, SIGNATURE)
                .prepare(request(Duration.ofHours(1)), CancellationSignal.NONE));
        assertThrows(PkiException.class, () -> fixture.preparer(fixed(), true, true, BootstrapAlgorithmIdentities.RSA_PSS_SHA256)
                .prepare(request(Duration.ofHours(1)), CancellationSignal.NONE));
        fixture.installProfile(X509AlgorithmBindingPolicy.standardOnly());
        assertThrows(PkiException.class, () -> fixture.preparer(fixed(), true, true, BootstrapAlgorithmIdentities.ECDSA_SHA256)
                .prepare(request(Duration.ofHours(1)), CancellationSignal.NONE));
        assertThrows(IllegalArgumentException.class, () -> new FullCrlPreparation(fixture.store(), fixed(),
                runtime(true, true), registry(), "SHA256withRSA"));
    }

    @Test void missingAndMismatchedPointLookupsFailClosed() throws Exception {
        for (String missing : List.of("getIssuerGeneration", "getCa", "getCredential", "getProfileVersion")) {
            Fixture fixture = new Fixture();
            fixture.missing = missing;
            assertThrows(PkiException.class, fixture::prepare);
        }
        Fixture fixture = new Fixture();
        assertThrows(PkiException.class, () -> fixture.preparer(fixed(), true, true, SIGNATURE)
                .prepare(new FullCrlRequest(CURRENT, Duration.ofHours(1)), CancellationSignal.NONE));
        fixture.ca = ca(CaState.ACTIVE, List.of(CURRENT));
        assertRejected(fixture, "ISSUER_BINDING_INCONSISTENT");
        fixture.ca = new CaRecord(new PkiId("ca:wrong"), CaKind.ROOT, CaState.ACTIVE, KEY,
                new SubjectRef("CN=Issuer"), List.of(GENERATION), GENERATION, new PkiId("path"));
        assertRejected(fixture, "ISSUER_BINDING_INCONSISTENT");
        fixture.ca = ca(CaState.ACTIVE, List.of(GENERATION, CURRENT));
        fixture.credential = credential(new PkiId("credential:wrong"), fixture.profile.reference(), certificate);
        assertRejected(fixture, "ISSUER_BINDING_INCONSISTENT");
    }

    @Test void generationProfileAndBindingCommitmentsCannotDrift() throws Exception {
        for (boolean policy : new boolean[] {false, true}) {
            Fixture fixture = new Fixture();
            fixture.generation = generation(IssuerGenerationState.ACTIVE,
                    policy ? "00".repeat(32) : fixture.commitment(), policy ? fixture.commitment() : "00".repeat(32));
            assertRejected(fixture, "PROFILE_BINDING_INCONSISTENT");
        }
        Fixture fixture = new Fixture();
        ImportedCertificateProfileVersion original = fixture.profile;
        fixture.profile = new ImportedCertificateProfileVersion(new CertificateProfileRef("root", 1, new byte[32]),
                CertificateProfileDefinition.SCHEMA_VERSION, original.definition(), original.canonicalJson(), NOW);
        assertRejected(fixture, "PROFILE_BINDING_INCONSISTENT");
        fixture.profile = new ImportedCertificateProfileVersion(original.reference(), CertificateProfileDefinition.SCHEMA_VERSION,
                original.definition(), new byte[] {1}, NOW);
        assertRejected(fixture, "PROFILE_COMMITMENT_MISMATCH");
    }

    @Test void certificateMustBeCaWithCrlSignAndMatchItsMetadataAndContentCommitment() throws Exception {
        for (byte[] invalid : List.of(certificate(false, KeyUsage.cRLSign), certificate(true, KeyUsage.keyCertSign))) {
            Fixture fixture = new Fixture();
            fixture.der = invalid;
            fixture.credential = credential(CREDENTIAL, fixture.profile.reference(), invalid);
            assertRejected(fixture, "CREDENTIAL_UNUSABLE");
        }
        Fixture fixture = new Fixture();
        fixture.der = certificate.clone();
        fixture.der[fixture.der.length - 1] ^= 1;
        assertRejected(fixture, "CREDENTIAL_COMMITMENT_MISMATCH");
        fixture.der = certificate;
        fixture.ca = new CaRecord(CA, CaKind.ROOT, CaState.ACTIVE, KEY, new SubjectRef("CN=Other"),
                List.of(GENERATION), GENERATION, new PkiId("path"));
        assertRejected(fixture, "CREDENTIAL_UNUSABLE");
    }

    @Test void cancellationBeforePreparationPerformsNoStoreRead() throws Exception {
        Fixture fixture = new Fixture();
        assertThrows(IOException.class, () -> fixture.preparer(fixed(), true, true, SIGNATURE)
                .prepare(request(Duration.ofHours(1)), () -> true));
        assertEquals(0, fixture.reads.get());
    }

    @Test void frozenPreparationAndTbsCarriersContainOnlyProviderNeutralResourceFreeComponents() {
        Set<Class<?>> allowed = Set.of(CaRecord.class, IssuerGeneration.class, PkiId.class, CertificateProfileRef.class,
                DurableContentReference.class, CrlScope.class, X509AlgorithmBinding.class, X509AlgorithmIdentifier.class,
                Instant.class, byte[].class, String.class, KeyRef.class, BigInteger.class, long.class, OptionalLong.class,
                zeroecho.pki.spi.store.MetadataStoreId.class, Optional.class,
                zeroecho.pki.impl.core.continuation.FullCrlSnapshotProvenance.class);
        for (Class<?> carrier : List.of(FullCrlPreparation.Prepared.class, PreparedFullCrlTbs.class, DeltaCrlBase.class,
                zeroecho.pki.impl.core.continuation.FullCrlSnapshotProvenance.class)) {
            for (RecordComponent component : carrier.getRecordComponents()) {
                assertTrue(allowed.contains(component.getType()), carrier.getSimpleName() + "." + component.getName()
                        + " must not retain a plan, provider, executor, source, cursor, sink or resource");
                if (component.getType() == Optional.class) {
                    assertEquals("java.util.Optional<zeroecho.pki.impl.core.DeltaCrlBase>", component.getGenericType().getTypeName());
                }
            }
        }
    }

    private static void assertRejected(Fixture fixture, String code) {
        assertEquals("Full CRL preparation rejected: code=" + code,
                assertThrows(PkiException.class, fixture::prepare).getMessage());
    }

    private static FullCrlRequest request(Duration duration) { return new FullCrlRequest(GENERATION, duration); }
    private static Clock fixed() { return Clock.fixed(NOW, ZoneOffset.UTC); }

    private static CaRecord ca(CaState state, List<PkiId> members) {
        return new CaRecord(CA, CaKind.ROOT, state, new KeyRef("key:current"), new SubjectRef("CN=Issuer"),
                members, CURRENT, new PkiId("path:current"));
    }

    private static IssuerGeneration generation(IssuerGenerationState state, String profile, String binding) {
        return new IssuerGeneration(GENERATION, CA, CREDENTIAL, KEY, state, profile, binding);
    }

    private static Credential credential(PkiId id, CertificateProfileRef profile, byte[] der) throws Exception {
        return new Credential(id, new FormatId("x509"), new IssuerRef(CA, GENERATION, new PkiId("path:historical")),
                new SubjectRef("CN=Issuer"), new Validity(BEFORE, AFTER), "1", new PkiId("public:issuer"),
                new CaProfileBinding(profile), CredentialStatus.ISSUED,
                new Content("test-store", "issuer", Encoding.DER, der.length, hex(der),
                        DurableContentReference.Lifecycle.PERSISTED), new SimpleAttributeSet());
    }

    private static byte[] certificate(boolean ca, int usage) throws Exception {
        X500Name subject = new X500Name("CN=Issuer");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
                Date.from(BEFORE), Date.from(AFTER), subject, key.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded();
    }

    private static String hex(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static X509AlgorithmBindingPolicy privatePolicy() {
        X509AlgorithmBinding binding = PrivateBinding.DESCRIPTOR;
        return new X509AlgorithmBindingPolicy(X509AlgorithmBindingPolicy.Mode.EXPLICIT,
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(
                        new X509AlgorithmBindingPolicy.BindingReference(binding.bindingId(), binding.semanticCommitment())));
    }

    private static X509AlgorithmBindingRegistry registry() {
        List<X509AlgorithmBinding> descriptors = new ArrayList<>(StandardX509Bindings.descriptors());
        descriptors.add(PrivateBinding.DESCRIPTOR);
        return ImmutableX509AlgorithmBindingRegistry.create(descriptors);
    }

    private static X509AuthoritySnapshot runtime(boolean permitted, boolean executor) {
        EndEntityIssuancePreparationTest.CountingProvider signer = new EndEntityIssuancePreparationTest.CountingProvider();
        AlgorithmExecutionCapability capability = new AlgorithmExecutionCapability() {
            @Override public String implementationId() { return "crl-test-signing"; }
            @Override public String domainFingerprint() { return "crl-test-signing-v1"; }
            @Override public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                return direction == Direction.SIGN && identity.equals(SIGNATURE);
            }
        };
        AlgorithmExecutionCapabilityProvider provider = () -> List.of(capability);
        X509AlgorithmResolver.Policy policy = new X509AlgorithmResolver.Policy() {
            @Override public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) {
                return permitted;
            }
            @Override public String semanticFingerprint() { return "crl-policy-" + permitted; }
        };
        return X509AuthoritySnapshot.compose(List.of(new PrivateBinding()), List.of(provider), executor ? List.of(
                X509AuthoritySnapshot.bindExecutor(capability.implementationId(), AlgorithmExecutionCapability.Direction.SIGN,
                        signer)) : List.of(), policy);
    }

    private static final class Fixture {
        private final AtomicInteger reads = new AtomicInteger();
        private IssuerGeneration generation;
        private CaRecord ca = ca(CaState.ACTIVE, List.of(GENERATION, CURRENT));
        private Credential credential;
        private ImportedCertificateProfileVersion profile;
        private byte[] der = certificate;
        private String missing = "";

        private Fixture() throws Exception { installProfile(X509AlgorithmBindingPolicy.standardOnly()); }

        private void installProfile(X509AlgorithmBindingPolicy policy) throws Exception {
            CertificateProfileDefinition definition = new CertificateProfileDefinition(CertificateProfileKind.ROOT_CA,
                    "root", 1, new FormatId("x509"), "Root", Duration.ofDays(4000),
                    new SubjectPolicy(false, List.of(new SubjectRdnRule(SubjectRdnType.COMMON_NAME, 1, 1, 253,
                            Optional.empty(), true))),
                    new CaCertificatePolicy(true, 1, true, Set.of(CaKeyUsage.KEY_CERT_SIGN, CaKeyUsage.CRL_SIGN),
                            Set.of("RSA")), policy);
            byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(definition);
            CertificateProfileRef reference = new CertificateProfileRef("root", 1,
                    MessageDigest.getInstance("SHA-256").digest(canonical));
            profile = new ImportedCertificateProfileVersion(reference, CertificateProfileDefinition.SCHEMA_VERSION,
                    definition, canonical, NOW);
            credential = credential(CREDENTIAL, reference, der);
            generation = generation(IssuerGenerationState.ACTIVE, commitment(), commitment());
        }

        private String commitment() { return HexFormat.of().formatHex(profile.reference().canonicalSha256()); }

        private FullCrlPreparation preparer(Clock clock, boolean permitted, boolean executor, AlgorithmIdentity signature) {
            return new FullCrlPreparation(store(), clock, runtime(permitted, executor), registry(), signature.canonicalForm());
        }

        private FullCrlPreparation.Prepared prepare() throws IOException {
            return preparer(fixed(), true, true, SIGNATURE).prepare(request(Duration.ofHours(1)), CancellationSignal.NONE);
        }

        private PkiStore store() {
            StagedContentStore content = (StagedContentStore) Proxy.newProxyInstance(StagedContentStore.class.getClassLoader(),
                    new Class<?>[] {StagedContentStore.class}, (proxy, method, args) -> {
                        assertEquals("openContent", method.getName(), "Preparation must not stage content");
                        assertEquals(credential.content(), args[0]);
                        return new ImmutableByteContent(der);
                    });
            return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] {PkiStore.class},
                    (proxy, method, args) -> {
                        if (method.getName().equals("stagedContent")) { return content; }
                        reads.incrementAndGet();
                        if (method.getName().equals(missing)) { return Optional.empty(); }
                        return switch (method.getName()) {
                            case "getIssuerGeneration" -> Optional.of(generation);
                            case "getCa" -> { assertEquals(generation.authorityId(), args[0]); yield Optional.of(ca); }
                            case "getCredential" -> { assertEquals(generation.credentialId(), args[0]); yield Optional.of(credential); }
                            case "getRevocation" -> Optional.empty();
                            case "getProfileVersion" -> {
                                assertEquals("root", args[0]); assertEquals(1L, args[1]); yield Optional.of(profile);
                            }
                            default -> throw new AssertionError("Unexpected preparation operation: " + method.getName());
                        };
                    });
        }
    }

    private record Content(String storeId, String contentId, Encoding encoding, long length, String sha256,
            DurableContentReference.Lifecycle lifecycle) implements DurableContentReference { }

    private static final class PrivateBinding implements X509BindingRuleProvider, X509BindingRule {
        private static final X509AlgorithmBinding DESCRIPTOR = new X509AlgorithmBinding("test.crl.rsa.v1", SIGNATURE,
                X509AlgorithmBinding.Role.CRL_SIGNATURE, "1.3.6.1.4.1.55555.77.2", X509AlgorithmBinding.Origin.DEPLOYER_PRIVATE,
                1, X509AlgorithmBinding.ParameterRule.ABSENT, X509AlgorithmBinding.PublicKeyEncoding.NOT_APPLICABLE,
                X509AlgorithmBinding.SignatureEncoding.OPAQUE, X509AlgorithmBinding.Interoperability.DEPLOYER_ECOSYSTEM,
                Optional.of("test.crl"), "crl-rsa-v1");
        @Override public List<X509BindingRule> rules() { return List.of(this); }
        @Override public List<X509AlgorithmBinding> bindings() { return List.of(DESCRIPTOR); }
        @Override public String id() { return DESCRIPTOR.bindingId(); }
        @Override public X509AlgorithmRole role() { return X509AlgorithmRole.SIGNATURE_ALGORITHM; }
        @Override public String oid() { return DESCRIPTOR.oid(); }
        @Override public String semanticFingerprint() { return DESCRIPTOR.semanticCommitment(); }
        @Override public SignatureEncoding signatureEncoding() { return SignatureEncoding.OPAQUE; }
        @Override public PublicKeyEncoding publicKeyEncoding() { return PublicKeyEncoding.NOT_APPLICABLE; }
        @Override public Optional<X509AlgorithmIdentifier> encode(AlgorithmIdentity identity) {
            return identity.equals(SIGNATURE) ? Optional.of(X509AlgorithmIdentifier.absent(oid())) : Optional.empty();
        }
        @Override public Optional<AlgorithmIdentity> decode(X509AlgorithmIdentifier identifier) {
            return identifier.equals(X509AlgorithmIdentifier.absent(oid())) ? Optional.of(SIGNATURE) : Optional.empty();
        }
    }
}
