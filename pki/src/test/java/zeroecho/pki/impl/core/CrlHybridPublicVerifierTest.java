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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.core.spi.AlgorithmExecutionCapabilityProvider;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.hybrid.HybridCertificateMode;
import zeroecho.pki.api.profile.CaCertificatePolicy;
import zeroecho.pki.api.profile.CaKeyUsage;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.IssuanceApprovalRequirement;
import zeroecho.pki.api.profile.SubjectPolicy;
import zeroecho.pki.api.profile.SubjectRdnRule;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.FullCrlSnapshotProvenance;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.ImmutableX509AlgorithmBindingRegistry;
import zeroecho.pki.impl.framework.x509.StreamingCrlAlternativeSignature;
import zeroecho.pki.impl.framework.x509.StreamingX509CrlTbsWriter;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509BindingRule;
import zeroecho.pki.impl.framework.x509.X509BindingRuleProvider;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.framework.CrlEntrySource;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.cert.CertificateBuilder;

/** Pure public-evidence checks; reference fixtures do not claim filesystem acceptance or adoption. */
class CrlHybridPublicVerifierTest {
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final PkiId CA = new PkiId("ca:public-verifier-fixture");
    private static final PkiId PARENT = new PkiId("zsign:v1:c036:1767225600000:0123456789abcdef0123456789abcdef");
    private static final KeyRef PRIMARY_KEY = new KeyRef("managed:primary");
    private static final KeyRef ALT_KEY = new KeyRef("managed:alternative");
    private static final X500Principal NAME = new X500Principal("CN=Public CRL Verifier");
    private static final byte[] SKI = {1, 2, 3, 4};
    private static final String PRIMARY_ID = BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm();
    private static final String ALT_ID = BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm();
    private static final X509AlgorithmIdentifier NATIVE_ALGORITHM = X509AlgorithmIdentifier.absent("1.2.840.10045.4.3.3");
    private static final X509AlgorithmIdentifier ALT_ALGORITHM = X509AlgorithmIdentifier.absent("2.16.840.1.101.3.4.3.19");
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "operator"), new Purpose("CRL"), Optional.empty(), Optional.empty());
    private static final MetadataStoreId SOURCE = new MetadataStoreId("a".repeat(32));
    private static KeyPair primary;
    private static KeyPair alternative;
    private static KeyPair wrongAlternative;
    private static KeyPair rsa;

    @BeforeAll static void keys() throws Exception {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp384r1")); primary = ec.generateKeyPair();
        KeyPairGenerator ml = KeyPairGenerator.getInstance("ML-DSA", "BC");
        ml.initialize(MLDSAParameterSpec.ml_dsa_87); alternative = ml.generateKeyPair(); wrongAlternative = ml.generateKeyPair();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(4096); rsa = generator.generateKeyPair();
    }

    @Test void verifiesRetainedAlternativeResultAndExactNativeChildForFullAndDelta() throws Exception {
        for (boolean delta : new boolean[] {false, true}) {
            Fixture fixture = new Fixture(delta, false, alternative, 1);
            assertTrue(Pkix.verifyAlternativeSignatureCor3(fixture.certificate, alternative.getPublic()));
            assertDoesNotThrow(() -> fixture.verify(fixture.parent, fixture.child, fixture.nativeTbs));
        }
    }

    @Test void rejectsBadAlternativeResultWrongIssuerAndChangedNativeReconstruction() throws Exception {
        Fixture fixture = new Fixture(false, false, alternative, 1);
        byte[] damaged = fixture.signature.clone(); damaged[0] ^= 1;
        for (byte[] signature : List.of(damaged, sign(wrongAlternative, fixture.transcript))) {
            SignWorkflowStore.Workflow changed = fixture.result(signature);
            Exception failure = assertThrows(Exception.class, () -> fixture.verify(changed, fixture.child, fixture.nativeTbs));
            assertTrue(failure instanceof GeneralSecurityException || failure instanceof IOException, failure::toString);
        }
        byte[] changedTbs = fixture.nativeTbs.clone(); changedTbs[changedTbs.length - 1] ^= 1;
        SignWorkflowStore.AcceptanceCommand changedContent = fixture.child(PRIMARY_KEY, NOW.plusSeconds(60), reference("changed-native", changedTbs));
        assertThrows(IOException.class, () -> fixture.verify(fixture.parent, changedContent, changedTbs));
        Fixture otherIssuer = new Fixture(false, false, wrongAlternative, 2);
        assertThrows(IllegalArgumentException.class, () -> fixture.verifier.verify(fixture.binding,
                new EncodedObject(Encoding.DER, otherIssuer.certificate.getEncoded()), fixture.parent,
                new ImmutableByteContent(fixture.transcript), fixture.child, new ImmutableByteContent(fixture.nativeTbs), CancellationSignal.NONE));
    }

    @Test void rejectsChangedChildRoleDeadlineAndFalsifiedPublicSignatureBound() throws Exception {
        Fixture fixture = new Fixture(false, false, alternative, 1);
        assertThrows(IllegalArgumentException.class, () -> fixture.templateWithNativeKey(ALT_KEY));
        assertThrows(IllegalArgumentException.class, () -> fixture.verify(fixture.parent,
                fixture.child(ALT_KEY, NOW.plusSeconds(60), reference("native", fixture.nativeTbs)), fixture.nativeTbs));
        assertThrows(IllegalArgumentException.class, () -> fixture.verify(fixture.parent,
                fixture.child(PRIMARY_KEY, NOW.plusSeconds(61), reference("native", fixture.nativeTbs)), fixture.nativeTbs));
        var descriptor = CrlHybridSigningCommand.descriptor(DomainCommandEncoding.decode(fixture.template.command()));
        var falsified = new CrlHybridSigningCommand.Descriptor(descriptor.issuerBindingCommitment(), descriptor.roleTupleCommitment(),
                descriptor.nativeChildId(), descriptor.primaryPlanCommitment(), descriptor.alternativePlanCommitment(), 4628, 104);
        List<String> fields = new java.util.ArrayList<>(DomainCommandEncoding.decode(fixture.template.command()).fields());
        fields.set(fields.size() - 1, falsified.encode());
        DomainContinuationTemplate changed = DomainCommandEncoding.correlatedTemplate(fixture.template.kind(),
                fixture.template.correlationId().orElseThrow(), "GENERATE_FULL_CRL", fields.toArray(String[]::new));
        SignWorkflowStore.Workflow changedBound = fixture.parent(changed, fixture.signature);
        assertThrows(IllegalArgumentException.class, () -> fixture.verify(changedBound, fixture.child, fixture.nativeTbs));
    }

    @Test void derivesPublicBoundsAndKeepsSameKeyTupleAcrossCertificateRollover() throws Exception {
        Fixture initial = new Fixture(false, false, alternative, 1);
        Fixture renewed = new Fixture(false, false, alternative, 2);
        Fixture changedRole = new Fixture(false, false, wrongAlternative, 3);
        Fixture privatePresentation = new Fixture(false, true, alternative, 4);
        assertNotEquals(initial.binding.commitment(), renewed.binding.commitment());
        assertEquals(initial.tuple, renewed.tuple);
        assertNotEquals(initial.tuple, changedRole.tuple);
        assertNotEquals(initial.tuple, privatePresentation.tuple);
        assertEquals(104, CrlSigningRoleTuple.maximumSignatureBytes(initial.binding.primary(), primary.getPublic().getEncoded(), initial.authority));
        assertEquals(4627, CrlSigningRoleTuple.maximumSignatureBytes(initial.binding.alternative().orElseThrow(), alternative.getPublic().getEncoded(), initial.authority));
        var rsaBinding = new IssuerKeyBinding(new KeyRef("managed:rsa"), BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY,
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384,
                new EncodedObject(Encoding.DER, Pkix.encodeAlgorithmIdentifier(zeroecho.pkix.AlgorithmIdentifier.derNull("1.2.840.113549.1.1.12"))),
                digest(rsa.getPublic().getEncoded()));
        assertEquals(512, CrlSigningRoleTuple.maximumSignatureBytes(rsaBinding, rsa.getPublic().getEncoded(), initial.authority));
        assertDoesNotThrow(() -> privatePresentation.verify(privatePresentation.parent, privatePresentation.child, privatePresentation.nativeTbs));
        var standardOnly = new CrlHybridPublicVerifier(authority(false));
        assertThrows(IllegalArgumentException.class, () -> standardOnly.verify(privatePresentation.binding,
                new EncodedObject(Encoding.DER, privatePresentation.certificate.getEncoded()), privatePresentation.parent,
                new ImmutableByteContent(privatePresentation.transcript), privatePresentation.child,
                new ImmutableByteContent(privatePresentation.nativeTbs), CancellationSignal.NONE));
    }

    @Test void planCommitmentRetainsAuthorityDirectionAndExactBindingSemantics() {
        X509AlgorithmBinding binding = StandardX509Bindings.descriptors().stream().filter(value ->
                value.role() == X509AlgorithmBinding.Role.CRL_SIGNATURE
                        && value.algorithmIdentity().equals(BootstrapAlgorithmIdentities.ECDSA_SHA384)).findFirst().orElseThrow();
        var sign = publicPlan("policy-a", AlgorithmExecutionCapability.Direction.SIGN, binding.bindingId());
        String expected = CrlSigningRoleTuple.planCommitment(sign, binding.bindingId(), binding.semanticCommitment());
        assertEquals(expected, CrlSigningRoleTuple.planCommitment(publicPlan("policy-a", AlgorithmExecutionCapability.Direction.SIGN,
                binding.bindingId()), binding.bindingId(), binding.semanticCommitment()));
        assertNotEquals(expected, CrlSigningRoleTuple.planCommitment(publicPlan("policy-b", AlgorithmExecutionCapability.Direction.SIGN,
                binding.bindingId()), binding.bindingId(), binding.semanticCommitment()));
        assertNotEquals(expected, CrlSigningRoleTuple.planCommitment(publicPlan("policy-a", AlgorithmExecutionCapability.Direction.VERIFY,
                binding.bindingId()), binding.bindingId(), binding.semanticCommitment()));
        assertNotEquals(expected, CrlSigningRoleTuple.planCommitment(sign, binding.bindingId() + ".other", binding.semanticCommitment()));
        assertNotEquals(expected, CrlSigningRoleTuple.planCommitment(sign, binding.bindingId(), binding.semanticCommitment() + ".changed"));
    }

    private static final class Fixture {
        private final X509AuthoritySnapshot authority;
        private final CrlHybridPublicVerifier verifier;
        private final X509Certificate certificate;
        private final IssuerCryptographicBinding binding;
        private final String tuple;
        private final byte[] transcript;
        private final byte[] signature;
        private final byte[] nativeTbs;
        private final DomainContinuationTemplate template;
        private final PreparedFullCrlTbs prepared;
        private final SignWorkflowStore.Workflow parent;
        private final SignWorkflowStore.AcceptanceCommand child;

        private Fixture(boolean delta, boolean privateCrl, KeyPair alternativePair, int version) throws Exception {
            authority = authority(privateCrl); verifier = new CrlHybridPublicVerifier(authority);
            var policy = privateCrl ? new X509AlgorithmBindingPolicy(X509AlgorithmBindingPolicy.Mode.EXPLICIT,
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(new X509AlgorithmBindingPolicy.BindingReference(
                            PrivateCrlBinding.DESCRIPTOR.bindingId(), PrivateCrlBinding.DESCRIPTOR.semanticCommitment()))) : X509AlgorithmBindingPolicy.standardOnly();
            var definition = new CertificateProfileDefinition(CertificateProfileKind.ROOT_CA, "root", version,
                    new FormatId("x509"), "Public CRL root", Duration.ofDays(3650), IssuanceApprovalRequirement.NONE,
                    new SubjectPolicy(false, List.of(new SubjectRdnRule(SubjectRdnType.COMMON_NAME, 1, 1, 253, Optional.empty(), true))), new CaCertificatePolicy(true, 1, true,
                            Set.of(CaKeyUsage.KEY_CERT_SIGN, CaKeyUsage.CRL_SIGN), Set.of("ECDSA")), policy,
                    Optional.empty(), new HybridCertificateMode.AltSignature(ALT_ID, ALT_KEY.value()));
            byte[] profileBytes = CertificateProfileDocumentCodec.writeCanonical(definition);
            var profile = new CertificateProfileRef("root", version, MessageDigest.getInstance("SHA-256").digest(profileBytes));
            var bindingDescriptors = new java.util.ArrayList<>(StandardX509Bindings.descriptors());
            if (privateCrl) bindingDescriptors.add(PrivateCrlBinding.DESCRIPTOR);
            String bindingSetCommitment = ImmutableX509AlgorithmBindingRegistry.create(bindingDescriptors).commitment();
            byte[] altCertificateInput = certificate(primary, alternativePair, version).buildAlternativeSignatureTbs(libNative());
            certificate = certificate(primary, alternativePair, version)
                    .addExtension(zeroecho.pki.impl.hybrid.AltSignatureExtensions.altSignatureValue(sign(alternativePair, altCertificateInput)))
                    .build(Pkix.signer(primary.getPrivate(), libNative()));
            certificate.verify(primary.getPublic(), "BC");
            byte[] certificateDer = certificate.getEncoded();
            PkiId credentialId = new PkiId("x509:" + digest(certificateDer));
            PkiId generationId = IssuerGeneration.idFor(CA, credentialId);
            IssuerKeyBinding primaryRole = role(PRIMARY_KEY, BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY,
                    BootstrapAlgorithmIdentities.ECDSA_SHA384, libNative(), primary.getPublic().getEncoded());
            IssuerKeyBinding altRole = role(ALT_KEY, BootstrapAlgorithmIdentities.ML_DSA_87_PUBLIC_KEY,
                    BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE,
                    zeroecho.pkix.AlgorithmIdentifier.absent(ALT_ALGORITHM.oid()), alternativePair.getPublic().getEncoded());
            var generation = new IssuerGeneration(generationId, CA, credentialId, PRIMARY_KEY, IssuerGenerationState.ACTIVE,
                    HexFormat.of().formatHex(profile.canonicalSha256()), bindingSetCommitment);
            binding = IssuerBindingResolver.createCaptured(generation, certificateDer, "x509", primaryRole, Optional.of(altRole),
                    IssuerCryptographicBinding.HybridSignatureBaseline.COR3_SIGNED_WRAPPER, profile, bindingSetCommitment);
            X509AlgorithmBinding nativeBinding = privateCrl ? PrivateCrlBinding.DESCRIPTOR : StandardX509Bindings.descriptors().stream()
                    .filter(value -> value.role() == X509AlgorithmBinding.Role.CRL_SIGNATURE
                            && value.algorithmIdentity().equals(BootstrapAlgorithmIdentities.ECDSA_SHA384)).findFirst().orElseThrow();
            X509AlgorithmIdentifier nativeAlgorithm = authority.bindings().resolve(nativeBinding.bindingId(),
                    BootstrapAlgorithmIdentities.ECDSA_SHA384, X509AlgorithmRole.SIGNATURE_ALGORITHM);
            tuple = verifier.roleTupleCommitment(binding, new EncodedObject(Encoding.DER, certificateDer), definition);
            var writer = StreamingX509CrlTbsWriter.forAlternativeSignature(ALT_ALGORITHM, NAME.getEncoded(), SKI,
                    NOW, NOW.plusSeconds(86400), delta ? Optional.of(BigInteger.valueOf(7)) : Optional.empty());
            CrlEntrySource entries = emptyEntries();
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            writer.write(entries, writer.measure(entries, CancellationSignal.NONE), BigInteger.valueOf(delta ? 8 : 7), output, CancellationSignal.NONE);
            transcript = output.toByteArray(); signature = sign(alternativePair, transcript);
            ByteArrayOutputStream nativeOutput = new ByteArrayOutputStream();
            StreamingCrlAlternativeSignature.completeTbs(new ImmutableByteContent(transcript), nativeAlgorithm, signature,
                    nativeOutput, CancellationSignal.NONE); nativeTbs = nativeOutput.toByteArray();
            var hybrid = new PreparedFullCrlTbs.Hybrid(binding, ALT_ALGORITHM, tuple, generationId,
                    "b".repeat(64), "c".repeat(64), 4627, 104);
            prepared = new PreparedFullCrlTbs(CA, generationId, credentialId, profile,
                    reference("issuer", certificateDer, DurableContentReference.Lifecycle.PERSISTED), CrlScope.of(NAME.getEncoded(), primary.getPublic().getEncoded()).digest(),
                    HexFormat.of().formatHex(profile.canonicalSha256()), bindingSetCommitment, PRIMARY_KEY, PRIMARY_ID,
                    nativeBinding, nativeAlgorithm, BigInteger.valueOf(delta ? 8 : 7), NOW, NOW, NOW.plusSeconds(86400),
                    "snapshot:fixture", SOURCE, 2, 2, "e".repeat(64), OptionalLong.of(0), 0,
                    reference("alternative", transcript), delta ? Optional.of(new DeltaCrlBase(new PkiId("crl:" + "f".repeat(64)),
                            BigInteger.valueOf(7), new FullCrlSnapshotProvenance(SOURCE, 1, 1, "f".repeat(64)))) : Optional.empty(), Optional.of(hybrid));
            template = CrlHybridSigningCommand.template(prepared, PARENT);
            parent = parent(template, signature);
            child = child(PRIMARY_KEY, NOW.plusSeconds(60), reference("native", nativeTbs));
        }

        private SignWorkflowStore.Workflow parent(DomainContinuationTemplate value, byte[] result) {
            var outer = new SignWorkflowStore.OuterCommand(value.kind(), value.correlationId().orElseThrow(), value.command(), value.commandCommitment());
            var accepted = new SignWorkflowStore.AcceptanceCommand(PARENT, "c036", new SigningProvider.ConfigurationCommitment(new byte[32]),
                    ACCESS, ALT_KEY, CA, ALT_ID, Encoding.BINARY, NOW, NOW.plusSeconds(60), reference("alternative", transcript),
                    Optional.of(outer), SignWorkflowStore.Mode.NORMAL, Optional.empty());
            var state = new SignWorkflowStore.MutableState(PARENT, SignWorkflowStore.State.SUCCEEDED, 2, 1, Optional.empty(),
                    Optional.of(new PkiId("provider:alternative")), Optional.of("SIGNED"), Optional.of(new EncodedObject(Encoding.BINARY, result)),
                    Optional.of(NOW), 0, Optional.empty(), Optional.empty(), SignWorkflowStore.InitialAttemptPhase.NOT_APPLICABLE,
                    SignWorkflowStore.Stage.SINGLE, Optional.empty());
            return new SignWorkflowStore.Workflow(SignWorkflowStore.AcceptanceEnvelope.from(accepted), state);
        }
        private SignWorkflowStore.Workflow result(byte[] result) { return parent(template, result); }
        private DomainContinuationTemplate templateWithNativeKey(KeyRef key) {
            PreparedFullCrlTbs p = prepared;
            return CrlHybridSigningCommand.template(new PreparedFullCrlTbs(p.authorityId(), p.issuerGenerationId(), p.issuerCredentialId(),
                    p.profile(), p.issuerContent(), p.scopeDigest(), p.profilePolicyCommitment(), p.x509BindingCommitment(), key,
                    p.signatureAlgorithm(), p.signatureBinding(), p.signatureIdentifier(), p.crlNumber(), p.evaluationTime(), p.thisUpdate(),
                    p.nextUpdate(), p.snapshotId(), p.snapshotSourceStoreId(), p.snapshotRevision(), p.snapshotBoundary(), p.snapshotCommitment(),
                    p.rawEntryCount(), p.emittedEntryCount(), p.tbsContent(), p.base(), p.hybrid()), PARENT);
        }
        private SignWorkflowStore.AcceptanceCommand child(KeyRef key, Instant deadline, DurableContentReference content) {
            return new SignWorkflowStore.AcceptanceCommand(CrlHybridSigningCommand.nativeChildId(PARENT), "c036",
                    new SigningProvider.ConfigurationCommitment(new byte[32]), ACCESS, key, CA, PRIMARY_ID,
                    Encoding.BINARY, NOW, deadline, content, Optional.empty(), SignWorkflowStore.Mode.NORMAL, Optional.empty());
        }
        private void verify(SignWorkflowStore.Workflow workflow, SignWorkflowStore.AcceptanceCommand nativeChild, byte[] nativeContent) throws Exception {
            verifier.verify(binding, new EncodedObject(Encoding.DER, certificate.getEncoded()), workflow,
                    new ImmutableByteContent(transcript), nativeChild, new ImmutableByteContent(nativeContent), CancellationSignal.NONE);
        }
    }

    private static CertificateBuilder certificate(KeyPair key, KeyPair alternativeKey, int serial) throws IOException {
        return Pkix.certificateBuilder().serialNumber(BigInteger.valueOf(serial)).issuer(NAME).subject(NAME)
                .validity(NOW.minusSeconds(86400), NOW.plusSeconds(86400L * 3649)).publicKey(key.getPublic())
                .basicConstraints(zeroecho.pkix.BasicConstraints.ca(1), true)
                .keyUsage(Set.of(zeroecho.pkix.KeyUsage.KEY_CERT_SIGN, zeroecho.pkix.KeyUsage.CRL_SIGN), true)
                .addExtension(zeroecho.pki.impl.hybrid.AltSignatureExtensions.subjectAltPublicKeyInfo(alternativeKey.getPublic().getEncoded()))
                .addExtension(zeroecho.pki.impl.hybrid.AltSignatureExtensions.altSignatureAlgorithm(zeroecho.pkix.AlgorithmIdentifier.absent(ALT_ALGORITHM.oid())))
                .addExtension(new zeroecho.pkix.CertificateExtension("2.5.29.14", false, new org.bouncycastle.asn1.DEROctetString(SKI).getEncoded()));
    }

    private static byte[] sign(KeyPair key, byte[] content) throws Exception {
        Signature signature = Signature.getInstance("ML-DSA-87", "BC"); signature.initSign(key.getPrivate()); signature.update(content); return signature.sign();
    }
    private static zeroecho.pkix.AlgorithmIdentifier libNative() { return zeroecho.pkix.AlgorithmIdentifier.absent(NATIVE_ALGORITHM.oid()); }
    private static IssuerKeyBinding role(KeyRef key, AlgorithmIdentity publicAlgorithm, AlgorithmIdentity signatureAlgorithm,
            zeroecho.pkix.AlgorithmIdentifier encoded, byte[] spki) {
        return new IssuerKeyBinding(key, publicAlgorithm, signatureAlgorithm, new EncodedObject(Encoding.DER, Pkix.encodeAlgorithmIdentifier(encoded)), digest(spki));
    }
    private static String digest(byte[] input) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input)); }
        catch (GeneralSecurityException impossible) { throw new IllegalStateException(impossible); }
    }
    private static DurableContentReference reference(String id, byte[] content) { return reference(id, content, DurableContentReference.Lifecycle.OPERATION); }
    private static DurableContentReference reference(String id, byte[] content, DurableContentReference.Lifecycle lifecycle) {
        return new Content("c036-public-fixture", id, Encoding.DER, content.length, digest(content), lifecycle);
    }
    private record Content(String storeId, String contentId, Encoding encoding, long length, String sha256,
            DurableContentReference.Lifecycle lifecycle) implements DurableContentReference { }
    private static CrlEntrySource emptyEntries() {
        return new CrlEntrySource() {
            @Override public Cursor openCursor() { return new Cursor() {
                @Override public boolean next() { return false; }
                @Override public zeroecho.pki.spi.framework.CrlEntry current() { throw new IllegalStateException("Empty snapshot"); }
                @Override public long ordinal() { return -1; }
                @Override public void close() { }
            }; }
            @Override public OptionalLong count() { return OptionalLong.of(0); }
            @Override public void close() { }
        };
    }
    private static X509AuthoritySnapshot authority(boolean privateCrl) {
        return X509AuthoritySnapshot.compose(privateCrl ? List.of(new PrivateCrlBinding()) : List.of(), List.of(),
                new X509AlgorithmResolver.Policy() {
                    @Override public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) {
                        return direction == AlgorithmExecutionCapability.Direction.VERIFY;
                    }
                    @Override public String semanticFingerprint() { return "c036-public-verification-only"; }
                });
    }

    private static X509ExecutionPlan<Object> publicPlan(String policyFingerprint, AlgorithmExecutionCapability.Direction direction, String bindingId) {
        AlgorithmExecutionCapability capability = new AlgorithmExecutionCapability() {
            @Override public String implementationId() { return "c036-plan-fixture"; }
            @Override public String domainFingerprint() { return "c036-plan-domain-v1"; }
            @Override public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction requested) {
                return identity.equals(BootstrapAlgorithmIdentities.ECDSA_SHA384);
            }
        };
        AlgorithmExecutionCapabilityProvider provider = () -> List.of(capability);
        // Plan commitments require real authority snapshots, not a signature dispatch.
        Object executor = new Object();
        var authority = X509AuthoritySnapshot.compose(List.of(), List.of(provider), List.of(
                X509AuthoritySnapshot.bindExecutor(capability.implementationId(), AlgorithmExecutionCapability.Direction.SIGN, executor),
                X509AuthoritySnapshot.bindExecutor(capability.implementationId(), AlgorithmExecutionCapability.Direction.VERIFY, executor)),
                new X509AlgorithmResolver.Policy() {
                    @Override public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction requested) { return true; }
                    @Override public String semanticFingerprint() { return policyFingerprint; }
                });
        return authority.plan(BootstrapAlgorithmIdentities.ECDSA_SHA384, BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY,
                direction, Optional.empty(), "explicit", bindingId, Object.class);
    }
    private static final class PrivateCrlBinding implements X509BindingRuleProvider, X509BindingRule {
        private static final X509AlgorithmBinding DESCRIPTOR = new X509AlgorithmBinding("example.crl.ecdsa.v1",
                BootstrapAlgorithmIdentities.ECDSA_SHA384, X509AlgorithmBinding.Role.CRL_SIGNATURE, "1.3.6.1.4.1.55555.77.9",
                X509AlgorithmBinding.Origin.DEPLOYER_PRIVATE, 1, X509AlgorithmBinding.ParameterRule.ABSENT,
                X509AlgorithmBinding.PublicKeyEncoding.NOT_APPLICABLE, X509AlgorithmBinding.SignatureEncoding.ECDSA_DER,
                X509AlgorithmBinding.Interoperability.DEPLOYER_ECOSYSTEM, Optional.of("example.crl"), "ecdsa-crl-v1");
        @Override public List<X509BindingRule> rules() { return List.of(this); }
        @Override public List<X509AlgorithmBinding> bindings() { return List.of(DESCRIPTOR); }
        @Override public String id() { return DESCRIPTOR.bindingId(); }
        @Override public X509AlgorithmRole role() { return X509AlgorithmRole.SIGNATURE_ALGORITHM; }
        @Override public String oid() { return DESCRIPTOR.oid(); }
        @Override public String semanticFingerprint() { return DESCRIPTOR.semanticCommitment(); }
        @Override public SignatureEncoding signatureEncoding() { return SignatureEncoding.ECDSA_DER; }
        @Override public PublicKeyEncoding publicKeyEncoding() { return PublicKeyEncoding.NOT_APPLICABLE; }
        @Override public Optional<X509AlgorithmIdentifier> encode(AlgorithmIdentity identity) {
            return BootstrapAlgorithmIdentities.ECDSA_SHA384.equals(identity) ? Optional.of(X509AlgorithmIdentifier.absent(oid())) : Optional.empty();
        }
        @Override public Optional<AlgorithmIdentity> decode(X509AlgorithmIdentifier identifier) {
            return X509AlgorithmIdentifier.absent(oid()).equals(identifier) ? Optional.of(BootstrapAlgorithmIdentities.ECDSA_SHA384) : Optional.empty();
        }
    }
}
