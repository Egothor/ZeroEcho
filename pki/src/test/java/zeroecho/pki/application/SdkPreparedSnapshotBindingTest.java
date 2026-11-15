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

package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.*;
import zeroecho.pki.api.hybrid.*;
import zeroecho.pki.api.hybrid.sdk.*;
import zeroecho.pki.api.profile.*;
import zeroecho.pki.spi.crypto.*;
import zeroecho.pki.spi.store.*;
import zeroecho.pki.testkit.*;

/** Actual retained proofs cannot authorize a different snapshot selected by a later policy read. */
final class SdkPreparedSnapshotBindingTest {
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"issue", "renew", "reissue", "replace"})
    void rejectsProfileChangeBetweenPreviewAndActualPreparationBeforeSigningOrStaging(String kind, @TempDir Path path) throws Exception {
        var fixture = new HybridIssuanceFixture(path, "EC384", "ECDSA", BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(),
                new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),
                        HybridIssuanceFixture.key("alt").value()), "EC384", "ML-DSA-87");
        AtomicBoolean armed = new AtomicBoolean();
        AtomicInteger issuerReads = new AtomicInteger(), stages = new AtomicInteger(), alternativeSigns = new AtomicInteger();
        fixture.storeDecorator = actual -> {
            var staged = proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
                if (armed.get() && method.getName().equals("beginContent")) stages.incrementAndGet();
            });
            return proxy(PkiStore.class, actual, (method, args) -> {
                if (armed.get() && method.getName().equals("getCa") && issuerReads.incrementAndGet() == 2) {
                    RootCreationFixture.install(actual, leaf(2));
                }
            }, staged);
        };
        fixture.signingDecorator = actual -> (SigningProvider) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{SigningProvider.class, PublicKeyInfoSource.class, AltSigningCapability.class}, (ignored, method, args) -> {
                    if (armed.get() && method.getName().equals("sign") && args.length == 3) alternativeSigns.incrementAndGet();
                    return invoke(actual, method, args);
                });
        try (PkiSession session = fixture.open()) {
            PkiId ca = fixture.create(session);
            RootCreationFixture.install(fixture.store, leaf(1));
            KeyPair primary = HybridIssuanceFixture.pair("EC384"), alternative = HybridIssuanceFixture.pair("ML-DSA-87");
            var extensions = new ExtensionsGenerator();
            extensions.addExtension(new ASN1ObjectIdentifier("2.5.29.72"), false, alternative.getPublic().getEncoded());
            byte[] csr = new JcaPKCS10CertificationRequestBuilder(new javax.security.auth.x500.X500Principal("CN=Client"), primary.getPublic())
                    .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate())
                    .build(new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BC").build(primary.getPrivate())).getEncoded();
            var parsed = HybridSdkProofs.parse(csr);
            var client = new Client(primary, alternative, csr, parsed);
            PkiId predecessor = kind.equals("issue") ? null : completeSdk(session,
                    new PkiSigningOperation.IssueCredential(ca, parsed.primary().requestId(), "sdk-race"), client);
            PkiSigningOperation operation = switch (kind) {
                case "issue" -> new PkiSigningOperation.IssueCredential(ca, parsed.primary().requestId(), "sdk-race");
                case "renew" -> new PkiSigningOperation.RenewCredential(predecessor);
                case "reissue" -> new PkiSigningOperation.ReissueCredential(predecessor);
                case "replace" -> new PkiSigningOperation.ReplaceCredential(predecessor, parsed.primary().requestId(), "sdk-race");
                default -> throw new AssertionError(kind);
            };
            var commands = session.signingCommands().orElseThrow();
            var preview = commands.previewSdk(operation, RootCreationFixture.ACCESS, parsed, Optional.empty(), CancellationSignal.NONE);
            var target = target(preview, operation);
            var first = first(parsed, csr, target);
            byte[] primaryProof = sign(primary, "SHA384withECDSA", first.encode());
            byte[] alternativeProof = sign(alternative, "ML-DSA-87", new HybridSdkFrame(2, first.fields()).encode());
            var approval = new SdkIssuanceApproval(preview, first, target, primaryProof, alternativeProof,
                    HybridSdkProofs.verify(parsed, first, primaryProof, alternativeProof, HybridIssuanceFixture.CLOCK.instant()),
                    HybridIssuanceFixture.CLOCK.instant());
            armed.set(true);
            var failure = assertThrows(PkiException.class, () -> commands.prepareSdk(operation, RootCreationFixture.ACCESS,
                    parsed, approval, Optional.empty(), CancellationSignal.NONE));
            assertEquals("SDK_FROZEN_TARGET_MISMATCH", failure.getMessage());
            assertEquals(2, fixture.store.requireActiveProfile("sdk-race").reference().profileVersion());
            assertEquals(0, alternativeSigns.get());
            assertEquals(0, stages.get());
        }
    }
    @Test void enrollmentTargetSurvivesActualPreparationAndRejectsPolicySubstitution(@TempDir Path path) throws Exception {
        var fixture = fixture(path);
        var signingCalls = new AtomicInteger();
        fixture.signingDecorator = provider -> (SigningProvider) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{SigningProvider.class, PublicKeyInfoSource.class, AltSigningCapability.class}, (ignored, method, args) -> {
                    if (method.getName().equals("sign") || method.getName().equals("dispatch")) signingCalls.incrementAndGet();
                    return invoke(provider, method, args);
                });
        try (var session = fixture.open()) {
            PkiId ca = fixture.create(session);
            RootCreationFixture.install(fixture.store, leaf(1));
            var client = client();
            var operation = new PkiSigningOperation.IssueCredential(ca, client.parsed().primary().requestId(), "sdk-race");
            var commands = session.signingCommands().orElseThrow();
            var ordinary = commands.previewSdk(operation, RootCreationFixture.ACCESS, client.parsed(), Optional.empty(), CancellationSignal.NONE);
            assertArrayEquals(HybridSdkValue.object(Map.of()).encode(), ordinary.targetExtensionValue().encode());
            var enrollment = new zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget(1, "EST", "endpoint", 1,
                    "0".repeat(64), "policy", 1, "1".repeat(64), "ISSUE",
                    zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10, "2".repeat(64), "sha512:" + "3".repeat(128));
            var preview = commands.previewSdk((PkiSigningOperation) operation, RootCreationFixture.ACCESS, client.parsed(),
                    Optional.empty(), Optional.of(enrollment), CancellationSignal.NONE);
            var signedTarget = target(preview, operation);
            var proof = approval(preview, signedTarget, client);
            var changed = new zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget(1, "EST", "endpoint", 1,
                    "0".repeat(64), "policy", 2, "4".repeat(64), "ISSUE",
                    zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10, "2".repeat(64), "sha512:" + "3".repeat(128));
            var changedPreview = commands.previewSdk((PkiSigningOperation) operation, RootCreationFixture.ACCESS, client.parsed(),
                    Optional.of(preview.validity()), Optional.of(changed), CancellationSignal.NONE);
            var altered = new SdkIssuanceApproval(changedPreview, proof.primaryFrame(), proof.targetFrame(),
                    proof.primaryProof(), proof.alternativeProof(), proof.expectedF3(), proof.proofAcceptedAt());
            assertThrows(PkiException.class, () -> commands.prepareSdk(operation, RootCreationFixture.ACCESS, client.parsed(),
                    altered, Optional.empty(), CancellationSignal.NONE));
            var service = session.semanticSigning().orElseThrow();
            var intent = new zeroecho.pki.api.issuance.IssuanceIntent("enrollment-sdk-1", "5".repeat(64),
                    preview.profile(), preview.issuerId(), preview.chainPathId(), preview.chainPathCommitment());
            var correlated = new zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest(
                    new zeroecho.pki.api.issuance.EndEntityIssuanceRequest(ca, client.parsed().originalPayload(), "sdk-race", Optional.empty()), intent);
            var prepared = assertInstanceOf(zeroecho.pki.api.issuance.CorrelatedIssuancePreparation.Prepared.class,
                    service.prepareSdk(RootCreationFixture.ACCESS, correlated, client.parsed(), proof, Optional.empty(), CancellationSignal.NONE));
            var accepted = service.accept(prepared.prepared());
            var retainedBinding = service.issuanceBinding(correlated);
            assertEquals(intent.issuanceId(), retainedBinding.issuanceId());
            assertEquals(preview.issuerId(), retainedBinding.expectedIssuerId());
            assertEquals(preview.chainPathCommitment(), retainedBinding.expectedChainPathCommitment());
            assertEquals(accepted.receipt().operationId(), service.findIssuance(retainedBinding).orElseThrow().submissionId().id());
            assertInstanceOf(LocalSigningResult.Completed.class,
                    session.localSigning().orElseThrow().complete(accepted.receipt().operationId(), CancellationSignal.NONE));
            int signedBeforeReplay = signingCalls.get();
            var replay = assertInstanceOf(zeroecho.pki.api.issuance.CorrelatedIssuancePreparation.Existing.class,
                    service.prepareSdk(RootCreationFixture.ACCESS, correlated, client.parsed(), proof, Optional.empty(), CancellationSignal.NONE));
            assertEquals(accepted.receipt().operationId(), replay.operation().submissionId().id());
            assertEquals(signedBeforeReplay, signingCalls.get());
            assertNotEquals(intent.commandCommitment(), retainedBinding.effectiveCommitment());
            var alteredIntent = new zeroecho.pki.api.issuance.IssuanceIntent(intent.issuanceId(), "6".repeat(64),
                    preview.profile(), preview.issuerId(), preview.chainPathId(), preview.chainPathCommitment());
            var conflicting = new zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest(correlated.request(), alteredIntent);
            assertThrows(PkiException.class, () -> service.prepareSdk(RootCreationFixture.ACCESS, conflicting, client.parsed(),
                    proof, Optional.empty(), CancellationSignal.NONE));
            byte[] badProof = proof.primaryProof(); badProof[badProof.length - 1] ^= 1;
            var invalid = new SdkIssuanceApproval(preview, proof.primaryFrame(), proof.targetFrame(), badProof,
                    proof.alternativeProof(), proof.expectedF3(), proof.proofAcceptedAt());
            assertThrows(PkiException.class, () -> service.prepareSdk(RootCreationFixture.ACCESS, correlated, client.parsed(),
                    invalid, Optional.empty(), CancellationSignal.NONE));
        }
    }

    @Test void lifecycleKeepsBothSubjectKeysAndVerifiesOriginalIssuerAfterBothIssuerRolesRotate(@TempDir Path path) throws Exception {
        var fixture = fixture(path);
        var oldKeysUnavailable = new AtomicBoolean();
        var signingCalls = new AtomicInteger();
        fixture.signingDecorator = provider -> (SigningProvider) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{SigningProvider.class, PublicKeyInfoSource.class, AltSigningCapability.class}, (ignored, method, args) -> {
                    if (method.getName().equals("sign") || method.getName().equals("dispatch")) signingCalls.incrementAndGet();
                    KeyRef key = null;
                    if (method.getName().equals("dispatch")) key = ((SigningProvider.SignRequest) args[0]).keyRef();
                    else if (method.getName().equals("resolvePublicKeyInfo") || method.getName().equals("sign")) key = (KeyRef) args[0];
                    if (oldKeysUnavailable.get() && (HybridIssuanceFixture.key("child").equals(key)
                            || HybridIssuanceFixture.key("other-alt").equals(key))) {
                        throw new IllegalStateException("Retired issuer managed key unavailable");
                    }
                    return invoke(provider, method, args);
                });
        byte[] originalBytes;
        PkiId renewed, reissued, replacement;
        try (var session = fixture.open()) {
            PkiId root = fixture.create(session);
            RootCreationFixture.install(fixture.store, fixture.profile("sdk-child", 1, CertificateProfileKind.INTERMEDIATE_CA,
                    new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),
                            HybridIssuanceFixture.key("other-alt").value())));
            fixture.execute(session, new PkiSigningOperation.CreateIntermediate(HybridIssuanceFixture.X509, root,
                    new SubjectRef("CN=SDK Child,C=CZ"), "sdk-child", Optional.of(HybridIssuanceFixture.key("child")),
                    Optional.of(BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm())));
            PkiId child = fixture.store.listCas().stream().filter(ca -> !ca.caId().equals(root)).findFirst().orElseThrow().caId();
            RootCreationFixture.install(fixture.store, leaf(1));
            var client = client();
            PkiId original = completeSdk(session, new PkiSigningOperation.IssueCredential(child, client.parsed().primary().requestId(), "sdk-race"), client);
            originalBytes = fixture.certificate(original).getEncoded();
            var old = fixture.store.getCredential(original).orElseThrow();
            var oldBinding = fixture.store.getIssuerCryptographicBinding(old.issuerRef().issuerId()).orElseThrow();
            var head = fixture.store.getCaHeadSnapshot(child).orElseThrow();
            var selection = new zeroecho.pki.api.ca.CaRotationSelection(1,
                    Optional.of(new zeroecho.pki.api.ca.CaRotationSelection.RoleChange(Optional.of(HybridIssuanceFixture.key("rotated")), Optional.empty())),
                    Optional.of(new zeroecho.pki.api.ca.CaRotationSelection.RoleChange(Optional.of(HybridIssuanceFixture.key("rotated-alt")), Optional.empty())));
            fixture.execute(session, new PkiSigningOperation.RotateCaKey(child, selection, Optional.of(root), Optional.of(head)));
            oldKeysUnavailable.set(true);
            var renew = new PkiSigningOperation.RenewCredential(original);
            var preview = session.signingCommands().orElseThrow().previewSdk((PkiSigningOperation) renew, RootCreationFixture.ACCESS,
                    client.parsed(), Optional.empty(), CancellationSignal.NONE);
            assertNotEquals(old.issuerRef().issuerId(), preview.issuerId());
            assertEquals(original, preview.lifecycleTarget().orElseThrow().predecessorId());
            assertArrayEquals(client.primary().getPublic().getEncoded(), preview.primarySubjectSpki().bytes());
            assertArrayEquals(client.alternative().getPublic().getEncoded(), preview.alternativeSubjectSpki().bytes());
            renewed = completeCorrelatedSdkLifecycle(session, renew, client, signingCalls);
            reissued = completeSdk(session, new PkiSigningOperation.ReissueCredential(renewed), client);
            for (PkiId id : List.of(renewed, reissued)) {
                var certificate = fixture.certificate(id);
                certificate.verify(fixture.rotatedKey.getPublic(), "BC");
                assertTrue(zeroecho.pkix.Pkix.verifyAlternativeSignatureCor3(certificate, fixture.rotatedAltKey.getPublic()));
                assertArrayEquals(client.primary().getPublic().getEncoded(), certificate.getPublicKey().getEncoded());
                assertArrayEquals(client.alternative().getPublic().getEncoded(), zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(certificate, "2.5.29.72"));
            }
            var newClient = client();
            replacement = completeCorrelatedSdkLifecycle(session, new PkiSigningOperation.ReplaceCredential(reissued, newClient.parsed().primary().requestId(), "sdk-race"), newClient, signingCalls);
            var replaced = fixture.certificate(replacement);
            replaced.verify(fixture.rotatedKey.getPublic(), "BC");
            assertTrue(zeroecho.pkix.Pkix.verifyAlternativeSignatureCor3(replaced, fixture.rotatedAltKey.getPublic()));
            assertArrayEquals(newClient.primary().getPublic().getEncoded(), replaced.getPublicKey().getEncoded());
            assertArrayEquals(newClient.alternative().getPublic().getEncoded(), zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(replaced, "2.5.29.72"));
            assertArrayEquals(originalBytes, fixture.certificate(original).getEncoded());
            assertEquals(oldBinding, fixture.store.getIssuerCryptographicBinding(old.issuerRef().issuerId()).orElseThrow());
        }
        try (var reopened = fixture.open()) {
            assertTrue(reopened.signingCommands().isPresent());
            for (PkiId id : List.of(renewed, reissued, replacement)) {
                var certificate = fixture.certificate(id);
                certificate.verify(fixture.rotatedKey.getPublic(), "BC");
                assertTrue(zeroecho.pkix.Pkix.verifyAlternativeSignatureCor3(certificate, fixture.rotatedAltKey.getPublic()));
            }
        }
    }

    @Test void rejectsChangedRenewalTupleAndRevokedPrimaryReuseButAllowsNewReplacementKeys(@TempDir Path path) throws Exception {
        var fixture = fixture(path);
        var armed = new AtomicBoolean(); var signs = new AtomicInteger();
        fixture.signingDecorator = provider -> (SigningProvider) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{SigningProvider.class, PublicKeyInfoSource.class, AltSigningCapability.class}, (ignored, method, args) -> {
                    if (armed.get() && method.getName().equals("sign")) signs.incrementAndGet();
                    return invoke(provider, method, args);
                });
        try (var session = fixture.open()) {
            PkiId root = fixture.create(session); RootCreationFixture.install(fixture.store, leaf(1));
            var old = client();
            PkiId credential = completeSdk(session, new PkiSigningOperation.IssueCredential(root, old.parsed().primary().requestId(), "sdk-race"), old);
            var changedAlternative = client(old.primary(), HybridIssuanceFixture.pair("ML-DSA-87"));
            var changedPrimary = client(HybridIssuanceFixture.pair("EC384"), old.alternative());
            armed.set(true);
            var commands = session.signingCommands().orElseThrow();
            assertThrows(PkiException.class, () -> commands.previewSdk((PkiSigningOperation) new PkiSigningOperation.RenewCredential(credential),
                    RootCreationFixture.ACCESS, changedAlternative.parsed(), Optional.empty(), CancellationSignal.NONE));
            assertThrows(PkiException.class, () -> commands.previewSdk((PkiSigningOperation) new PkiSigningOperation.ReissueCredential(credential),
                    RootCreationFixture.ACCESS, changedPrimary.parsed(), Optional.empty(), CancellationSignal.NONE));
            assertThrows(PkiException.class, () -> commands.prepare(new PkiSigningOperation.RenewCredential(credential),
                    RootCreationFixture.ACCESS, Optional.empty(), CancellationSignal.NONE));
            fixture.store.transitionRevocation(new zeroecho.pki.api.revocation.RevocationCommand.RevokePermanently(credential,
                    zeroecho.pki.api.revocation.RevocationReason.KEY_COMPROMISE, new zeroecho.pki.impl.core.attr.SimpleAttributeSet()), HybridIssuanceFixture.CLOCK.instant());
            assertThrows(PkiException.class, () -> commands.previewSdk(new PkiSigningOperation.ReplaceCredential(credential,
                    changedAlternative.parsed().primary().requestId(), "sdk-race"), RootCreationFixture.ACCESS,
                    changedAlternative.parsed(), Optional.empty(), CancellationSignal.NONE));
            assertEquals(0, signs.get());
            var fresh = client();
            PkiId replacement = completeSdk(session, new PkiSigningOperation.ReplaceCredential(credential, fresh.parsed().primary().requestId(), "sdk-race"), fresh);
            fixture.certificate(replacement).verify(fixture.rootKey.getPublic(), "BC");
            assertEquals(1, signs.get());
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"wrong-operation", "wrong-predecessor", "wrong-alternative-proof"})
    void rejectsProofTargetSubstitutionBeforeAnyAlternativeSigning(String fault, @TempDir Path path) throws Exception {
        var fixture = fixture(path);
        var armed = new AtomicBoolean(); var signs = new AtomicInteger(); var stages = new AtomicInteger();
        fixture.signingDecorator = provider -> (SigningProvider) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{SigningProvider.class, PublicKeyInfoSource.class, AltSigningCapability.class}, (ignored, method, args) -> {
                    if (armed.get() && method.getName().equals("sign")) signs.incrementAndGet();
                    return invoke(provider, method, args);
                });
        fixture.storeDecorator = actual -> proxy(PkiStore.class, actual, (method, args) -> { },
                proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
                    if (armed.get() && method.getName().equals("beginContent")) stages.incrementAndGet();
                }));
        try (var session = fixture.open()) {
            PkiId root = fixture.create(session); RootCreationFixture.install(fixture.store, leaf(1));
            var client = client();
            PkiId predecessor = completeSdk(session, new PkiSigningOperation.IssueCredential(root, client.parsed().primary().requestId(), "sdk-race"), client);
            PkiSigningOperation operation = new PkiSigningOperation.RenewCredential(predecessor);
            var commands = session.signingCommands().orElseThrow();
            var preview = commands.previewSdk(operation, RootCreationFixture.ACCESS, client.parsed(), Optional.empty(), CancellationSignal.NONE);
            var target = target(preview, operation);
            if (!fault.equals("wrong-alternative-proof")) {
                var fields = new TreeMap<>(target.fields()); var lifecycle = preview.lifecycleTarget().orElseThrow();
                var changed = new SdkLifecycleTarget(1, fault.equals("wrong-operation") ? "credential.reissue" : lifecycle.operation(),
                        fault.equals("wrong-predecessor") ? new PkiId("x509:" + "0".repeat(64)) : lifecycle.predecessorId(),
                        lifecycle.predecessorSha256(), lifecycle.subjectPrimarySpkiSha512(), lifecycle.subjectAlternativeSpkiSha512());
                fields.put(1, text(changed.operation())); fields.put(17, changed.value().encode()); target = new HybridSdkFrame(7, fields);
            }
            var valid = approval(preview, target, client);
            byte[] alternative = valid.alternativeProof();
            if (fault.equals("wrong-alternative-proof")) alternative = sign(HybridIssuanceFixture.pair("ML-DSA-87"), "ML-DSA-87",
                    new HybridSdkFrame(2, valid.primaryFrame().fields()).encode());
            var retained = new SdkIssuanceApproval(preview, valid.primaryFrame(), target, valid.primaryProof(), alternative,
                    valid.expectedF3(), valid.proofAcceptedAt());
            armed.set(true);
            assertThrows(PkiException.class, () -> commands.prepareSdk(operation, RootCreationFixture.ACCESS, client.parsed(),
                    retained, Optional.empty(), CancellationSignal.NONE));
            assertEquals(0, signs.get()); assertEquals(0, stages.get());
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"native", "alternative"})
    void rejectsInvalidOriginalSignaturesAtStorageOrLifecycleBoundary(String fault, @TempDir Path path) throws Exception {
        var fixture = fixture(path); var armed = new AtomicBoolean(); var signs = new AtomicInteger();
        fixture.signingDecorator = provider -> (SigningProvider) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{SigningProvider.class, PublicKeyInfoSource.class, AltSigningCapability.class}, (ignored, method, args) -> {
                    if (armed.get() && method.getName().equals("sign")) signs.incrementAndGet();
                    return invoke(provider, method, args);
                });
        try (var session = fixture.open()) {
            PkiId root = fixture.create(session); RootCreationFixture.install(fixture.store, leaf(1)); var client = client();
            PkiId original = completeSdk(session, new PkiSigningOperation.IssueCredential(root, client.parsed().primary().requestId(), "sdk-race"), client);
            var metadata = fixture.store.getCredential(original).orElseThrow(); var certificate = fixture.certificate(original);
            var builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(certificate.getIssuerX500Principal(),
                    certificate.getSerialNumber().add(java.math.BigInteger.ONE), certificate.getNotBefore(), certificate.getNotAfter(),
                    certificate.getSubjectX500Principal(), certificate.getPublicKey());
            var holder = new org.bouncycastle.cert.X509CertificateHolder(certificate.getEncoded());
            for (var oid : holder.getExtensions().getExtensionOIDs()) {
                var extension = holder.getExtension(oid);
                if (fault.equals("alternative") && oid.getId().equals("2.5.29.74")) {
                    byte[] alternative = ASN1BitString.getInstance(extension.getExtnValue().getOctets()).getBytes(); alternative[0] ^= 1;
                    builder.addExtension(oid, extension.isCritical(), new DERBitString(alternative));
                } else builder.addExtension(extension);
            }
            byte[] der = builder.build(new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BC")
                    .build(fault.equals("native") ? fixture.rotatedKey.getPrivate() : fixture.rootKey.getPrivate())).getEncoded();
            if (fault.equals("alternative")) zeroecho.pkix.Pkix.parseCertificate(der).verify(fixture.rootKey.getPublic(), "BC");
            var id = new PkiId("x509:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(der)));
            var content = PkiTestRuntime.stageCredential(fixture.store, der);
            var corrupted = new zeroecho.pki.api.credential.Credential(id, metadata.formatId(), metadata.issuerRef(),
                    metadata.subjectRef(), metadata.validity(), certificate.getSerialNumber().add(java.math.BigInteger.ONE).toString(),
                    metadata.publicKeyId(), metadata.profileBinding(), metadata.status(), content, metadata.attributes());
            if (fault.equals("native")) {
                var rejected = assertThrows(IllegalStateException.class, () -> fixture.store.putCredential(corrupted));
                assertEquals("X.509 credential issuer signature differs", rejected.getMessage());
                assertEquals(0, signs.get());
                return;
            }
            fixture.store.putCredential(corrupted);
            armed.set(true);
            var failure = assertThrows(PkiException.class, () -> session.signingCommands().orElseThrow().previewSdk(
                    (PkiSigningOperation) new PkiSigningOperation.RenewCredential(id), RootCreationFixture.ACCESS, client.parsed(),
                    Optional.empty(), CancellationSignal.NONE));
            assertTrue(failure.getMessage().contains(fault.equals("native") ? "PREDECESSOR_SIGNATURE_INVALID"
                    : "PREDECESSOR_ALTERNATIVE_SIGNATURE_INVALID"));
            assertEquals(0, signs.get());
        }
    }

    @Test void activeSingleKeyProfileCannotBypassHybridPredecessorDualProofRequirement(@TempDir Path path) throws Exception {
        var fixture = fixture(path); var armed = new AtomicBoolean(); var signs = new AtomicInteger(); var stages = new AtomicInteger();
        fixture.signingDecorator = provider -> (SigningProvider) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{SigningProvider.class, PublicKeyInfoSource.class, AltSigningCapability.class}, (ignored, method, args) -> {
                    if (armed.get() && method.getName().equals("sign")) signs.incrementAndGet();
                    return invoke(provider, method, args);
                });
        fixture.storeDecorator = actual -> proxy(PkiStore.class, actual, (method, args) -> { },
                proxy(StagedContentStore.class, actual.stagedContent(), (method, args) -> {
                    if (armed.get() && method.getName().equals("beginContent")) stages.incrementAndGet();
                }));
        try (var session = fixture.open()) {
            PkiId root = fixture.create(session); RootCreationFixture.install(fixture.store, leaf(1)); var client = client();
            PkiId predecessor = completeSdk(session, new PkiSigningOperation.IssueCredential(root, client.parsed().primary().requestId(), "sdk-race"), client);
            PkiId ordinaryRequest = session.requests().orElseThrow().store(client.parsed().primary(),
                    zeroecho.pki.api.request.RequestStorePolicy.STORE_ALWAYS);
            assertEquals(client.parsed().primary().requestId(), ordinaryRequest);
            var operations = List.<PkiSigningOperation>of(new PkiSigningOperation.RenewCredential(predecessor),
                    new PkiSigningOperation.ReissueCredential(predecessor),
                    new PkiSigningOperation.ReplaceCredential(predecessor, client.parsed().primary().requestId(), "sdk-race"));
            var commands = session.signingCommands().orElseThrow(); var approvals = new ArrayList<SdkIssuanceApproval>();
            for (var operation : operations) {
                var preview = commands.previewSdk(operation, RootCreationFixture.ACCESS, client.parsed(), Optional.empty(), CancellationSignal.NONE);
                approvals.add(approval(preview, target(preview, operation), client));
            }
            var base = leaf(2);
            RootCreationFixture.install(fixture.store, new CertificateProfileDefinition(base.certificateType(), base.profileId(), base.profileVersion(),
                    base.formatId(), base.displayName(), base.maximumValidity(), base.approvalRequirement(), base.subjectPolicy(),
                    base.certificatePolicy(), base.algorithmBindingPolicy(), base.confirmationPolicy(), HybridCertificateMode.None.INSTANCE));
            armed.set(true);
            for (int index = 0; index < operations.size(); index++) {
                var operation = operations.get(index); var accepted = approvals.get(index);
                var ordinary = assertThrows(PkiException.class, () -> commands.prepare(operation, RootCreationFixture.ACCESS,
                        Optional.empty(), CancellationSignal.NONE));
                assertTrue(ordinary.getMessage().contains("SDK_DUAL_PROOF_REQUIRED"));
                assertThrows(PkiException.class, () -> commands.prepareSdk(operation, RootCreationFixture.ACCESS, client.parsed(),
                        accepted, Optional.empty(), CancellationSignal.NONE));
            }
            assertEquals(HybridCertificateMode.None.INSTANCE, fixture.store.requireActiveProfile("sdk-race").definition().hybridMode());
            assertEquals(0, signs.get()); assertEquals(0, stages.get());
        }
    }

    private static HybridIssuanceFixture fixture(Path path) throws Exception {
        return new HybridIssuanceFixture(path, "EC384", "ECDSA", BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(),
                new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),
                        HybridIssuanceFixture.key("alt").value()), "EC384", "ML-DSA-87");
    }

    private record Client(KeyPair primary, KeyPair alternative, byte[] csr, ParsedHybridSdkRequest parsed) { }

    private static Client client() throws Exception {
        return client(HybridIssuanceFixture.pair("EC384"), HybridIssuanceFixture.pair("ML-DSA-87"));
    }

    private static Client client(KeyPair primary, KeyPair alternative) throws Exception {
        var extensions = new ExtensionsGenerator();
        extensions.addExtension(new ASN1ObjectIdentifier("2.5.29.72"), false, alternative.getPublic().getEncoded());
        byte[] csr = new JcaPKCS10CertificationRequestBuilder(new javax.security.auth.x500.X500Principal("CN=Client"), primary.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate())
                .build(new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BC").build(primary.getPrivate())).getEncoded();
        return new Client(primary, alternative, csr, HybridSdkProofs.parse(csr));
    }

    private static SdkIssuanceApproval approval(SdkIssuancePreview preview, HybridSdkFrame target, Client client) throws Exception {
        var original = first(client.parsed(), client.csr(), target);
        var fields = new TreeMap<>(original.fields());
        for (int tag = 3; tag <= 6; tag++) { byte[] nonce = new byte[32]; new SecureRandom().nextBytes(nonce); fields.put(tag, nonce); }
        var frame = new HybridSdkFrame(1, fields);
        byte[] primary = sign(client.primary(), "SHA384withECDSA", frame.encode());
        byte[] alternative = sign(client.alternative(), "ML-DSA-87", new HybridSdkFrame(2, frame.fields()).encode());
        return new SdkIssuanceApproval(preview, frame, target, primary, alternative,
                HybridSdkProofs.verify(client.parsed(), frame, primary, alternative, HybridIssuanceFixture.CLOCK.instant()),
                HybridIssuanceFixture.CLOCK.instant());
    }

    private static PkiId completeCorrelatedSdkLifecycle(PkiSession session, PkiSigningOperation operation,
            Client client, AtomicInteger signingCalls) throws Exception {
        var commands = session.signingCommands().orElseThrow();
        var service = session.semanticSigning().orElseThrow();
        var preview = commands.previewSdk(operation, RootCreationFixture.ACCESS, client.parsed(), Optional.empty(), CancellationSignal.NONE);
        var proof = approval(preview, target(preview, operation), client);
        boolean renewal = operation instanceof PkiSigningOperation.RenewCredential;
        PkiId predecessor = renewal ? ((PkiSigningOperation.RenewCredential) operation).credentialId()
                : ((PkiSigningOperation.ReplaceCredential) operation).existingCredentialId();
        var predecessorRecord = session.repository().credential(predecessor).orElseThrow();
        String predecessorDigest = predecessorRecord.content().sha256();
        var intent = new zeroecho.pki.api.issuance.IssuanceIntent(renewal ? "sdk-correlated-renew" : "sdk-correlated-replace",
                "7".repeat(64), preview.profile(), preview.issuerId(), preview.chainPathId(), preview.chainPathCommitment());
        var renewed = new zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest(preview.issuerCaId(),
                new zeroecho.pki.api.issuance.EndEntityRenewalRequest(predecessor, Optional.empty()), predecessorDigest,
                intent, Optional.of(client.parsed().originalPayload()));
        var replaced = new zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest(preview.issuerCaId(),
                new zeroecho.pki.api.issuance.EndEntityReplacementRequest(predecessor, client.parsed().originalPayload(), "sdk-race"),
                predecessorDigest, intent);
        var preparation = renewal
                ? service.prepareSdk(RootCreationFixture.ACCESS, renewed, client.parsed(), proof, Optional.empty(), CancellationSignal.NONE)
                : service.prepareSdk(RootCreationFixture.ACCESS, replaced, client.parsed(), proof, Optional.empty(), CancellationSignal.NONE);
        var prepared = assertInstanceOf(zeroecho.pki.api.issuance.CorrelatedIssuancePreparation.Prepared.class, preparation);
        var accepted = service.accept(prepared.prepared());
        assertEquals(accepted.receipt().operationId(), (renewal ? service.findRenewal(renewed) : service.findReplacement(replaced))
                .orElseThrow().submissionId().id());
        var completed = assertInstanceOf(LocalSigningResult.Completed.class,
                session.localSigning().orElseThrow().complete(accepted.receipt().operationId(), CancellationSignal.NONE));
        int beforeReplay = signingCalls.get();
        var replay = renewal
                ? service.prepareSdk(RootCreationFixture.ACCESS, renewed, client.parsed(), proof, Optional.empty(), CancellationSignal.NONE)
                : service.prepareSdk(RootCreationFixture.ACCESS, replaced, client.parsed(), proof, Optional.empty(), CancellationSignal.NONE);
        assertEquals(accepted.receipt().operationId(), assertInstanceOf(
                zeroecho.pki.api.issuance.CorrelatedIssuancePreparation.Existing.class, replay).operation().submissionId().id());
        assertEquals(beforeReplay, signingCalls.get());
        String changedDigest = predecessorDigest.equals("0".repeat(64)) ? "1".repeat(64) : "0".repeat(64);
        if (renewal) {
            var changed = new zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest(preview.issuerCaId(), renewed.request(),
                    changedDigest, intent, renewed.originalRequest());
            assertThrows(PkiException.class, () -> service.prepareSdk(RootCreationFixture.ACCESS, changed, client.parsed(), proof,
                    Optional.empty(), CancellationSignal.NONE));
        } else {
            var changed = new zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest(preview.issuerCaId(), replaced.request(),
                    changedDigest, intent);
            assertThrows(PkiException.class, () -> service.prepareSdk(RootCreationFixture.ACCESS, changed, client.parsed(), proof,
                    Optional.empty(), CancellationSignal.NONE));
        }
        assertEquals(beforeReplay, signingCalls.get());
        return new PkiId(((PkiOperationValue.Text) completed.result().fields().get("credentialId")).value());
    }

    private static PkiId completeSdk(PkiSession session, PkiSigningOperation operation, Client client) throws Exception {
        var commands = session.signingCommands().orElseThrow();
        var preview = commands.previewSdk(operation, RootCreationFixture.ACCESS, client.parsed(), Optional.empty(), CancellationSignal.NONE);
        var proof = approval(preview, target(preview, operation), client);
        var prepared = commands.prepareSdk(operation, RootCreationFixture.ACCESS, client.parsed(), proof, Optional.empty(), CancellationSignal.NONE);
        var accepted = session.semanticSigning().orElseThrow().accept(prepared);
        var result = assertInstanceOf(LocalSigningResult.Completed.class,
                session.localSigning().orElseThrow().complete(accepted.receipt().operationId(), CancellationSignal.NONE));
        var id = new PkiId(((PkiOperationValue.Text) result.result().fields().get("credentialId")).value());
        assertEquals(preview.validity().notBefore(), session.repository().credential(id).orElseThrow().validity().notBefore());
        assertEquals(preview.validity().notAfter(), session.repository().credential(id).orElseThrow().validity().notAfter());
        return id;
    }

    private static HybridSdkFrame target(SdkIssuancePreview preview, PkiSigningOperation operation) {
        var fields = new TreeMap<>(target(preview).fields());
        Map<String, HybridSdkValue> arguments = switch (operation) {
            case PkiSigningOperation.IssueCredential value -> Map.of("issuerCaId", HybridSdkValue.text(value.issuerCaId().value()),
                    "requestId", HybridSdkValue.text(value.requestId().value()), "profileId", HybridSdkValue.text(value.profileId()));
            case PkiSigningOperation.RenewCredential value -> Map.of("credentialId", HybridSdkValue.text(value.credentialId().value()));
            case PkiSigningOperation.ReissueCredential value -> Map.of("credentialId", HybridSdkValue.text(value.credentialId().value()));
            case PkiSigningOperation.ReplaceCredential value -> Map.of("existingCredentialId", HybridSdkValue.text(value.existingCredentialId().value()),
                    "requestId", HybridSdkValue.text(value.requestId().value()), "profileId", HybridSdkValue.text(value.profileId()));
            default -> throw new AssertionError("Unsupported test lifecycle operation");
        };
        fields.put(1, text(operation.name())); fields.put(2, HybridSdkValue.object(arguments).encode());
        fields.put(17, preview.targetExtensionValue().encode());
        return new HybridSdkFrame(7, fields);
    }

    private static CertificateProfileDefinition leaf(long version) {
        var base = CertificateProfileDocumentCodec.parse(H7ProfileDocuments.noSanOrEkuProfile());
        var source = (LeafCertificatePolicy) base.certificatePolicy();
        var policy = new LeafCertificatePolicy(source.subjectAlternativeNamePolicy(), source.keyUsages(), source.extendedKeyUsages(),
                source.keyUsageCritical(), source.extendedKeyUsageCritical(), source.basicConstraintsCritical(), Set.of("ECDSA"));
        return new CertificateProfileDefinition(base.certificateType(), "sdk-race", version, base.formatId(), "SDK race",
                base.maximumValidity(), base.approvalRequirement(), base.subjectPolicy(), policy, base.algorithmBindingPolicy(),
                base.confirmationPolicy(), HybridCertificateMode.AltSignature.requested(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm()));
    }
    private static HybridSdkFrame target(SdkIssuancePreview p) {
        var f = new TreeMap<Integer, byte[]>();
        f.put(1, text("credential.issue")); f.put(2, HybridSdkValue.object(Map.of()).encode()); f.put(3, text("actor"));
        f.put(4, text(p.issuerCaId().value())); f.put(5, text(p.issuerId().value())); f.put(6, text(p.chainPathId().value()));
        f.put(7, text("sha512:" + p.issuerCertificateSha512())); f.put(8, p.primaryIssuerBindingFrame().encode());
        f.put(9, p.alternativeIssuerBindingFrame().orElseThrow().encode()); f.put(10, text(p.profile().profileId()));
        f.put(11, ByteBuffer.allocate(8).putLong(p.profile().profileVersion()).array());
        f.put(12, text("sha256:" + HexFormat.of().formatHex(p.profile().canonicalSha256()))); f.put(13, text(p.bindingSetCommitment()));
        f.put(14, text("sha256:" + "0".repeat(64))); f.put(15, p.effectiveSubjectValue().encode());
        f.put(16, p.disclosurePolicy().encode()); f.put(17, p.targetExtensionValue().encode()); return new HybridSdkFrame(7, f);
    }
    private static HybridSdkFrame first(ParsedHybridSdkRequest p, byte[] csr, HybridSdkFrame target) {
        var f = new TreeMap<Integer, byte[]>(); f.put(1, text("zeroecho-hybrid-sdk-v1")); f.put(2, text("race-realm"));
        for (int i = 3; i <= 6; i++) { byte[] nonce = new byte[32]; nonce[0] = (byte) i; f.put(i, nonce); }
        long now = HybridIssuanceFixture.CLOCK.instant().getEpochSecond();
        f.put(7, ByteBuffer.allocate(8).putLong(now).array()); f.put(8, ByteBuffer.allocate(8).putLong(now + 300).array());
        f.put(9, text("https://example.invalid:443")); f.put(10, text("admin-http-v1")); f.put(11, HybridSdkFrame.hash(csr)); f.put(12, new byte[64]);
        f.put(13, HybridSdkFrame.hash(p.primary().publicKeyInfo().bytes())); f.put(14, HybridSdkFrame.hash(p.alternativeSubjectPublicKeyInfo().bytes()));
        f.put(15, HybridSdkFrame.primaryAlgorithm()); f.put(16, HybridSdkFrame.alternativeAlgorithm()); f.put(17, HybridSdkFrame.hash(target.encode()));
        return new HybridSdkFrame(1, f);
    }
    private static byte[] sign(KeyPair key, String algorithm, byte[] bytes) throws Exception {
        Signature signer = Signature.getInstance(algorithm, "BC"); signer.initSign(key.getPrivate()); signer.update(bytes); return signer.sign();
    }
    private static byte[] text(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static Object invoke(Object target, Method method, Object[] args) throws Throwable {
        try { return method.invoke(target, args); } catch (InvocationTargetException failure) { throw failure.getCause(); }
    }
    @FunctionalInterface private interface Before { void run(Method method, Object[] args) throws Exception; }
    private static <T> T proxy(Class<T> type, T target, Before before) { return proxy(type, target, before, null); }
    private static <T> T proxy(Class<T> type, T target, Before before, StagedContentStore staging) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (ignored, method, args) -> {
            before.run(method, args);
            if (staging != null && method.getName().equals("stagedContent")) return staging;
            return invoke(target, method, args);
        }));
    }
}
