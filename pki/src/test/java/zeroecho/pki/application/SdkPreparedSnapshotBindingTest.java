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
    @Test void rejectsProfileChangeBetweenPreviewAndActualPreparationBeforeSigningOrStaging(@TempDir Path path) throws Exception {
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
            var operation = new PkiSigningOperation.IssueCredential(ca, parsed.primary().requestId(), "sdk-race");
            var commands = session.signingCommands().orElseThrow();
            var preview = commands.previewSdk(operation, RootCreationFixture.ACCESS, parsed, Optional.empty(), CancellationSignal.NONE);
            var target = target(preview);
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
        f.put(16, p.disclosurePolicy().encode()); f.put(17, HybridSdkValue.object(Map.of()).encode()); return new HybridSdkFrame(7, f);
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
