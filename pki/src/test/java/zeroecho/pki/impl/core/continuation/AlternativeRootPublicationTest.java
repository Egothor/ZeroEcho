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
package zeroecho.pki.impl.core.continuation;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.hybrid.HybridCertificateMode;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.impl.hybrid.AltSignatureExtensions;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.testkit.RootCreationFixture;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.cert.CertificateBuilder;

final class AlternativeRootPublicationTest {
    @ParameterizedTest
    @ValueSource(strings = {"missing", "partial", "empty", "changed-signature", "wrong-key", "changed-algorithm", "changed-spki"})
    void validPrimaryCannotPublishInvalidAlternative(String fault, @TempDir Path root) throws Exception {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        KeyPair primary = KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();
        KeyPair alternative = KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();
        KeyPair other = KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();
        AlgorithmIdentifier algorithm = AlgorithmIdentifier.absent("1.3.101.112");
        Instant before = Instant.parse("2026-10-01T00:00:00Z");
        Instant after = before.plusSeconds(3600);
        CertificateBuilder builder = Pkix.certificateBuilder().serialNumber(BigInteger.ONE)
                .issuer(new X500Principal("CN=Root")).subject(new X500Principal("CN=Root"))
                .validity(before, after).publicKey(primary.getPublic());
        if (!fault.equals("missing")) {
            builder.addExtension(AltSignatureExtensions.subjectAltPublicKeyInfo(
                    (fault.equals("changed-spki") ? other : alternative).getPublic().getEncoded()));
            builder.addExtension(AltSignatureExtensions.altSignatureAlgorithm(
                    fault.equals("changed-algorithm") ? AlgorithmIdentifier.absent("1.3.101.113") : algorithm));
            if (!fault.equals("partial")) {
                Signature signer = Signature.getInstance("Ed25519", "BC");
                signer.initSign((fault.equals("wrong-key") || fault.equals("changed-spki") ? other : alternative).getPrivate());
                signer.update(builder.buildAlternativeSignatureTbs());
                byte[] value = signer.sign();
                if (fault.equals("empty")) { value = new byte[0]; }
                if (fault.equals("changed-signature") || fault.equals("changed-spki")) { value[0] ^= 1; }
                builder.addExtension(AltSignatureExtensions.altSignatureValue(value));
            }
        }
        java.security.cert.X509Certificate certificate = builder.build(Pkix.signer(primary.getPrivate(), algorithm));
        certificate.verify(primary.getPublic(), "BC");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), RootCreationFixture.CLOCK)) {
            CertificateProfileDefinition base = RootCreationFixture.definition("alt-root", CertificateProfileKind.ROOT_CA,
                    Duration.ofDays(1), X509AlgorithmBindingPolicy.standardOnly());
            CertificateProfileDefinition definition = new CertificateProfileDefinition(base.certificateType(), base.profileId(),
                    base.profileVersion(), base.formatId(), base.displayName(), base.maximumValidity(), base.approvalRequirement(),
                    base.subjectPolicy(), base.certificatePolicy(), base.algorithmBindingPolicy(), Optional.empty(),
                    new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm(), "alt"));
            CertificateProfileRef profile = RootCreationFixture.install(store, definition);
            DomainContinuationTemplate template = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA, "CREATE_ROOT",
                    "x509", "CN=Root", "alt-root", "root-key", "alt-root", "1", HexFormat.of().formatHex(profile.canonicalSha256()),
                    before.toString(), after.toString(), "1", "CN=Root", "policy", "binding", "root-ca");
            CaContinuationPublisher publisher = new CaContinuationPublisher(store, new DomainContinuationPublisher(store));
            assertThrows(DomainContinuationPublisher.PostconditionFailure.class, () -> publisher.publish(
                    DomainCommandEncoding.decode(template.command()), new EncodedObject(Encoding.DER, certificate.getEncoded()), null));
            assertTrue(store.listCas().isEmpty());
        }
    }
}
