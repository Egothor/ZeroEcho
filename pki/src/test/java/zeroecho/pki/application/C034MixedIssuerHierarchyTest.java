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
import java.nio.file.Path;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.*;
import zeroecho.pki.api.hybrid.HybridCertificateMode;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.testkit.RootCreationFixture;

/** Native managed-key chains prove incoming and outgoing algorithms remain distinct in one realm. */
final class C034MixedIssuerHierarchyTest {
    @ParameterizedTest
    @CsvSource({"EC384,ECDSA,ML-DSA-87,ML-DSA", "ML-DSA-87,ML-DSA,RSA4096,RSA", "RSA4096,RSA,EC384,ECDSA"})
    void issuesAndReopensMixedAlgorithmRootIntermediateLeaf(String rootAlgorithm, String rootFamily,
            String childAlgorithm, String childFamily, @TempDir Path directory) throws Exception {
        AlgorithmIdentity rootSignature = signature(rootAlgorithm);
        AlgorithmIdentity childSignature = signature(childAlgorithm);
        HybridIssuanceFixture fixture = new HybridIssuanceFixture(directory, rootAlgorithm, rootFamily,
                rootSignature.canonicalForm(), HybridCertificateMode.None.INSTANCE, childAlgorithm, "ML-DSA-87");
        PkiId root;
        PkiId child;
        PkiId leaf;
        try (PkiSession session = fixture.open()) {
            fixture.execute(session, new PkiSigningOperation.CreateAuthority(HybridIssuanceFixture.X509,
                    new SubjectRef("CN=Mixed Root,C=CZ"), "matrix-root", HybridIssuanceFixture.key("root"),
                    Optional.of(rootSignature.canonicalForm())));
            root = fixture.store.listCas().getFirst().caId();
            RootCreationFixture.install(fixture.store, fixture.profile("mixed-child", 1,
                    CertificateProfileKind.INTERMEDIATE_CA, HybridCertificateMode.None.INSTANCE, Set.of(childFamily)));
            fixture.execute(session, new PkiSigningOperation.CreateIntermediate(HybridIssuanceFixture.X509, root,
                    new SubjectRef("CN=Mixed Child,C=CZ"), "mixed-child", Optional.of(HybridIssuanceFixture.key("child")),
                    Optional.of(childSignature.canonicalForm())));
            child = fixture.store.listCas().stream().filter(ca -> !ca.caId().equals(root)).findFirst().orElseThrow().caId();
            var childCertificate = fixture.certificate(fixture.current(child));
            childCertificate.verify(fixture.rootKey.getPublic(), "BC");
            assertArrayEquals(fixture.childKey.getPublic().getEncoded(), childCertificate.getPublicKey().getEncoded());
            var binding = fixture.store.getIssuerCryptographicBinding(fixture.store.getCa(child).orElseThrow().currentIssuanceIssuerId()).orElseThrow();
            assertEquals(childSignature, binding.primary().signatureAlgorithm());
            assertNotEquals(rootSignature, binding.primary().signatureAlgorithm());
            leaf = fixture.issueLeaf(session, child);
            fixture.certificate(leaf).verify(fixture.childKey.getPublic(), "BC");
            var certificate = fixture.certificate(leaf);
            assertThrows(java.security.GeneralSecurityException.class, () -> certificate.verify(fixture.rootKey.getPublic(), "BC"));
        }
        try (PkiSession reopened = fixture.open()) {
            assertTrue(reopened.signingCommands().isPresent());
            fixture.certificate(fixture.current(root)).verify(fixture.rootKey.getPublic(), "BC");
            fixture.certificate(fixture.current(child)).verify(fixture.rootKey.getPublic(), "BC");
            fixture.certificate(leaf).verify(fixture.childKey.getPublic(), "BC");
        }
    }
    private static AlgorithmIdentity signature(String algorithm) {
        return switch (algorithm) {
            case "EC384" -> BootstrapAlgorithmIdentities.ECDSA_SHA384;
            case "RSA4096" -> BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384;
            case "ML-DSA-87" -> BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE;
            default -> throw new IllegalArgumentException("Unsupported test algorithm");
        };
    }
}
