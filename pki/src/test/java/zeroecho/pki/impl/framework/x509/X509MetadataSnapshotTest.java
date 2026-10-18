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

package zeroecho.pki.impl.framework.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;

class X509MetadataSnapshotTest {
    @Test
    void everyDescriptorAliasResolvesTheSameExactEncoding() {
        X509BindingCatalog catalog = StandardX509Bindings.catalog();
        for (X509BindingRule rule : catalog.rules()) {
            for (X509AlgorithmBinding binding : rule.bindings()) {
                assertEquals(rule.encode(binding.algorithmIdentity()).orElseThrow(),
                        catalog.resolve(binding.bindingId(), binding.algorithmIdentity(), rule.role()));
                assertEquals(rule.encode(binding.algorithmIdentity()).orElseThrow(),
                        catalog.resolve(binding.algorithmIdentity(), rule.role()));
            }
            assertSame(rule.bindings(), rule.bindings());
            assertThrows(UnsupportedOperationException.class, () -> rule.bindings().add(null));
        }
        assertSame(StandardX509Bindings.descriptors(), StandardX509Bindings.descriptors());
        assertThrows(UnsupportedOperationException.class, () -> StandardX509Bindings.descriptors().add(null));
    }

    @Test
    void extensionMetadataIsSnapshottedOnceAcrossLookupsAndMerges() {
        AtomicInteger calls = new AtomicInteger();
        List<X509AlgorithmBinding> mutable = new ArrayList<>();
        X509BindingRule provider = rule("example.extension", mutable, calls, false);
        X509BindingCatalog extension = X509BindingCatalog.extension(List.of(provider));
        X509BindingCatalog merged = StandardX509Bindings.catalog().merge(List.of(extension));
        mutable.add(StandardX509Bindings.descriptors().getFirst());
        for (int index = 0; index < 3; index++) {
            merged.resolve(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                    X509AlgorithmRole.SIGNATURE_ALGORITHM);
            merged.resolve("zeroecho.signature.rsa-pkcs1-sha256",
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, X509AlgorithmRole.SIGNATURE_ALGORITHM);
        }
        assertEquals(1, calls.get());
        assertEquals(List.of(), extension.rules().getFirst().bindings());
    }

    @Test
    void fixedHitStillChecksExtensionAmbiguityInEitherMergeOrder() {
        X509BindingCatalog extension = X509BindingCatalog.extension(List.of(
                rule("example.overlap", List.of(), new AtomicInteger(), true)));
        X509BindingCatalog standards = StandardX509Bindings.catalog();
        for (X509BindingCatalog catalog : List.of(standards.merge(List.of(extension)),
                extension.merge(List.of(standards)))) {
            assertThrows(IllegalArgumentException.class, () -> catalog.resolve(
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, X509AlgorithmRole.SIGNATURE_ALGORITHM));
        }
    }

    @Test
    void descriptorAliasesCannotShadowAnotherRuleOrDescriptor() {
        X509AlgorithmBinding binding = StandardX509Bindings.descriptors().getFirst();
        X509BindingCatalog extension = X509BindingCatalog.extension(List.of(
                rule("example.alias", List.of(binding), new AtomicInteger(), false)));
        assertThrows(IllegalArgumentException.class,
                () -> StandardX509Bindings.catalog().merge(List.of(extension)));
    }

    @Test
    void parameterizedFallbackAndUnknownInputsRetainTheirContracts() {
        X509BindingCatalog catalog = StandardX509Bindings.catalog();
        AlgorithmIdentity pss = BootstrapAlgorithmIdentities.rsaPss(
                BootstrapAlgorithmIdentities.SHA384, BootstrapAlgorithmIdentities.SHA256, 48);
        assertEquals(pss, catalog.reverse(catalog.resolve(pss, X509AlgorithmRole.SIGNATURE_ALGORITHM),
                X509AlgorithmRole.SIGNATURE_ALGORITHM));
        assertThrows(IllegalArgumentException.class, () -> catalog.resolve("unknown", pss,
                X509AlgorithmRole.SIGNATURE_ALGORITHM));
        assertThrows(IllegalArgumentException.class, () -> catalog.resolve("zeroecho.spki.rsa", pss,
                X509AlgorithmRole.SIGNATURE_ALGORITHM));
        assertThrows(IllegalArgumentException.class, () -> catalog.resolve("zeroecho.signature.rsa-pkcs1-sha256",
                BootstrapAlgorithmIdentities.ED448_SIGNATURE, X509AlgorithmRole.SIGNATURE_ALGORITHM));
    }

    @Test
    void privateOnlyDescriptorsStayExplicitOnly() {
        X509AlgorithmBinding binding = new X509AlgorithmBinding("example.private-alias",
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE,
                "1.3.6.1.4.1.31424.1.2.999", X509AlgorithmBinding.Origin.ZEROECHO_PRIVATE, 1,
                X509AlgorithmBinding.ParameterRule.ABSENT, X509AlgorithmBinding.PublicKeyEncoding.NOT_APPLICABLE,
                X509AlgorithmBinding.SignatureEncoding.OPAQUE,
                X509AlgorithmBinding.Interoperability.ZEROECHO_ECOSYSTEM, Optional.empty(), "private-rule");
        X509BindingCatalog catalog = X509BindingCatalog.extension(List.of(
                rule("example.private", List.of(binding), new AtomicInteger(), true)));
        assertEquals(binding.oid(), catalog.resolve(binding.bindingId(), binding.algorithmIdentity(),
                X509AlgorithmRole.SIGNATURE_ALGORITHM).oid());
        assertThrows(IllegalArgumentException.class, () -> catalog.resolve(binding.algorithmIdentity(),
                X509AlgorithmRole.SIGNATURE_ALGORITHM));
    }

    private static X509BindingRule rule(String id, List<X509AlgorithmBinding> bindings,
            AtomicInteger calls, boolean overlaps) {
        return new X509BindingRule() {
            @Override public String id() { return id; }
            @Override public X509AlgorithmRole role() { return X509AlgorithmRole.SIGNATURE_ALGORITHM; }
            @Override public String oid() { return "1.3.6.1.4.1.31424.1.2.999"; }
            @Override public String semanticFingerprint() { return id; }
            @Override public SignatureEncoding signatureEncoding() { return SignatureEncoding.OPAQUE; }
            @Override public PublicKeyEncoding publicKeyEncoding() { return PublicKeyEncoding.NOT_APPLICABLE; }
            @Override public List<X509AlgorithmBinding> bindings() {
                calls.incrementAndGet();
                return bindings;
            }
            @Override public Optional<X509AlgorithmIdentifier> encode(AlgorithmIdentity identity) {
                return overlaps && BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.equals(identity)
                        ? Optional.of(X509AlgorithmIdentifier.absent(oid())) : Optional.empty();
            }
            @Override public Optional<AlgorithmIdentity> decode(X509AlgorithmIdentifier identifier) {
                return Optional.empty();
            }
        };
    }
}
