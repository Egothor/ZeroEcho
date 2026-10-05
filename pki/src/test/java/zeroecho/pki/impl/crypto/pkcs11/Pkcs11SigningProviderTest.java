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
package zeroecho.pki.impl.crypto.pkcs11;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.spi.crypto.SigningProvider;

class Pkcs11SigningProviderTest {
    @Test
    void rejectsStatefulAlgorithmsBeforeKeyLookupAndActualKeysBeforeProviderUse() throws Exception {
        TestStoreSpi spi = new TestStoreSpi();
        Provider engine = new Provider("test", "1", "No signature engine") { };
        KeyStore store = new KeyStore(spi, engine, "test") { };
        store.load(null, null);
        try (Pkcs11SigningProvider provider = new Pkcs11SigningProvider("test", store, engine,
                Set.of("SHA256withRSA", "LMS", "XMSS"),
                new SigningProvider.ConfigurationCommitment(new byte[32]),
                Duration.ofDays(1), "", "", 1)) {
            assertEquals(Set.of("SHA256withRSA"), provider.supportedAlgorithms());
            SigningProvider.CallControl control = new SigningProvider.CallControl(Instant.MAX, CancellationSignal.NONE);
            assertEquals(SigningProvider.DetailCode.INVALID_ALGORITHM,
                    provider.dispatch(request(provider, "LMS"), control).detailCode());
            assertEquals(0, spi.reads);
            assertEquals(SigningProvider.DetailCode.ALGORITHM_MISMATCH,
                    provider.dispatch(request(provider, "SHA256withRSA"), control).detailCode());
            assertEquals(1, spi.reads);
        }
    }

    private SigningProvider.SignRequest request(SigningProvider provider, String algorithm) {
        RepeatableContent content = (RepeatableContent) java.lang.reflect.Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] { RepeatableContent.class }, (proxy, method, args) -> {
                    throw new AssertionError("Content must not be read");
                });
        return SigningProvider.SignRequest.create(new PkiId("operation"), "store.test",
                provider.configurationCommitment(), 1,
                new AccessContext(new Principal("TEST", "owner"), new Purpose("TEST"), Optional.empty(), Optional.empty()),
                new KeyRef("key"), algorithm, SigningProvider.ContentCommitment.sha256(new byte[] { 1 }),
                content, Optional.of(Encoding.BINARY), Optional.empty());
    }

    private static final class TestStoreSpi extends java.security.KeyStoreSpi {
        private int reads;
        @Override public java.security.Key engineGetKey(String alias, char[] password) {
            reads++;
            return new PrivateKey() {
                public String getAlgorithm() { return "XMSS"; }
                public String getFormat() { return "PKCS#8"; }
                public byte[] getEncoded() { throw new AssertionError("Key must not be encoded"); }
            };
        }
        @Override public void engineLoad(java.io.InputStream stream, char[] password) { }
        @Override public java.security.cert.Certificate[] engineGetCertificateChain(String alias) { throw new AssertionError(); }
        @Override public java.security.cert.Certificate engineGetCertificate(String alias) { throw new AssertionError(); }
        @Override public java.util.Date engineGetCreationDate(String alias) { throw new AssertionError(); }
        @Override public void engineSetKeyEntry(String alias, java.security.Key key, char[] password,
                java.security.cert.Certificate[] chain) { throw new AssertionError(); }
        @Override public void engineSetKeyEntry(String alias, byte[] key, java.security.cert.Certificate[] chain) { throw new AssertionError(); }
        @Override public void engineSetCertificateEntry(String alias, java.security.cert.Certificate cert) { throw new AssertionError(); }
        @Override public void engineDeleteEntry(String alias) { throw new AssertionError(); }
        @Override public java.util.Enumeration<String> engineAliases() { throw new AssertionError(); }
        @Override public boolean engineContainsAlias(String alias) { throw new AssertionError(); }
        @Override public int engineSize() { throw new AssertionError(); }
        @Override public boolean engineIsKeyEntry(String alias) { throw new AssertionError(); }
        @Override public boolean engineIsCertificateEntry(String alias) { throw new AssertionError(); }
        @Override public String engineGetCertificateAlias(java.security.cert.Certificate cert) { throw new AssertionError(); }
        @Override public void engineStore(java.io.OutputStream stream, char[] password) { throw new AssertionError(); }
    }
}
