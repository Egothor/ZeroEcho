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
package zeroecho.pkix;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import zeroecho.pkix.cert.CertificateBuilder;
import zeroecho.pkix.spi.PkixProvider;

class PkixCertificateExtensionsTest {
    private static final String FIRST_OID = "1.3.6.1.4.1.55555.1";
    private static final String SECOND_OID = "1.3.6.1.4.1.55555.2";

    @Test
    void certificateExtensionsPreservePayloadAndCriticality() throws Exception {
        byte[] payload = {4, 3, 1, 2, 3};
        X509Certificate certificate = certificate(List.of(new CertificateExtension(FIRST_OID, false, payload),
                new CertificateExtension(SECOND_OID, true, new byte[] {5, 0})));
        List<CertificateExtension> extensions = Pkix.certificateExtensions(certificate);
        assertEquals(2, extensions.size());
        assertEquals(new CertificateExtension(FIRST_OID, false, payload), extensions.getFirst());
        assertEquals(new CertificateExtension(SECOND_OID, true, new byte[] {5, 0}), extensions.get(1));
        assertArrayEquals(payload, extensions.getFirst().derValue(), "Payload must not be OCTET STRING-wrapped again");
        byte[] copy = extensions.getFirst().derValue();
        copy[0] ^= 1;
        assertArrayEquals(payload, extensions.getFirst().derValue());
        assertThrows(UnsupportedOperationException.class, () -> extensions.clear());
    }

    @Test
    void certificateWithoutExtensionsReturnsEmptyList() throws Exception {
        assertEquals(List.of(), Pkix.certificateExtensions(certificate(List.of())));
    }

    @Test
    void certificateExtensionsRejectNullCertificate() {
        assertThrows(NullPointerException.class, () -> Pkix.certificateExtensions(null));
    }

    @Test
    void legacyProviderReportsUnsupportedExtensionInspection() throws Exception {
        // A legacy provider supplies its existing methods but inherits newly added SPI defaults.
        PkixProvider legacy = (PkixProvider) Proxy.newProxyInstance(PkixProvider.class.getClassLoader(),
                new Class<?>[] {PkixProvider.class}, (proxy, method, arguments) -> {
                    if (method.isDefault()) { return InvocationHandler.invokeDefault(proxy, method, arguments); }
                    throw new AssertionError("Extension inspection invoked an unrelated legacy method");
                });
        X509Certificate certificate = certificate(List.of());
        assertThrows(UnsupportedOperationException.class, () -> legacy.certificateExtensions(certificate));
    }

    private static X509Certificate certificate(List<CertificateExtension> extensions) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair key = generator.generateKeyPair();
        X500Principal name = new X500Principal("CN=Extension inspection");
        CertificateBuilder builder = Pkix.certificateBuilder().serialNumber(BigInteger.ONE)
                .subject(name).issuer(name).validity(Instant.parse("2026-01-01T00:00:00Z"),
                        Instant.parse("2027-01-01T00:00:00Z")).publicKey(key.getPublic());
        extensions.forEach(builder::addExtension);
        return builder.build(Pkix.signer(key.getPrivate(), AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11")));
    }
}
