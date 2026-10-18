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
package zeroecho.pki.server.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.server.ForwardedCertificateFormat;
import zeroecho.pki.server.HttpServerTestSupport;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.PkiServerConfigurationCodec;

/** Hostile-input coverage for both explicit forwarded certificate formats. */
class ForwardedClientCertificateParserTest {
    @TempDir java.nio.file.Path temporaryDirectory;

    @Test
    void parsesStrictRfc9440LeafAndChain() throws Exception {
        System.out.println("parsesStrictRfc9440LeafAndChain");
        HttpServerTestSupport.Fixture fixture = HttpServerTestSupport.tls();
        PkiServerConfiguration.Authentication configuration = HttpServerTestSupport.proxyConfiguration(
                temporaryDirectory, fixture, ForwardedCertificateFormat.RFC9440).authentication();
        String leaf = item(fixture.forwardedCertificate());
        String root = item(fixture.rootCertificate());
        List<X509Certificate> parsed = ForwardedClientCertificateParser.parse(configuration,
                Map.of("Client-Cert", List.of(leaf), "Client-Cert-Chain", List.of(root)));
        assertEquals(2, parsed.size());
        assertEquals(fixture.forwardedCertificate(), parsed.getFirst());
        assertThrows(IllegalArgumentException.class, () -> ForwardedClientCertificateParser.parse(configuration,
                Map.of("Client-Cert", List.of(leaf, leaf))));
        assertThrows(IllegalArgumentException.class, () -> ForwardedClientCertificateParser.parse(configuration,
                Map.of("Client-Cert", List.of(leaf), "X-ZeroEcho-Client-Cert", List.of("ignored"))));
        assertThrows(IllegalArgumentException.class, () -> ForwardedClientCertificateParser.parse(configuration,
                Map.of("Client-Cert", List.of(leaf + ";foo=bar"))));
        System.out.println("...chain-count=" + parsed.size());
        System.out.println("...ok");
    }

    @Test
    void rejectsMalformedRfc9440ByteSequences() throws Exception {
        System.out.println("rejectsMalformedRfc9440ByteSequences");
        HttpServerTestSupport.Fixture fixture = HttpServerTestSupport.tls();
        PkiServerConfiguration.Authentication configuration = HttpServerTestSupport.proxyConfiguration(
                temporaryDirectory, fixture, ForwardedCertificateFormat.RFC9440).authentication();
        for (String malformed : List.of("", ":*:", ":Zg=:", ":Zm9v:trailing", "::")) {
            assertThrows(IllegalArgumentException.class, () -> ForwardedClientCertificateParser.parse(configuration,
                    Map.of("Client-Cert", List.of(malformed))));
        }
        System.out.println("...malformed-count=5");
        System.out.println("...ok");
    }

    @Test
    void parsesOnlyCanonicalNginxEscapedPem() throws Exception {
        System.out.println("parsesOnlyCanonicalNginxEscapedPem");
        HttpServerTestSupport.Fixture fixture = HttpServerTestSupport.tls();
        PkiServerConfiguration.Authentication configuration = HttpServerTestSupport.proxyConfiguration(
                temporaryDirectory, fixture, ForwardedCertificateFormat.NGINX_ESCAPED_PEM_V1).authentication();
        String pem = pem(fixture.forwardedCertificate());
        String escaped = escape(pem);
        assertEquals(fixture.forwardedCertificate(), ForwardedClientCertificateParser.parse(configuration,
                Map.of("X-ZeroEcho-Client-Cert", List.of(escaped))).getFirst());
        for (String malformed : List.of(pem, escaped + "%", escaped.replaceFirst("%0A", "+"),
                escaped + escaped, escape(pem.replace("CERTIFICATE", "PUBLIC KEY")))) {
            assertThrows(IllegalArgumentException.class, () -> ForwardedClientCertificateParser.parse(configuration,
                    Map.of("X-ZeroEcho-Client-Cert", List.of(malformed))));
        }
        System.out.println("...raw-pem-autodetection=false");
        System.out.println("...ok");
    }

    @Test
    void rejectsObsoleteConfigurationSchemaWithoutFallback() {
        System.out.println("rejectsObsoleteConfigurationSchemaWithoutFallback");
        byte[] obsolete = "{\"version\":1}".getBytes(StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class, () -> PkiServerConfigurationCodec.decode(obsolete));
        System.out.println("...current-schema=" + PkiServerConfiguration.CURRENT_VERSION);
        System.out.println("...ok");
    }

    private static String item(X509Certificate certificate) throws Exception {
        return ":" + Base64.getEncoder().encodeToString(certificate.getEncoded()) + ":";
    }

    private static String pem(X509Certificate certificate) throws Exception {
        String encoded = Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----\n";
    }

    private static String escape(String value) {
        StringBuilder result = new StringBuilder(value.length() * 3);
        for (byte item : value.getBytes(StandardCharsets.US_ASCII)) {
            int unsigned = item & 0xff;
            char character = (char) unsigned;
            if (character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
                    || character >= '0' && character <= '9' || character == '-' || character == '.'
                    || character == '_' || character == '~') {
                result.append(character);
            } else {
                result.append('%').append(HexFormat.of().withUpperCase().toHexDigits(item));
            }
        }
        return result.toString();
    }
}
