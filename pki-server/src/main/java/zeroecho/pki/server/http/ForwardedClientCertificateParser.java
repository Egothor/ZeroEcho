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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import zeroecho.pki.server.ForwardedCertificateFormat;
import zeroecho.pki.server.PkiServerConfiguration;

/** Narrow strict parser for the two explicitly supported forwarded-certificate formats. */
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.AvoidLiteralsInIfCondition", "PMD.CyclomaticComplexity",
        "PMD.AvoidDeeplyNestedIfStmts", "PMD.ExceptionAsFlowControl",
        "PMD.AvoidThrowingNewInstanceOfSameException", "PMD.PreserveStackTrace",
        "PMD.AvoidReassigningLoopVariables" })
final class ForwardedClientCertificateParser {
    /* default */ static final String RFC_CERTIFICATE_HEADER = "Client-Cert";
    /* default */ static final String RFC_CHAIN_HEADER = "Client-Cert-Chain";
    /* default */ static final String DIRECT_REJECTED_NGINX_HEADER = "X-ZeroEcho-Client-Cert";
    private static final String PEM_BEGIN = "-----BEGIN CERTIFICATE-----\n";
    private static final String PEM_END = "\n-----END CERTIFICATE-----\n";

    private ForwardedClientCertificateParser() {
    }

    /* default */ static List<X509Certificate> parse(PkiServerConfiguration.Authentication configuration,
            Map<String, List<String>> headers) {
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(headers, "headers");
        ForwardedCertificateFormat format = configuration.forwardedCertificateFormat().orElseThrow();
        if (format == ForwardedCertificateFormat.RFC9440
                && present(headers, DIRECT_REJECTED_NGINX_HEADER)
                || format == ForwardedCertificateFormat.NGINX_ESCAPED_PEM_V1
                && (present(headers, RFC_CERTIFICATE_HEADER) || present(headers, RFC_CHAIN_HEADER)
                        || !DIRECT_REJECTED_NGINX_HEADER.equalsIgnoreCase(
                                configuration.forwardedCertificateHeaderName().orElseThrow())
                        && present(headers, DIRECT_REJECTED_NGINX_HEADER))) {
            throw new IllegalArgumentException("Conflicting forwarded certificate representation");
        }
        String leafValue = singleton(headers, configuration.forwardedCertificateHeaderName().orElseThrow(), true);
        List<byte[]> encoded = new ArrayList<>();
        if (format == ForwardedCertificateFormat.RFC9440) {
            encoded.add(byteSequence(leafValue, configuration.maximumForwardedCertificateBytes()));
            String chainValue = singleton(headers,
                    configuration.forwardedCertificateChainHeaderName().orElseThrow(), false);
            if (chainValue != null) {
                int total = 0;
                for (String item : chainValue.split(",", -1)) {
                    byte[] certificate = byteSequence(item.strip(), configuration.maximumForwardedChainBytes());
                    total = Math.addExact(total, certificate.length);
                    if (total > configuration.maximumForwardedChainBytes() || encoded.size() >= 64) {
                        throw new IllegalArgumentException("Forwarded certificate chain is oversized");
                    }
                    encoded.add(certificate);
                }
            }
        } else {
            encoded.add(escapedPem(leafValue, configuration.maximumForwardedCertificateBytes()));
        }
        List<X509Certificate> result = new ArrayList<>(encoded.size());
        for (byte[] certificate : encoded) result.add(certificate(certificate));
        return List.copyOf(result);
    }

    /* default */ static boolean containsForwardedIdentity(Map<String, List<String>> headers) {
        return present(headers, RFC_CERTIFICATE_HEADER) || present(headers, RFC_CHAIN_HEADER)
                || present(headers, DIRECT_REJECTED_NGINX_HEADER);
    }

    private static String singleton(Map<String, List<String>> headers, String name, boolean required) {
        List<String> matches = new ArrayList<>();
        int matchingNames = 0;
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                matchingNames++;
                matches.addAll(entry.getValue());
            }
        }
        if (matchingNames > 1 || matches.size() > 1 || required && matches.isEmpty()) {
            throw new IllegalArgumentException("Forwarded certificate header cardinality is invalid");
        }
        return matches.isEmpty() ? null : matches.getFirst();
    }

    private static boolean present(Map<String, List<String>> headers, String name) {
        return headers.keySet().stream().anyMatch(candidate -> candidate.equalsIgnoreCase(name));
    }

    private static byte[] byteSequence(String source, int maximum) {
        if (source.length() < 3 || source.charAt(0) != ':' || source.charAt(source.length() - 1) != ':'
                || source.indexOf(';') >= 0 || source.indexOf(' ') >= 0 || source.indexOf('\t') >= 0) {
            throw new IllegalArgumentException("RFC 9440 certificate field is malformed");
        }
        String encoded = source.substring(1, source.length() - 1);
        if (encoded.isEmpty() || encoded.length() > Math.multiplyExact(maximum, 2)) {
            throw new IllegalArgumentException("RFC 9440 certificate field is oversized");
        }
        try {
            byte[] result = Base64.getDecoder().decode(encoded);
            if (result.length == 0 || result.length > maximum
                    || !Base64.getEncoder().encodeToString(result).equals(encoded)) {
                throw new IllegalArgumentException("RFC 9440 certificate byte sequence is not canonical");
            }
            return result;
        } catch (IllegalArgumentException failure) {
            throw new IllegalArgumentException("RFC 9440 certificate byte sequence is invalid");
        }
    }

    private static byte[] escapedPem(String source, int maximum) {
        if (source.length() > Math.multiplyExact(maximum, 4) || source.indexOf('+') >= 0) {
            throw new IllegalArgumentException("NGINX forwarded certificate is invalid");
        }
        byte[] decoded = percentDecode(source);
        String pem = new String(decoded, StandardCharsets.US_ASCII);
        if (!Arrays.equals(decoded, pem.getBytes(StandardCharsets.US_ASCII)) || !pem.startsWith(PEM_BEGIN)
                || !pem.endsWith(PEM_END) || pem.indexOf(PEM_BEGIN, 1) >= 0
                || pem.indexOf(PEM_END) != pem.lastIndexOf(PEM_END)) {
            throw new IllegalArgumentException("NGINX forwarded PEM framing is invalid");
        }
        String base64 = pem.substring(PEM_BEGIN.length(), pem.length() - PEM_END.length());
        String[] lines = base64.split("\\n", -1);
        StringBuilder canonical = new StringBuilder(base64.length());
        for (int index = 0; index < lines.length; index++) {
            String line = lines[index];
            if (line.isEmpty() || line.length() > 64 || index + 1 < lines.length && line.length() != 64) {
                throw new IllegalArgumentException("NGINX forwarded PEM is not canonical");
            }
            canonical.append(line);
        }
        try {
            byte[] result = Base64.getDecoder().decode(canonical.toString());
            if (result.length == 0 || result.length > maximum
                    || !Base64.getEncoder().encodeToString(result).equals(canonical.toString())) {
                throw new IllegalArgumentException("NGINX forwarded PEM payload is not canonical");
            }
            return result;
        } catch (IllegalArgumentException failure) {
            throw new IllegalArgumentException("NGINX forwarded PEM payload is invalid");
        }
    }

    private static byte[] percentDecode(String source) {
        byte[] output = new byte[source.length()];
        int length = 0;
        for (int index = 0; index < source.length(); index++) {
            char current = source.charAt(index);
            int value;
            if (current == '%') {
                if (index + 2 >= source.length()) throw new IllegalArgumentException("Percent escape is truncated");
                value = hexadecimal(source.charAt(++index)) * 16 + hexadecimal(source.charAt(++index));
            } else {
                if (current > 0x7e || !unreserved(current)) {
                    throw new IllegalArgumentException("Escaped PEM contains unescaped data");
                }
                value = current;
            }
            if (value == 0 || value < 0x20 && value != '\n' || value == 0x7f) {
                throw new IllegalArgumentException("Escaped PEM contains a control character");
            }
            output[length++] = (byte) value;
        }
        return Arrays.copyOf(output, length);
    }

    private static int hexadecimal(char value) {
        int digit = Character.digit(value, 16);
        if (digit < 0) throw new IllegalArgumentException("Percent escape is malformed");
        return digit;
    }

    private static boolean unreserved(char value) {
        return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
                || value >= '0' && value <= '9' || value == '-' || value == '.' || value == '_'
                || value == '~';
    }

    private static X509Certificate certificate(byte[] encoded) {
        try {
            ByteArrayInputStream input = new ByteArrayInputStream(encoded);
            X509Certificate result = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
            if (input.available() != 0 || !Arrays.equals(encoded, result.getEncoded())) {
                throw new IllegalArgumentException("Forwarded certificate is not canonical DER");
            }
            return result;
        } catch (java.security.cert.CertificateException failure) {
            throw new IllegalArgumentException("Forwarded certificate is malformed");
        }
    }
}
