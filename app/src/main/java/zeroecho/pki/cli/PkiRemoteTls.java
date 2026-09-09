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
package zeroecho.pki.cli;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * Builds a mutual-TLS {@link SSLContext} from CLI-supplied client identity and
 * server trust material, using only the JDK (no BouncyCastle, no new dependency).
 *
 * <p>The client key comes from either a PKCS#12 keystore or a PEM certificate and
 * PKCS#8 private key pair. Server trust comes from an optional PKCS#12 or PEM CA
 * bundle; when omitted, the platform default trust store is used. Keystore and
 * truststore passwords are read from environment variables, never from the command
 * line.</p>
 */
final class PkiRemoteTls {

    private static final int MAXIMUM_MATERIAL_BYTES = 4 * 1_048_576;
    private static final String PEM_CERTIFICATE_MARKER = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PEM_KEY_FOOTER = "-----END PRIVATE KEY-----";
    private static final List<String> KEY_ALGORITHMS = List.of("RSA", "EC", "EdDSA", "DSA");

    private PkiRemoteTls() {
    }

    /**
     * Creates a mutual-TLS context for the supplied target.
     *
     * @param target validated connection target
     * @param environment resolver for password environment variables
     * @return an initialized TLS context
     * @throws IOException on unreadable material or a missing password variable
     * @throws GeneralSecurityException on invalid key, certificate, or store material
     */
    /* default */ static SSLContext createContext(PkiRemoteTarget target, Function<String, String> environment)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(environment, "environment");
        KeyManagerFactory keyManagers = target.usesPemClientIdentity()
                ? pemKeyManagers(target.clientCertificate().orElseThrow(), target.clientKey().orElseThrow())
                : keystoreKeyManagers(target.clientKeystore().orElseThrow(),
                        password(target.clientKeystorePasswordEnv(), environment));
        TrustManager[] trustManagers = target.trustStore().isPresent()
                ? trustManagers(target.trustStore().orElseThrow(),
                        password(target.trustStorePasswordEnv(), environment))
                : null;
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagers.getKeyManagers(), trustManagers, null);
        return context;
    }

    // Password is one mutable secret buffer that is wiped; varargs would misrepresent ownership.
    @SuppressWarnings("PMD.UseVarargs")
    private static KeyManagerFactory keystoreKeyManagers(Path keystore, char[] password)
            throws IOException, GeneralSecurityException {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            try (ByteArrayInputStream input = new ByteArrayInputStream(read(keystore))) {
                store.load(input, password);
            }
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(store, password);
            return factory;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static KeyManagerFactory pemKeyManagers(Path certificatePath, Path keyPath)
            throws IOException, GeneralSecurityException {
        Certificate[] chain = readCertificates(read(certificatePath)).toArray(new Certificate[0]);
        if (chain.length == 0) {
            throw new GeneralSecurityException("Client certificate PEM contained no certificate");
        }
        PrivateKey key = readPrivateKey(read(keyPath));
        char[] empty = new char[0];
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, empty);
        store.setKeyEntry("client", key, empty, chain);
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(store, empty);
        return factory;
    }

    // Password is one mutable secret buffer that is wiped; varargs would misrepresent ownership.
    @SuppressWarnings("PMD.UseVarargs")
    private static TrustManager[] trustManagers(Path trustStore, char[] password)
            throws IOException, GeneralSecurityException {
        try {
            byte[] material = read(trustStore);
            KeyStore store = KeyStore.getInstance("PKCS12");
            if (new String(material, StandardCharsets.US_ASCII).contains(PEM_CERTIFICATE_MARKER)) {
                store.load(null, new char[0]);
                int index = 0;
                for (Certificate certificate : readCertificates(material)) {
                    store.setCertificateEntry("ca-" + index, certificate);
                    index++;
                }
            } else {
                try (ByteArrayInputStream input = new ByteArrayInputStream(material)) {
                    store.load(input, password);
                }
            }
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(store);
            return factory.getTrustManagers();
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static Collection<? extends Certificate> readCertificates(byte[] material)
            throws GeneralSecurityException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (ByteArrayInputStream input = new ByteArrayInputStream(material)) {
            return factory.generateCertificates(input);
        } catch (IOException failure) {
            throw new GeneralSecurityException("Certificate material could not be read", failure);
        }
    }

    private static PrivateKey readPrivateKey(byte[] material) throws GeneralSecurityException {
        // Locate markers in the raw bytes to avoid copying key material into an immutable String.
        byte[] headerBytes = PEM_KEY_HEADER.getBytes(StandardCharsets.US_ASCII);
        byte[] footerBytes = PEM_KEY_FOOTER.getBytes(StandardCharsets.US_ASCII);
        int begin = indexOf(material, headerBytes);
        int end = indexOf(material, footerBytes);
        if (begin < 0 || end < 0) {
            throw new GeneralSecurityException("Client key must be an unencrypted PKCS#8 PEM (BEGIN PRIVATE KEY)");
        }
        int bodyStart = begin + headerBytes.length;
        // Strip whitespace from the base64 body region.
        byte[] body = Arrays.copyOfRange(material, bodyStart, end);
        String base64 = new String(body, StandardCharsets.US_ASCII).replaceAll("\\s", "");
        Arrays.fill(body, (byte) 0);
        byte[] pkcs8 = Base64.getDecoder().decode(base64);
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
            GeneralSecurityException last = null;
            for (String algorithm : KEY_ALGORITHMS) {
                try {
                    return KeyFactory.getInstance(algorithm).generatePrivate(spec);
                } catch (GeneralSecurityException attempt) {
                    last = attempt;
                }
            }
            throw new GeneralSecurityException("Unsupported client private key algorithm", last);
        } finally {
            Arrays.fill(pkcs8, (byte) 0);
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            if (matchesAt(haystack, needle, i)) {
                return i;
            }
        }
        return -1;
    }

    private static boolean matchesAt(byte[] haystack, byte[] needle, int offset) {
        int index = 0;
        while (index < needle.length && haystack[offset + index] == needle[index]) {
            index++;
        }
        return index == needle.length;
    }

    private static char[] password(Optional<String> environmentVariable, Function<String, String> environment)
            throws IOException {
        if (environmentVariable.isEmpty()) {
            return new char[0];
        }
        String name = environmentVariable.orElseThrow();
        String value = environment.apply(name);
        if (value == null) {
            throw new IOException("Password environment variable is not set");
        }
        return value.toCharArray();
    }

    private static byte[] read(Path path) throws IOException {
        return PkiCliFiles.readRegularFile(path, MAXIMUM_MATERIAL_BYTES);
    }
}
