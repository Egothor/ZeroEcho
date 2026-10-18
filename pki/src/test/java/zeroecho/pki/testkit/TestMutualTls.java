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
package zeroecho.pki.testkit;

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Deterministic mutual-TLS fixture for loopback remote-signing tests: a test root
 * CA issues a {@code localhost}/{@code 127.0.0.1} server certificate and a client
 * certificate, and exposes matching server and client {@link SSLContext}s plus a
 * writer for the PKCS#12 client keystore and trust store consumed by the
 * production provider configuration path.
 */
public final class TestMutualTls {

    /** Password protecting every generated keystore and key entry. */
    public static final char[] PASSWORD = "changeit".toCharArray();
    private static final String PROTOCOL = "TLSv1.3";

    private final X509Certificate root;
    private final X509Certificate serverCertificate;
    private final X509Certificate clientCertificate;
    private final KeyPair serverKey;
    private final KeyPair clientKey;

    private TestMutualTls(X509Certificate root, X509Certificate serverCertificate, KeyPair serverKey,
            X509Certificate clientCertificate, KeyPair clientKey) {
        this.root = root;
        this.serverCertificate = serverCertificate;
        this.serverKey = serverKey;
        this.clientCertificate = clientCertificate;
        this.clientKey = clientKey;
    }

    /**
     * Generates a fresh, self-consistent mutual-TLS fixture.
     *
     * @return a ready fixture
     * @throws Exception if key or certificate generation fails
     */
    public static TestMutualTls create() throws Exception {
        KeyPair rootKey = keyPair((byte) 11);
        X509Certificate root = certificate(rootKey, rootKey, "CN=ZeroEcho Remote Signing Test Root",
                "CN=ZeroEcho Remote Signing Test Root", BigInteger.valueOf(11), true, false);
        KeyPair serverKey = keyPair((byte) 12);
        X509Certificate server = certificate(serverKey, rootKey, "CN=localhost",
                "CN=ZeroEcho Remote Signing Test Root", BigInteger.valueOf(12), false, true);
        KeyPair clientKey = keyPair((byte) 13);
        X509Certificate client = certificate(clientKey, rootKey, "CN=zeroecho-pki-client",
                "CN=ZeroEcho Remote Signing Test Root", BigInteger.valueOf(13), false, false);
        return new TestMutualTls(root, server, serverKey, client, clientKey);
    }

    /**
     * @return a server context presenting the localhost identity and requiring the
     *         test client certificate
     * @throws Exception if the context cannot be built
     */
    public SSLContext serverContext() throws Exception {
        return context(serverKey, serverCertificate);
    }

    /**
     * @return a client context presenting the client identity and pinning the test root
     * @throws Exception if the context cannot be built
     */
    public SSLContext clientContext() throws Exception {
        return context(clientKey, clientCertificate);
    }

    /**
     * Writes the PKCS#12 client keystore and trust store the production provider
     * configuration expects.
     *
     * @param directory destination directory (created if absent)
     * @return the written client material
     * @throws Exception if the material cannot be written
     */
    public ClientMaterial writeClientMaterial(Path directory) throws Exception {
        Files.createDirectories(directory);
        Path keystore = directory.resolve("client-identity.p12");
        Path truststore = directory.resolve("remote-trust.p12");
        KeyStore identity = KeyStore.getInstance("PKCS12");
        identity.load(null, PASSWORD);
        identity.setKeyEntry("client", clientKey.getPrivate(), PASSWORD,
                new Certificate[] { clientCertificate, root });
        write(identity, keystore);
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, PASSWORD);
        trust.setCertificateEntry("root", root);
        write(trust, truststore);
        return new ClientMaterial(keystore, truststore);
    }

    private static void write(KeyStore store, Path path) throws Exception {
        try (OutputStream output = Files.newOutputStream(path)) {
            store.store(output, PASSWORD);
        }
    }

    private SSLContext context(KeyPair identity, X509Certificate certificate) throws Exception {
        KeyStore keys = KeyStore.getInstance("PKCS12");
        keys.load(null, PASSWORD);
        keys.setKeyEntry("identity", identity.getPrivate(), PASSWORD,
                new Certificate[] { certificate, root });
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keys, PASSWORD);
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, PASSWORD);
        trust.setCertificateEntry("root", root);
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trust);
        SSLContext context = SSLContext.getInstance(PROTOCOL);
        context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), SecureRandom.getInstanceStrong());
        return context;
    }

    private static KeyPair keyPair(byte identity) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        SecureRandom deterministic = SecureRandom.getInstance("SHA1PRNG");
        deterministic.setSeed(new byte[] { 2, 4, 6, 8, identity });
        generator.initialize(2048, deterministic);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(KeyPair subjectKey, KeyPair issuerKey, String subject, String issuer,
            BigInteger serial, boolean ca, boolean server) throws Exception {
        Instant before = Instant.parse("2026-01-01T00:00:00Z");
        Instant after = Instant.parse("2027-01-01T00:00:00Z");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name(issuer), serial,
                Date.from(before), Date.from(after), new X500Name(subject), subjectKey.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (server) {
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName[] { new GeneralName(GeneralName.dNSName, "localhost"),
                            new GeneralName(GeneralName.iPAddress, "127.0.0.1") }));
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate result = new JcaX509CertificateConverter().getCertificate(holder);
        result.verify(issuerKey.getPublic());
        return result;
    }

    /**
     * Paths to the written PKCS#12 client material.
     *
     * @param keystore client identity keystore
     * @param truststore trusted-issuer store
     */
    public record ClientMaterial(Path keystore, Path truststore) {
    }
}
