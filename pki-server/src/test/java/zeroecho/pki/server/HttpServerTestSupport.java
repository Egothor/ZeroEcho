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
package zeroecho.pki.server;

import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

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

import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.server.http.TestTlsProvider;
import zeroecho.pki.server.http.TestClientTrustProvider;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.store.MetadataStoreId;

/** Shared deterministic TLS, realm and server configuration fixtures. */
public final class HttpServerTestSupport {
    static final char[] PASSWORD = "test-password".toCharArray();

    private HttpServerTestSupport() { }

    public static Fixture tls() throws Exception {
        KeyPair rootKey = keyPair((byte) 1);
        X509Certificate root = certificate(rootKey, rootKey, "CN=ZeroEcho Test Root", "CN=ZeroEcho Test Root",
                BigInteger.ONE, true, false);
        KeyPair serverKey = keyPair((byte) 2);
        X509Certificate server = certificate(serverKey, rootKey, "CN=localhost", "CN=ZeroEcho Test Root",
                BigInteger.TWO, false, true);
        KeyPair clientKey = keyPair((byte) 3);
        X509Certificate client = certificate(clientKey, rootKey, "CN=client", "CN=ZeroEcho Test Root",
                BigInteger.valueOf(3), false, false);
        SSLContext serverContext = context(serverKey, server, root, true);
        SSLContext clientContext = context(clientKey, client, root, true);
        SSLContext anonymousContext = context(clientKey, client, root, false);
        KeyPair proxyKey = keyPair((byte) 4);
        X509Certificate proxy = certificate(proxyKey, rootKey, "CN=proxy", "CN=ZeroEcho Test Root",
                BigInteger.valueOf(4), false, false);
        SSLContext proxyContext = context(proxyKey, proxy, root, true);
        KeyPair forwardedKey = keyPair((byte) 5);
        X509Certificate forwarded = certificate(forwardedKey, rootKey, "CN=forwarded-client",
                "CN=ZeroEcho Test Root", BigInteger.valueOf(5), false, false);
        TestTlsProvider.install(serverContext);
        TestClientTrustProvider.install(trustManager(root));
        return new Fixture(client, clientContext, anonymousContext, proxy, proxyContext, forwarded, root);
    }

    static PackagedTls packagedTls(java.nio.file.Path directory) throws Exception {
        java.nio.file.Files.createDirectories(directory);
        KeyPair rootKey = keyPair((byte) 31);
        X509Certificate root = certificate(rootKey, rootKey, "CN=Packaged Test Root", "CN=Packaged Test Root",
                BigInteger.valueOf(31), true, false);
        KeyPair serverKey = keyPair((byte) 32);
        X509Certificate server = certificate(serverKey, rootKey, "CN=localhost", "CN=Packaged Test Root",
                BigInteger.valueOf(32), false, true);
        KeyPair clientKey = keyPair((byte) 33);
        X509Certificate client = certificate(clientKey, rootKey, "CN=packaged-admin", "CN=Packaged Test Root",
                BigInteger.valueOf(33), false, false);
        java.nio.file.Path keys = directory.resolve("server.p12");
        java.nio.file.Path trust = directory.resolve("trust.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, PASSWORD);
        keyStore.setKeyEntry("server", serverKey.getPrivate(), PASSWORD,
                new java.security.cert.Certificate[] { server, root });
        try (java.io.OutputStream output = java.nio.file.Files.newOutputStream(keys)) {
            keyStore.store(output, PASSWORD);
        }
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, PASSWORD);
        trustStore.setCertificateEntry("root", root);
        try (java.io.OutputStream output = java.nio.file.Files.newOutputStream(trust)) {
            trustStore.store(output, PASSWORD);
        }
        return new PackagedTls(keys, trust, context(clientKey, client, root, false), client);
    }

    public static PkiServerConfiguration configuration(java.nio.file.Path directory, X509Certificate client)
            throws Exception {
        return configuration(directory, directAuthentication(client));
    }

    public static PkiServerConfiguration proxyConfiguration(java.nio.file.Path directory, Fixture fixture,
            ForwardedCertificateFormat format) throws Exception {
        PkiServerConfiguration.ClientCertificateMapping proxy = mapping("proxy-map", "trusted-proxy",
                fixture.proxyCertificate());
        PkiServerConfiguration.ClientCertificateMapping forwarded = mapping("forwarded-map", "administrator",
                fixture.forwardedCertificate());
        String header = format == ForwardedCertificateFormat.RFC9440
                ? "Client-Cert" : "X-ZeroEcho-Client-Cert";
        Optional<String> chainHeader = format == ForwardedCertificateFormat.RFC9440
                ? Optional.of("Client-Cert-Chain") : Optional.empty();
        PkiServerConfiguration.Authentication authentication = new PkiServerConfiguration.Authentication(
                AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, List.of(), List.of(proxy),
                List.of(forwarded), Set.of("trusted-proxy"), Optional.of(format), Optional.of(header), chainHeader,
                Optional.of(new ProviderConfig(TestClientTrustProvider.ID, Map.of())), 16_384, 65_536);
        return configuration(directory, authentication);
    }

    public static PkiServerConfiguration withPublicListener(PkiServerConfiguration source,
            PkiServerConfiguration.Authentication authentication) throws Exception {
        PkiServerConfiguration.Execution publicExecution = new PkiServerConfiguration.Execution(2, 4, 2, 4, 4,
                Duration.ofSeconds(5), Duration.ofSeconds(10), Duration.ofSeconds(1), Duration.ofSeconds(1));
        PkiServerConfiguration.PublicListener listener = new PkiServerConfiguration.PublicListener(
                InetAddress.getByName("127.0.0.1"), 0,
                Optional.of(new ProviderConfig("test-tls", Map.of())), false, authentication, 16_384,
                1_024, publicExecution, Duration.ofSeconds(10), Duration.ofHours(1), Duration.ofMinutes(1), true);
        return new PkiServerConfiguration(source.version(), source.serverName(), source.realm(), source.listener(),
                source.authentication(), source.execution(), source.runtime(), Optional.of(listener));
    }

    private static PkiServerConfiguration.Authentication directAuthentication(X509Certificate client)
            throws Exception {
        PkiServerConfiguration.ClientCertificateMapping mapping = mapping("administrator-map", "administrator",
                client);
        return new PkiServerConfiguration.Authentication(AdministrativeAuthenticationMode.DIRECT_MTLS,
                List.of(mapping), List.of(), List.of(), Set.of(), Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(), 0, 0);
    }

    private static PkiServerConfiguration configuration(java.nio.file.Path directory,
            PkiServerConfiguration.Authentication authentication) throws Exception {
        java.nio.file.Files.createDirectories(directory);
        ApprovalService.Policy approval = new ApprovalService.Policy("high-risk", 1, Set.of("approver"),
                Set.of(), true, Duration.ofHours(1), true);
        PkiSessionConfiguration session = new PkiSessionConfiguration(1,
                new ProviderConfig("fs", Map.of("root", directory.resolve("pki-store").toString())),
                new ProviderConfig("memory", Map.of("size", "128")), Optional.empty(), List.of(), List.of());
        ServerRealmConfiguration realm = new ServerRealmConfiguration(ServerTestSupport.REALM, "Production",
                ServerTestSupport.CONFIRMATION_PROOF_POLICY, session,
                new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES,
                        Set.of(), true), ServerTestSupport.DIGEST, approval.commitment(),
                ServerRealmConfiguration.extendedApprovalCommitment(
                        Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, approval)),
                ServerTestSupport.DIGEST,
                DisclosureService.Defaults.recommended(), directory.resolve("control.log"),
                new MetadataStoreId("fedcba9876543210fedcba9876543210"),
                Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, approval));
        return new PkiServerConfiguration(PkiServerConfiguration.CURRENT_VERSION, "test-server", realm,
                new PkiServerConfiguration.Listener(InetAddress.getByName("127.0.0.1"), 0,
                        new ProviderConfig("test-tls", Map.of()), true, 16_384, 65_536),
                authentication,
                new PkiServerConfiguration.Execution(2, 4, 2, 4, 8, Duration.ofSeconds(5),
                        Duration.ofSeconds(10), Duration.ofSeconds(1), Duration.ofSeconds(1)),
                new PkiServerConfiguration.RuntimeCapabilities(Optional.empty()));
    }

    private static PkiServerConfiguration.ClientCertificateMapping mapping(String mappingId,
            String principalId, X509Certificate certificate) throws Exception {
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(certificate.getEncoded()));
        return new PkiServerConfiguration.ClientCertificateMapping(mappingId, principalId, Optional.of(digest),
                Optional.empty(), Optional.empty());
    }

    public static SecureRandom random() throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(new byte[] { 1, 3, 5, 7, 9 });
        return random;
    }

    private static KeyPair keyPair(byte identity) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        SecureRandom deterministic = SecureRandom.getInstance("SHA1PRNG");
        deterministic.setSeed(new byte[] { 1, 3, 5, 7, 9, identity });
        generator.initialize(2048, deterministic);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(KeyPair subjectKey, KeyPair issuerKey, String subject,
            String issuer, BigInteger serial, boolean ca, boolean server) throws Exception {
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

    private static SSLContext context(KeyPair identity, X509Certificate certificate, X509Certificate root,
            boolean includeIdentity) throws Exception {
        KeyStore keys = KeyStore.getInstance("PKCS12");
        keys.load(null, PASSWORD);
        if (includeIdentity) {
            keys.setKeyEntry("identity", identity.getPrivate(), PASSWORD,
                    new java.security.cert.Certificate[] { certificate, root });
        }
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keys, PASSWORD);
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, PASSWORD);
        trust.setCertificateEntry("root", root);
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trust);
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), random());
        return context;
    }

    private static X509TrustManager trustManager(X509Certificate root) throws Exception {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, PASSWORD);
        trust.setCertificateEntry("root", root);
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trust);
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509TrustManager result) return result;
        }
        throw new IllegalStateException("Test trust manager unavailable");
    }

    public record Fixture(X509Certificate clientCertificate, SSLContext clientContext, SSLContext anonymousContext,
            X509Certificate proxyCertificate, SSLContext proxyContext, X509Certificate forwardedCertificate,
            X509Certificate rootCertificate) { }

    record PackagedTls(java.nio.file.Path keyStore, java.nio.file.Path trustStore, SSLContext anonymousContext,
            X509Certificate clientCertificate) { }
}
