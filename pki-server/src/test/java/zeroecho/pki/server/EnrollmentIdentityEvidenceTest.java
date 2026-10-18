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

package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.server.enrollment.EnrollmentIdentityAliases;
import zeroecho.pki.server.http.AdministrativeAuthenticator;
import zeroecho.pki.server.http.MutualTlsAuthenticator;
import zeroecho.pki.server.http.TestTlsProvider;
import zeroecho.pki.server.spi.PkiServerAuthenticationContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationResult;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.PublicKeyIdentity;

class EnrollmentIdentityEvidenceTest {
    private static HttpServerTestSupport.Fixture tls;

    @BeforeAll
    static void certificates() throws Exception { tls = HttpServerTestSupport.tls(); }

    @Test
    void equivalentMappingAliasesRemainExclusionOnlyAndIncludeDisabledPrincipals() throws Exception {
        CertificateIdentityEvidence evidence = CertificateIdentityEvidence.fromCertificate(ServerTestSupport.REALM, tls.clientCertificate());
        String actualSpki = digest(tls.clientCertificate().getPublicKey().getEncoded());
        String alternative = evidence.legacySpkiSha256().stream().filter(value -> !value.equals(actualSpki)).findFirst().orElseThrow();
        PkiServerConfiguration.ClientCertificateMapping first = mapping("certificate", "owner",
                Optional.of(evidence.certificateSha256()), Optional.empty(), Optional.empty());
        PkiServerConfiguration.ClientCertificateMapping disabled = mapping("alternative", "disabled",
                Optional.empty(), Optional.of(alternative), Optional.empty());
        PkiServerConfiguration.ClientCertificateMapping mixed = mapping("mixed", "second-alias",
                Optional.of("0".repeat(64)), Optional.of(actualSpki), Optional.empty());
        PkiServerConfiguration.ClientCertificateMapping serial = mapping("serial", "serial-alias",
                Optional.empty(), Optional.empty(), Optional.of(evidence.issuerSerialSha256()));
        PkiServerConfiguration.ClientCertificateMapping wrongType = mapping("wrong-type", "unrelated",
                Optional.of(actualSpki), Optional.empty(), Optional.empty());
        PkiServerConfiguration.Authentication config = direct(List.of(first, disabled, mixed, serial, wrongType));
        EnrollmentIdentityAliases.Snapshot frozen = new EnrollmentIdentityAliases(ServerTestSupport.REALM, config).knownAliases(evidence);
        assertEquals(Set.of("owner", "disabled", "second-alias", "serial-alias"), frozen.principalIds());
        assertThrows(UnsupportedOperationException.class, () -> frozen.principalIds().clear());
        MutualTlsAuthenticator alternativeAuth = new MutualTlsAuthenticator(List.of(disabled),
                ignored -> ServerTestSupport.principal("disabled"), ServerTestSupport.CLOCK);
        assertEquals(PkiServerAuthenticationResult.Code.MAPPING_UNAVAILABLE,
                ((PkiServerAuthenticationResult.Rejected) alternativeAuth.authenticate(context(tls.clientCertificate(), Map.of()))).code());
        MutualTlsAuthenticator conjunction = new MutualTlsAuthenticator(List.of(mixed),
                ignored -> ServerTestSupport.principal("second-alias"), ServerTestSupport.CLOCK);
        assertInstanceOf(PkiServerAuthenticationResult.Rejected.class, conjunction.authenticate(context(tls.clientCertificate(), Map.of())));
        MutualTlsAuthenticator disabledAuth = new MutualTlsAuthenticator(List.of(first), ignored ->
                new SecurityPrincipal("owner", SecurityPrincipal.Type.USER, "Disabled", Optional.empty(), Map.of(), false),
                ServerTestSupport.CLOCK);
        assertEquals(PkiServerAuthenticationResult.Code.PRINCIPAL_DISABLED,
                ((PkiServerAuthenticationResult.Rejected) disabledAuth.authenticate(context(tls.clientCertificate(), Map.of()))).code());
        EnrollmentIdentityAliases.Snapshot current = new EnrollmentIdentityAliases(ServerTestSupport.REALM,
                direct(List.of(mapping("new", "new-alias", Optional.empty(), Optional.of(actualSpki), Optional.empty())))).knownAliases(evidence);
        assertEquals(Set.of("owner", "disabled", "second-alias", "serial-alias", "new-alias"), frozen.union(current).principalIds());
        CertificateIdentityEvidence anotherRealm = new CertificateIdentityEvidence(new RealmId("other"),
                evidence.certificateSha256(), evidence.canonicalKeySha256(), evidence.legacySpkiSha256(), evidence.issuerSerialSha256());
        assertFalse(evidence.sameCredential(anotherRealm));
        assertThrows(IllegalArgumentException.class, () -> new EnrollmentIdentityAliases(ServerTestSupport.REALM, config).knownAliases(anotherRealm));
        assertThrows(IllegalArgumentException.class, () -> frozen.union(new EnrollmentIdentityAliases.Snapshot(new RealmId("other"), Set.of("owner"))));
        assertFalse(evidence.toString().contains(evidence.certificateSha256()));
        assertFalse(frozen.toString().contains("owner"));
    }

    @Test
    void authenticatedEvidenceUsesActualDirectOrValidatedForwardedEndClient(@TempDir Path root) throws Exception {
        CertificateIdentityEvidence expected = CertificateIdentityEvidence.fromCertificate(ServerTestSupport.REALM, tls.clientCertificate());
        PkiServerConfiguration.Authentication direct = direct(List.of(mapping("client", "administrator",
                Optional.of(expected.certificateSha256()), Optional.empty(), Optional.empty())));
        AdministrativeAuthenticator directAuth = AdministrativeAuthenticator.create(direct, ServerTestSupport::principal,
                (principal, request) -> new AuthorizationEngine.Decision(AuthorizationEngine.Code.ALLOWED, false),
                ServerTestSupport.CLOCK, TestTlsProvider.class.getClassLoader());
        PkiServerAuthenticationResult.Authenticated authenticated = assertInstanceOf(PkiServerAuthenticationResult.Authenticated.class,
                directAuth.authenticate(context(tls.clientCertificate(), Map.of())));
        assertEquals(Optional.of(expected), authenticated.credentialEvidence());

        PkiServerConfiguration configuration = HttpServerTestSupport.proxyConfiguration(root, tls, ForwardedCertificateFormat.RFC9440);
        AdministrativeAuthenticator proxyAuth = AdministrativeAuthenticator.create(configuration.authentication(), ServerTestSupport::principal,
                (principal, request) -> new AuthorizationEngine.Decision(AuthorizationEngine.Code.ALLOWED, false),
                ServerTestSupport.CLOCK, TestTlsProvider.class.getClassLoader());
        Map<String, List<String>> headers = Map.of("Client-Cert", List.of(":" + Base64.getEncoder().encodeToString(
                tls.forwardedCertificate().getEncoded()) + ":"), "Client-Cert-Chain", List.of(":" + Base64.getEncoder().encodeToString(
                        tls.rootCertificate().getEncoded()) + ":"));
        PkiServerAuthenticationResult.Authenticated forwarded = assertInstanceOf(PkiServerAuthenticationResult.Authenticated.class,
                proxyAuth.authenticate(context(tls.proxyCertificate(), headers)));
        CertificateIdentityEvidence client = CertificateIdentityEvidence.fromCertificate(ServerTestSupport.REALM, tls.forwardedCertificate());
        assertEquals(Optional.of(client), forwarded.credentialEvidence());
        assertNotEquals(digest(tls.proxyCertificate().getEncoded()), forwarded.credentialEvidence().orElseThrow().certificateSha256());
        assertEquals(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, forwarded.mode());
        EnrollmentIdentityAliases.Snapshot aliases = new EnrollmentIdentityAliases(ServerTestSupport.REALM,
                configuration.authentication()).knownAliases(client);
        assertTrue(aliases.principalIds().contains(forwarded.endClientPrincipalId()));
        assertFalse(aliases.principalIds().contains(forwarded.transportPrincipalId().orElseThrow()));
        assertInstanceOf(PkiServerAuthenticationResult.Rejected.class, directAuth.authenticate(context(tls.clientCertificate(), headers)));
    }

    @Test
    void equivalentRsaEncodingsCannotSeparateProxyFromForwardedIdentity() throws Exception {
        java.security.SecureRandom random = java.security.SecureRandom.getInstance("SHA1PRNG", "SUN");
        random.setSeed(new byte[] { 54, 21, 3, 87 });
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
        generator.initialize(2048, random);
        KeyPair key = generator.generateKeyPair();
        AlgorithmIdentifier signature = AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11");
        X500Principal rootName = new X500Principal("CN=Identity Regression Root");
        java.time.Instant before = java.time.Instant.parse("2025-01-01T00:00:00Z");
        java.time.Instant after = java.time.Instant.parse("2030-01-01T00:00:00Z");
        X509Certificate root = Pkix.certificateBuilder().issuer(rootName).subject(rootName)
                .serialNumber(BigInteger.ONE).validity(before, after).publicKey(key.getPublic())
                .basicConstraints(zeroecho.pkix.BasicConstraints.ca(), true)
                .keyUsage(Set.of(zeroecho.pkix.KeyUsage.KEY_CERT_SIGN), true)
                .build(Pkix.signer(key.getPrivate(), signature));
        byte[] bits = Pkix.subjectPublicKeyBytes(key.getPublic().getEncoded());
        byte[] absent = Pkix.buildSubjectPublicKeyInfo(AlgorithmIdentifier.absent("1.2.840.113549.1.1.1"), bits);
        byte[] withNull = Pkix.buildSubjectPublicKeyInfo(AlgorithmIdentifier.derNull("1.2.840.113549.1.1.1"), bits);
        X509Certificate proxyCertificate = identityCertificate(rootName, "CN=Proxy", 2, absent, key, signature, before, after);
        X509Certificate proxy = (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509", "BC")
                .generateCertificate(new java.io.ByteArrayInputStream(proxyCertificate.getEncoded()));
        X509Certificate client = identityCertificate(rootName, "CN=Forwarded", 3, withNull, key, signature, before, after);
        X509Certificate parsedClient = (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(client.getEncoded()));
        assertFalse(java.util.Arrays.equals(proxy.getEncoded(), parsedClient.getEncoded()));
        // Reproduce the exact two comparisons in the original early collision check.
        assertFalse(java.util.Arrays.equals(proxy.getPublicKey().getEncoded(), parsedClient.getPublicKey().getEncoded()));
        assertEquals(CertificateIdentityEvidence.fromCertificate(ServerTestSupport.REALM, proxy).canonicalKeySha256(),
                CertificateIdentityEvidence.fromCertificate(ServerTestSupport.REALM, parsedClient).canonicalKeySha256());
        java.security.KeyStore trustStore = java.security.KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("root", root);
        javax.net.ssl.TrustManagerFactory factory = javax.net.ssl.TrustManagerFactory.getInstance(
                javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trustStore);
        javax.net.ssl.X509TrustManager trust = (javax.net.ssl.X509TrustManager) factory.getTrustManagers()[0];
        java.util.concurrent.atomic.AtomicInteger trustChecks = new java.util.concurrent.atomic.AtomicInteger();
        zeroecho.pki.server.http.TestClientTrustProvider.install(new javax.net.ssl.X509TrustManager() {
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
                trustChecks.incrementAndGet();
                trust.checkClientTrusted(chain, authType);
            }
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
                trust.checkServerTrusted(chain, authType);
            }
            @Override public X509Certificate[] getAcceptedIssuers() { return trust.getAcceptedIssuers(); }
        });
        try {
            PkiServerConfiguration.Authentication configuration = new PkiServerConfiguration.Authentication(
                    AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, List.of(),
                    List.of(mapping("proxy", "trusted-proxy", Optional.of(digest(proxy.getEncoded())), Optional.empty(), Optional.empty())),
                    List.of(mapping("client", "requester", Optional.of(digest(client.getEncoded())), Optional.empty(), Optional.empty())),
                    Set.of("trusted-proxy"), Optional.of(ForwardedCertificateFormat.RFC9440), Optional.of("Client-Cert"),
                    Optional.of("Client-Cert-Chain"), Optional.of(new zeroecho.pki.spi.ProviderConfig(
                            zeroecho.pki.server.http.TestClientTrustProvider.ID, Map.of())), 16_384, 65_536);
            AdministrativeAuthenticator authenticator = AdministrativeAuthenticator.create(configuration, ServerTestSupport::principal,
                    (principal, request) -> new AuthorizationEngine.Decision(AuthorizationEngine.Code.ALLOWED, false),
                    ServerTestSupport.CLOCK, TestTlsProvider.class.getClassLoader());
            PkiServerAuthenticationResult.Rejected rejected = assertInstanceOf(PkiServerAuthenticationResult.Rejected.class,
                    authenticator.authenticate(context(proxy, forwardedHeaders(client, root))));
            assertEquals(PkiServerAuthenticationResult.Code.IDENTITY_COLLISION, rejected.code());
            assertEquals(Optional.of("trusted-proxy"), rejected.transportPrincipalId());
            assertEquals(Optional.of("requester"), rejected.endClientPrincipalId());
            assertEquals(1, trustChecks.get());
        } finally {
            certificates();
        }
    }

    @Test
    void distinctForwardedClientKeysBehindOneProxyKeepIndependentEvidence(@TempDir Path directory) throws Exception {
        PkiServerConfiguration.Authentication source = HttpServerTestSupport.proxyConfiguration(directory, tls,
                ForwardedCertificateFormat.RFC9440).authentication();
        PkiServerConfiguration.Authentication configuration = new PkiServerConfiguration.Authentication(source.mode(),
                source.directClientMappings(), source.proxyTransportMappings(), List.of(source.forwardedClientMappings().getFirst(),
                        mapping("second-client", "second-administrator", Optional.of(digest(tls.clientCertificate().getEncoded())),
                                Optional.empty(), Optional.empty())), source.trustedProxyPrincipalIds(), source.forwardedCertificateFormat(),
                source.forwardedCertificateHeaderName(), source.forwardedCertificateChainHeaderName(), source.administrativeClientTrust(),
                source.maximumForwardedCertificateBytes(), source.maximumForwardedChainBytes());
        AdministrativeAuthenticator authenticator = AdministrativeAuthenticator.create(configuration, ServerTestSupport::principal,
                (principal, request) -> new AuthorizationEngine.Decision(AuthorizationEngine.Code.ALLOWED, false),
                ServerTestSupport.CLOCK, TestTlsProvider.class.getClassLoader());
        PkiServerAuthenticationResult.Authenticated first = assertInstanceOf(PkiServerAuthenticationResult.Authenticated.class,
                authenticator.authenticate(context(tls.proxyCertificate(), forwardedHeaders(tls.forwardedCertificate(), tls.rootCertificate()))));
        PkiServerAuthenticationResult.Authenticated second = assertInstanceOf(PkiServerAuthenticationResult.Authenticated.class,
                authenticator.authenticate(context(tls.proxyCertificate(), forwardedHeaders(tls.clientCertificate(), tls.rootCertificate()))));
        assertEquals(first.transportPrincipalId(), second.transportPrincipalId());
        assertNotEquals(first.endClientPrincipalId(), second.endClientPrincipalId());
        assertNotEquals(first.credentialEvidence().orElseThrow().canonicalKeySha256(), second.credentialEvidence().orElseThrow().canonicalKeySha256());
        assertFalse(first.credentialEvidence().orElseThrow().sameCredential(second.credentialEvidence().orElseThrow()));
    }

    private static X509Certificate identityCertificate(X500Principal issuer, String subject, int serial, byte[] spki,
            KeyPair signer, AlgorithmIdentifier signature, java.time.Instant before, java.time.Instant after) {
        return Pkix.certificateBuilder().issuer(issuer).subject(new X500Principal(subject)).serialNumber(BigInteger.valueOf(serial))
                .validity(before, after).publicKeyInfo(spki).basicConstraints(zeroecho.pkix.BasicConstraints.endEntity(), true)
                .keyUsage(Set.of(zeroecho.pkix.KeyUsage.DIGITAL_SIGNATURE), true)
                .extendedKeyUsage(new zeroecho.pkix.ExtendedKeyUsage(List.of("1.3.6.1.5.5.7.3.2")), false)
                .build(Pkix.signer(signer.getPrivate(), signature));
    }

    private static Map<String, List<String>> forwardedHeaders(X509Certificate client, X509Certificate root) throws Exception {
        return Map.of("Client-Cert", List.of(":" + Base64.getEncoder().encodeToString(client.getEncoded()) + ":"),
                "Client-Cert-Chain", List.of(":" + Base64.getEncoder().encodeToString(root.getEncoded()) + ":"));
    }

    @Test
    void unsupportedEnrollmentIdentityDoesNotDisableOrdinaryAuthentication() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        java.security.SecureRandom random = java.security.SecureRandom.getInstance("SHA1PRNG", "SUN");
        random.setSeed(new byte[] { 14, 7, 3, 19 });
        generator.initialize(new java.security.spec.NamedParameterSpec("Ed25519"), random);
        KeyPair key = generator.generateKeyPair();
        X509Certificate certificate = Pkix.certificateBuilder().issuer(new X500Principal("CN=Unsupported Enrollment Identity"))
                .subject(new X500Principal("CN=Unsupported Enrollment Identity")).serialNumber(BigInteger.valueOf(77))
                .validity(ServerTestSupport.CLOCK.instant().minusSeconds(60), ServerTestSupport.CLOCK.instant().plusSeconds(60))
                .publicKey(key.getPublic()).build(Pkix.signer(key.getPrivate(), AlgorithmIdentifier.absent("1.3.101.112")));
        MutualTlsAuthenticator auth = new MutualTlsAuthenticator(List.of(mapping("ed", "administrator",
                Optional.of(digest(certificate.getEncoded())), Optional.empty(), Optional.empty())),
                ServerTestSupport::principal, ServerTestSupport.CLOCK);
        PkiServerAuthenticationResult.Authenticated result = assertInstanceOf(PkiServerAuthenticationResult.Authenticated.class,
                auth.authenticate(context(certificate, Map.of())));
        assertTrue(result.credentialEvidence().isEmpty());
        assertThrows(IllegalArgumentException.class, () -> PublicKeyIdentity.fromSubjectPublicKeyInfo(key.getPublic().getEncoded()));
    }

    @Test
    void gatewayEvidenceIsRealmBoundAndEmbeddedActorDoesNotInventEvidence() throws Exception {
        CertificateIdentityEvidence evidence = CertificateIdentityEvidence.fromCertificate(ServerTestSupport.REALM, tls.clientCertificate());
        ServerOperationGateway.Request request = new ServerOperationGateway.Request(ServerTestSupport.REALM, "administrator",
                AdministrativeAuthenticationMode.DIRECT_MTLS, Optional.empty(), Optional.of(evidence),
                new AdministrativeOperation.Control(new ServerControlOperation.ListPrincipals(0, 10)),
                new Permission.Resource(Permission.ResourceType.PRINCIPAL, new Permission.Scope(ServerTestSupport.REALM,
                        Optional.empty(), Optional.empty(), Optional.empty()), Optional.empty(), Optional.empty()),
                Permission.Relationship.ANY, Permission.Context.empty(), Optional.empty(), "identity-test");
        assertEquals(Optional.of(evidence), request.credentialEvidence());
        assertThrows(IllegalArgumentException.class, () -> new ServerOperationGateway.Request(new RealmId("other"), request.principalId(),
                request.authenticationMode(), request.transportPrincipalId(), request.credentialEvidence(), request.operation(),
                request.resource(), request.relationship(), request.context(), request.approvalId(), request.correlationId()));
        assertTrue(new PkiServerAuthenticationResult.Authenticated("administrator").credentialEvidence().isEmpty());
        assertFalse(new AdministrativeDecisionActor("administrator", Optional.of(evidence)).toString().contains(evidence.canonicalKeySha256()));
    }

    private static PkiServerConfiguration.Authentication direct(List<PkiServerConfiguration.ClientCertificateMapping> mappings) {
        return new PkiServerConfiguration.Authentication(AdministrativeAuthenticationMode.DIRECT_MTLS, mappings, List.of(), List.of(),
                Set.of(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 0, 0);
    }

    private static PkiServerConfiguration.ClientCertificateMapping mapping(String id, String principal, Optional<String> certificate,
            Optional<String> spki, Optional<String> serial) {
        return new PkiServerConfiguration.ClientCertificateMapping(id, principal, certificate, spki, serial);
    }

    private static PkiServerAuthenticationContext context(X509Certificate certificate, Map<String, List<String>> headers) {
        return new PkiServerAuthenticationContext(List.of(certificate), "TLSv1.3", "TLS_AES_128_GCM_SHA256",
                "identity-request-0001", ServerTestSupport.REALM, headers);
    }

    private static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
