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
 *******************************************************************************/
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.HexFormat;
import java.security.MessageDigest;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.impl.framework.x509.bc.SimpleAttributeSet;
import zeroecho.pki.server.acme.AcmeService;
import zeroecho.pki.server.acme.AcmeState;
import zeroecho.pki.server.acme.Http01ChallengeProvider;
import zeroecho.pki.server.acme.TestAcmeEabProvider;
import zeroecho.pki.server.http.AcmeTestClient;
import zeroecho.pki.server.http.TestTlsProvider;
import zeroecho.pki.spi.ProviderConfig;

/** Complete wire-level ACME account-to-revocation integration. */
@SuppressWarnings("PMD")
class AcmeEndToEndTest {
    private static final char[] KEYRING_PASSWORD = "acme-end-to-end-password".toCharArray();
    private static final String DIRECTORY_ALIAS = "internal";
    private static final String EAB_DIRECTORY_ALIAS = "eab";
    private static final String IDENTIFIER = "localhost";
    private static final byte[] EAB_SECRET = "zeroecho-test-eab-secret-32-bytes"
            .getBytes(StandardCharsets.US_ASCII);

    @TempDir Path temporaryDirectory;

    @Test
    void completesRealHttpsAccountIssuanceRolloverRestartAndRevocation() throws Exception {
        System.out.println("completesRealHttpsAccountIssuanceRolloverRestartAndRevocation");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        int acmePort = reservePort();
        int challengePort = reservePort();
        KeyPair rootKey = rsa((byte) 21);
        KeyPair leafKey = rsa((byte) 22);
        KeyPair accountKey = ec((byte) 23);
        KeyPair replacementKey = ec((byte) 24);
        Fixture fixture = fixture(tls, acmePort, challengePort, rootKey);
        seed(fixture);

        URI directoryUri = URI.create("https://localhost:" + acmePort + "/acme/" + DIRECTORY_ALIAS
                + "/directory");
        HttpClient wire = HttpClient.newBuilder().sslContext(tls.anonymousContext())
                .connectTimeout(Duration.ofSeconds(5)).build();
        String accountKid;
        URI accountUri;
        URI orderUri;
        URI certificateUri;
        byte[] leafDer;
        try (PkiHttpsServer server = start(fixture);
                AcmeTestClient client = new AcmeTestClient(wire, directoryUri, accountKey)) {
            verifyEabOverHttp(wire, acmePort, ec((byte) 25));
            AcmeTestClient.Response directory = client.directory();
            assertEquals(200, directory.status());
            URI nonceUri = URI.create(AcmeTestClient.text(directory, "newNonce"));
            URI newAccount = URI.create(AcmeTestClient.text(directory, "newAccount"));
            URI newOrder = URI.create(AcmeTestClient.text(directory, "newOrder"));
            URI keyChange = URI.create(AcmeTestClient.text(directory, "keyChange"));
            client.nonce(nonceUri);
            AcmeTestClient.Response account = client.createAccount(newAccount,
                    "{\"termsOfServiceAgreed\":true}");
            assertEquals(201, account.status());
            accountKid = client.accountKid();
            accountUri = URI.create(accountKid);

            AcmeTestClient.Response order = client.kid(newOrder,
                    "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"localhost\"}]}");
            assertEquals(201, order.status());
            orderUri = URI.create(order.header("Location").orElseThrow());
            URI authorizationUri = URI.create(AcmeTestClient.textList(order, "authorizations").get(0));
            URI finalizeUri = URI.create(AcmeTestClient.text(order, "finalize"));
            AcmeTestClient.Response authorization = client.postAsGet(authorizationUri);
            assertEquals("pending", AcmeTestClient.text(authorization, "status"));
            URI challengeUri = AcmeTestClient.challenge(authorization).url();
            AcmeTestClient.Response challenge = client.postAsGet(challengeUri);
            String token = AcmeTestClient.text(challenge, "token");

            try (Http01Responder responder = new Http01Responder(challengePort, token,
                    client.keyAuthorization(token))) {
                responder.start();
                AcmeTestClient.Response validated = client.kid(challengeUri, "{}");
                assertEquals(200, validated.status());
                assertEquals("valid", AcmeTestClient.text(validated, "status"));
                responder.await();
            }
            AcmeTestClient.Response ready = client.postAsGet(orderUri);
            assertEquals("ready", AcmeTestClient.text(ready, "status"));
            String csr = Base64.getUrlEncoder().withoutPadding().encodeToString(csr(leafKey));
            AcmeTestClient.Response finalized = client.kid(finalizeUri, "{\"csr\":\"" + csr + "\"}");
            assertEquals(200, finalized.status());
            assertEquals("valid", AcmeTestClient.text(finalized, "status"));
            certificateUri = URI.create(AcmeTestClient.text(finalized, "certificate"));
            AcmeTestClient.Response certificate = client.postAsGet(certificateUri);
            assertEquals(200, certificate.status());
            List<X509Certificate> chain = certificates(certificate.bodyText());
            assertEquals(2, chain.size());
            assertEquals(List.of(IDENTIFIER), chain.get(0).getSubjectAlternativeNames().stream()
                    .filter(value -> Integer.valueOf(2).equals(value.get(0))).map(value -> value.get(1).toString())
                    .toList());
            chain.get(0).verify(chain.get(1).getPublicKey());
            leafDer = chain.get(0).getEncoded();

            assertEquals(200, client.rollover(keyChange, replacementKey).status());
            assertEquals(200, client.postAsGet(accountUri).status());
            System.out.println("...https-jws-http01-issuance=true");
        }

        try (PkiHttpsServer restarted = start(fixture);
                AcmeTestClient replacement = new AcmeTestClient(wire, directoryUri, replacementKey);
                AcmeTestClient old = new AcmeTestClient(wire, directoryUri, accountKey)) {
            URI nonceUri = URI.create(AcmeTestClient.text(replacement.directory(), "newNonce"));
            replacement.nonce(nonceUri); replacement.useAccount(accountKid);
            assertEquals(200, replacement.postAsGet(accountUri).status());
            old.directory(); old.nonce(nonceUri); old.useAccount(accountKid);
            assertEquals(403, old.postAsGet(accountUri).status());
            assertEquals(200, replacement.postAsGet(orderUri).status());
            assertEquals(200, replacement.postAsGet(certificateUri).status());
            URI revoke = URI.create(AcmeTestClient.text(replacement.directory(), "revokeCert"));
            String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(leafDer);
            assertEquals(200, replacement.kid(revoke,
                    "{\"certificate\":\"" + encoded + "\",\"reason\":1}").status());
            assertFalse(replacement.kid(revoke,
                    "{\"certificate\":\"" + encoded + "\",\"reason\":1}").status() == 200);
            System.out.println("...rollover-restart-revocation=true");
        }
        System.out.println("...ok");
    }

    @Test
    void completesInstalledDistributionAccountToRevocationWorkflow() throws Exception {
        System.out.println("completesInstalledDistributionAccountToRevocationWorkflow");
        Path root = temporaryDirectory.resolve("packaged");
        java.nio.file.Files.createDirectories(root);
        java.nio.file.Files.setPosixFilePermissions(root, java.nio.file.attribute.PosixFilePermissions
                .fromString("rwx------"));
        HttpServerTestSupport.PackagedTls tls = HttpServerTestSupport.packagedTls(root.resolve("tls"));
        int adminPort = reservePort();
        int acmePort = reservePort();
        int challengePort = reservePort();
        KeyPair rootKey = rsa((byte) 41);
        Fixture fixture = packagedFixture(root, tls, adminPort, acmePort, challengePort, rootKey);
        seed(fixture, false);
        Path configuration = root.resolve("server.json");
        java.nio.file.Files.writeString(configuration, packagedJson(fixture.configuration(), tls),
                StandardCharsets.UTF_8);
        Path launcher = Path.of(System.getProperty("user.dir"), "build", "install", "zeroecho-pki-server", "bin",
                "zeroecho-pki-server").toAbsolutePath();
        Path output = root.resolve("server-output.log");
        ProcessBuilder builder = new ProcessBuilder(launcher.toString(), "--config", configuration.toString());
        builder.environment().put("ZEROECHO_TEST_TLS_PASSWORD", new String(HttpServerTestSupport.PASSWORD));
        builder.environment().put("ZEROECHO_TEST_KEYRING_PASSWORD", new String(KEYRING_PASSWORD));
        builder.redirectErrorStream(true).redirectOutput(output.toFile());
        Process process = builder.start();
        URI directoryUri = URI.create("https://localhost:" + acmePort + "/acme/" + DIRECTORY_ALIAS
                + "/directory");
        HttpClient wire = HttpClient.newBuilder().sslContext(tls.anonymousContext())
                .connectTimeout(Duration.ofMillis(500)).build();
        try {
            awaitDirectory(wire, directoryUri, process, output);
            KeyPair accountKey = ec((byte) 42);
            KeyPair replacement = ec((byte) 43);
            KeyPair leaf = rsa((byte) 44);
            try (AcmeTestClient client = new AcmeTestClient(wire, directoryUri, accountKey)) {
                AcmeTestClient.Response directory = client.directory();
                URI nonce = URI.create(AcmeTestClient.text(directory, "newNonce"));
                URI account = URI.create(AcmeTestClient.text(directory, "newAccount"));
                URI orderEndpoint = URI.create(AcmeTestClient.text(directory, "newOrder"));
                URI rollover = URI.create(AcmeTestClient.text(directory, "keyChange"));
                URI revoke = URI.create(AcmeTestClient.text(directory, "revokeCert"));
                client.nonce(nonce);
                assertEquals(201, client.createAccount(account, "{}").status());
                AcmeTestClient.Response order = client.kid(orderEndpoint,
                        "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"localhost\"}]}");
                URI authorization = URI.create(AcmeTestClient.textList(order, "authorizations").get(0));
                URI finalizeOrder = URI.create(AcmeTestClient.text(order, "finalize"));
                URI orderUri = URI.create(order.header("Location").orElseThrow());
                URI challenge = AcmeTestClient.challenge(client.postAsGet(authorization)).url();
                String token = AcmeTestClient.text(client.postAsGet(challenge), "token");
                try (Http01Responder responder = new Http01Responder(challengePort, token,
                        client.keyAuthorization(token))) {
                    responder.start();
                    assertEquals("valid", AcmeTestClient.text(client.kid(challenge, "{}"), "status"));
                    responder.await();
                }
                assertEquals("ready", AcmeTestClient.text(client.postAsGet(orderUri), "status"));
                String encodedCsr = Base64.getUrlEncoder().withoutPadding().encodeToString(csr(leaf));
                AcmeTestClient.Response finalized = client.kid(finalizeOrder,
                        "{\"csr\":\"" + encodedCsr + "\"}");
                URI certificate = URI.create(AcmeTestClient.text(finalized, "certificate"));
                List<X509Certificate> chain = certificates(client.postAsGet(certificate).bodyText());
                assertEquals(2, chain.size());
                assertEquals(200, client.rollover(rollover, replacement).status());
                String der = Base64.getUrlEncoder().withoutPadding().encodeToString(chain.get(0).getEncoded());
                assertEquals(200, client.kid(revoke,
                        "{\"certificate\":\"" + der + "\",\"reason\":1}").status());
            }
            System.out.println("...installed-launcher-flow=true");
        } finally {
            process.destroy();
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                assertTrue(process.waitFor(5, TimeUnit.SECONDS));
            }
        }
        System.out.println("...ok");
    }

    private static void verifyEabOverHttp(HttpClient wire, int acmePort, KeyPair key) throws Exception {
        URI directoryUri = URI.create("https://localhost:" + acmePort + "/acme/" + EAB_DIRECTORY_ALIAS
                + "/directory");
        try (AcmeTestClient client = new AcmeTestClient(wire, directoryUri, key)) {
            AcmeTestClient.Response directory = client.directory();
            URI nonce = URI.create(AcmeTestClient.text(directory, "newNonce"));
            URI account = URI.create(AcmeTestClient.text(directory, "newAccount"));
            client.nonce(nonce);
            assertEquals(403, client.jwk(account, "{}").status());
            String binding = client.externalAccountBinding(account, "test-key", EAB_SECRET);
            AcmeTestClient.Response created = client.jwk(account,
                    "{\"externalAccountBinding\":" + binding + "}");
            assertEquals(201, created.status(), created.bodyText());
            System.out.println("...http-eab-required=true");
        }
    }

    private Fixture fixture(HttpServerTestSupport.Fixture tls, int acmePort, int challengePort, KeyPair rootKey)
            throws Exception {
        Path root = temporaryDirectory.resolve("server");
        PkiServerConfiguration base = HttpServerTestSupport.configuration(root, tls.clientCertificate());
        java.nio.file.Files.setPosixFilePermissions(root, java.nio.file.attribute.PosixFilePermissions
                .fromString("rwx------"));
        Path keyring = root.resolve("signing-keyring.zek");
        try (KeyringPassword password = new KeyringPassword(KEYRING_PASSWORD.clone());
                KeyringStore store = KeyringStore.create(keyring, password)) {
            store.putPrivate("root.prv", "RSA", rootKey.getPrivate());
            store.putPublic("root.pub", "RSA", rootKey.getPublic());
        }
        ProviderConfig workflow = new ProviderConfig("zeroecho-lib", Map.of(
                "keyringPath", keyring.toString(), "operationRoot", root.resolve("signing-operations").toString(),
                "keyRefPrefix", "acme-test:", "requireComponentSuffix", "true"));
        PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                workflow, new ProviderConfig("x509-bc", Map.of()), root.resolve("signing-bus.log").toString(),
                "SHA256withRSA", Duration.ofSeconds(10), Optional.empty());
        PkiSessionConfiguration session = new PkiSessionConfiguration(3,
                base.realm().pkiSessionConfiguration().store(), base.realm().pkiSessionConfiguration().audit(),
                Optional.of(signing), List.of(), List.of());
        ServerRealmConfiguration realm = new ServerRealmConfiguration(base.realm().realmId(),
                base.realm().displayName(), session, base.realm().authorityExposure(),
                base.realm().authorizationCommitment(), base.realm().approvalCommitment(),
                base.realm().disclosureCommitment(), base.realm().disclosureDefaults(),
                base.realm().controlLogPath(), base.realm().controlStoreId(), base.realm().approvalPolicies());
        PkiServerConfiguration.Execution lane = new PkiServerConfiguration.Execution(2, 4, 2, 4, 4,
                Duration.ofSeconds(10), Duration.ofSeconds(20), Duration.ofSeconds(2), Duration.ofSeconds(2));
        ProviderConfig http01 = new ProviderConfig(Http01ChallengeProvider.ID, Map.of("allowPrivate", "true",
                "timeoutMillis", "5000", "maximumBodyBytes", "4096", "maximumAddresses", "4",
                "targetPort", Integer.toString(challengePort)));
        PkiServerConfiguration.AcmeListener acme = new PkiServerConfiguration.AcmeListener("acme-e2e",
                InetAddress.getByName("127.0.0.1"), acmePort, new ProviderConfig("test-tls", Map.of()),
                PkiServerConfiguration.AcmeTransportMode.DIRECT_TLS, List.of(), Set.of(),
                URI.create("https://localhost:" + acmePort), 16_384, 1_048_576, lane, lane,
                Duration.ofMinutes(5), 256, 32, 32, Duration.ofMinutes(1), 32, 32, 16, 32, 2,
                List.of(http01), List.of(new ProviderConfig(TestAcmeEabProvider.ID, Map.of())));
        PkiServerConfiguration configuration = new PkiServerConfiguration(base.version(), base.serverName(), realm,
                base.listener(), base.authentication(), base.execution(), base.runtime(), Optional.empty(),
                Optional.of(acme));
        PkiSessionRuntimeDependencies dependencies = PkiSessionRuntimeDependencies.withKeyringUnlockProvider(
                () -> new KeyringPassword(KEYRING_PASSWORD.clone()));
        return new Fixture(configuration, dependencies, http01);
    }

    private void seed(Fixture fixture) throws Exception {
        seed(fixture, true);
    }

    private void seed(Fixture fixture, boolean includeEab) throws Exception {
        try (ServerRealmContext context = ServerRealmContext.open(fixture.configuration().realm(),
                fixture.dependencies(), ServerTestSupport.CLOCK, HttpServerTestSupport.random())) {
            BuiltInCertificateProfileTemplate root = template("root-ca");
            BuiltInCertificateProfileTemplate leaf = template("server-tls");
            context.session().profiles().importBuiltIn(root);
            context.session().profiles().activateProfile("root-ca", root.definition().profileVersion());
            context.session().profiles().importBuiltIn(leaf);
            context.session().profiles().activateProfile("server-tls", leaf.definition().profileVersion());
            PkiId authority = context.session().authorities().orElseThrow().createRoot(new CaCreateCommand(
                    root.definition().formatId(), new SubjectRef("CN=ZeroEcho ACME E2E Root"), "root-ca",
                    Optional.of(new KeyRef("acme-test:root.prv")), new SimpleAttributeSet()));
            ActiveCertificateProfile active = context.session().profiles().requireActiveProfile("server-tls");
            AcmeService service = new AcmeService(context, ServerTestSupport.CLOCK, HttpServerTestSupport.random(),
                    Map.of(Http01ChallengeProvider.ID, new Http01ChallengeProvider()),
                    Map.of(Http01ChallengeProvider.ID, fixture.http01()),
                    Map.of(TestAcmeEabProvider.ID, new TestAcmeEabProvider()),
                    Map.of(TestAcmeEabProvider.ID, new ProviderConfig(TestAcmeEabProvider.ID, Map.of())));
            AcmeState.Directory directory = service.registerDirectory(new AcmeService.DirectoryRegistration(
                    DIRECTORY_ALIAS, authority, "server-tls", Set.of(IDENTIFIER), Duration.ofDays(30),
                    active.definition().leafPolicy().allowedSubjectKeyAlgorithmIds(), Set.of("STANDARD_ONLY"),
                    Set.of(AcmeState.ChallengeType.HTTP_01), Set.of(Http01ChallengeProvider.ID), Optional.empty(),
                    false, DisclosureService.Policy.OWNER_ONLY));
            service.activateDirectory(directory.directoryId());
            if (includeEab) {
                AcmeState.Directory eab = service.registerDirectory(new AcmeService.DirectoryRegistration(
                        EAB_DIRECTORY_ALIAS, authority, "server-tls", Set.of(IDENTIFIER), Duration.ofDays(30),
                        active.definition().leafPolicy().allowedSubjectKeyAlgorithmIds(), Set.of("STANDARD_ONLY"),
                        Set.of(AcmeState.ChallengeType.HTTP_01), Set.of(Http01ChallengeProvider.ID),
                        Optional.of(TestAcmeEabProvider.ID), true, DisclosureService.Policy.OWNER_ONLY));
                service.activateDirectory(eab.directoryId());
            }
            assertEquals(authority, context.session().repository().authority(authority).orElseThrow().caId());
        }
    }

    private PkiHttpsServer start(Fixture fixture) throws Exception {
        return PkiHttpsServer.start(fixture.configuration(), fixture.dependencies(), ServerTestSupport.CLOCK,
                HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader());
    }

    private Fixture packagedFixture(Path root, HttpServerTestSupport.PackagedTls tls, int adminPort, int acmePort,
            int challengePort, KeyPair rootKey) throws Exception {
        Path keyring = root.resolve("signing-keyring.zek");
        try (KeyringPassword password = new KeyringPassword(KEYRING_PASSWORD.clone());
                KeyringStore store = KeyringStore.create(keyring, password)) {
            store.putPrivate("root.prv", "RSA", rootKey.getPrivate());
            store.putPublic("root.pub", "RSA", rootKey.getPublic());
        }
        ProviderConfig workflow = new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString(),
                "operationRoot", root.resolve("signing-operations").toString(), "keyRefPrefix", "acme-test:",
                "requireComponentSuffix", "true"));
        PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                workflow, new ProviderConfig("x509-bc", Map.of()), root.resolve("signing-bus.log").toString(),
                "SHA256withRSA", Duration.ofSeconds(10), Optional.of("ZEROECHO_TEST_KEYRING_PASSWORD"));
        PkiSessionConfiguration session = new PkiSessionConfiguration(3,
                new ProviderConfig("fs", Map.of("root", root.resolve("pki").toString())),
                new ProviderConfig("memory", Map.of("size", "256")), Optional.of(signing), List.of(), List.of());
        ApprovalService.Policy approval = new ApprovalService.Policy("high-risk", 1, Set.of("approver"), Set.of(),
                true, Duration.ofHours(1), true);
        ServerRealmConfiguration realm = new ServerRealmConfiguration(ServerTestSupport.REALM, "Packaged ACME",
                session, new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(),
                        true), ServerTestSupport.DIGEST, approval.commitment(), ServerTestSupport.DIGEST,
                DisclosureService.Defaults.recommended(), root.resolve("control.log"),
                new zeroecho.pki.spi.store.MetadataStoreId("1234567890abcdef1234567890abcdef"),
                Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, approval));
        String certificateDigest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(tls.clientCertificate().getEncoded()));
        PkiServerConfiguration.Authentication authentication = new PkiServerConfiguration.Authentication(
                AdministrativeAuthenticationMode.DIRECT_MTLS,
                List.of(new PkiServerConfiguration.ClientCertificateMapping("packaged-admin", "administrator",
                        Optional.of(certificateDigest), Optional.empty(), Optional.empty())),
                List.of(), List.of(), Set.of(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                0, 0);
        ProviderConfig tlsProvider = tlsProvider(tls);
        PkiServerConfiguration.Execution lane = new PkiServerConfiguration.Execution(2, 4, 2, 4, 4,
                Duration.ofSeconds(10), Duration.ofSeconds(20), Duration.ofSeconds(2), Duration.ofSeconds(2));
        ProviderConfig http01 = new ProviderConfig(Http01ChallengeProvider.ID, Map.of("allowPrivate", "true",
                "timeoutMillis", "5000", "maximumBodyBytes", "4096", "maximumAddresses", "4", "targetPort",
                Integer.toString(challengePort)));
        PkiServerConfiguration.AcmeListener acme = new PkiServerConfiguration.AcmeListener("packaged-acme",
                InetAddress.getByName("127.0.0.1"), acmePort, tlsProvider,
                PkiServerConfiguration.AcmeTransportMode.DIRECT_TLS, List.of(), Set.of(),
                URI.create("https://localhost:" + acmePort), 16_384, 1_048_576, lane, lane,
                Duration.ofMinutes(5), 256, 32, 32, Duration.ofMinutes(1), 32, 32, 16, 32, 2,
                List.of(http01), List.of());
        PkiServerConfiguration configuration = new PkiServerConfiguration(4, "packaged-acme", realm,
                new PkiServerConfiguration.Listener(InetAddress.getByName("127.0.0.1"), adminPort, tlsProvider,
                        true, 16_384, 1_048_576), authentication, lane,
                new PkiServerConfiguration.RuntimeCapabilities(Optional.of("ZEROECHO_TEST_KEYRING_PASSWORD")),
                Optional.empty(), Optional.of(acme));
        return new Fixture(configuration, PkiSessionRuntimeDependencies.withKeyringUnlockProvider(
                () -> new KeyringPassword(KEYRING_PASSWORD.clone())), http01);
    }

    private static ProviderConfig tlsProvider(HttpServerTestSupport.PackagedTls tls) {
        return new ProviderConfig("jsse-pkcs12", Map.of("keyStore", tls.keyStore().toString(),
                "keyStorePasswordEnvironment", "ZEROECHO_TEST_TLS_PASSWORD", "trustStore",
                tls.trustStore().toString(), "trustStorePasswordEnvironment", "ZEROECHO_TEST_TLS_PASSWORD"));
    }

    private static String packagedJson(PkiServerConfiguration configuration,
            HttpServerTestSupport.PackagedTls tls) {
        ServerRealmConfiguration realm = configuration.realm();
        PkiSessionConfiguration.SigningConfiguration signing = realm.pkiSessionConfiguration().signing()
                .orElseThrow();
        ProviderConfig http = configuration.acmeListener().orElseThrow().challengeProviders().get(0);
        String tlsJson = providerJson(tlsProvider(tls));
        String workflow = providerJson(signing.workflow());
        String store = providerJson(realm.pkiSessionConfiguration().store());
        String audit = providerJson(realm.pkiSessionConfiguration().audit());
        return "{\"version\":4,\"serverName\":\"packaged-acme\",\"realm\":{"
                + "\"realmId\":\"production\",\"displayName\":\"Packaged ACME\","
                + "\"authorityExposure\":{\"mode\":\"ALL_REALM_AUTHORITIES\",\"authorityIds\":[],"
                + "\"creationPermitted\":true},\"authorizationCommitment\":\"" + realm.authorizationCommitment()
                + "\",\"approvalCommitment\":\"" + realm.approvalCommitment()
                + "\",\"disclosureCommitment\":\"" + realm.disclosureCommitment() + "\","
                + "\"disclosureDefaults\":{\"rootCa\":\"PUBLIC\",\"intermediateCa\":\"PUBLIC\","
                + "\"caChain\":\"PUBLIC\",\"crl\":\"PUBLIC\",\"leaf\":\"OWNER_ONLY\","
                + "\"sensitiveLeaf\":\"RESTRICTED\"},\"controlLog\":\"" + json(realm.controlLogPath().toString())
                + "\",\"controlStoreId\":\"" + realm.controlStoreId().value() + "\","
                + "\"approvalPolicy\":{\"policyId\":\"high-risk\",\"threshold\":1,"
                + "\"eligibleApprovers\":[\"approver\"],\"requiredRoleTemplateIds\":[],"
                + "\"requesterSeparation\":true,\"lifetimeMillis\":3600000,\"justificationRequired\":true},"
                + "\"pkiSession\":{\"version\":3,\"store\":" + store + ",\"audit\":" + audit
                + ",\"signing\":{\"workflow\":" + workflow + ",\"framework\":"
                + providerJson(signing.framework()) + ",\"busPath\":\"" + json(signing.busPath())
                + "\",\"signatureAlgorithm\":\"SHA256withRSA\",\"signingTtlMillis\":10000,"
                + "\"unlockEnvironmentVariable\":\"ZEROECHO_TEST_KEYRING_PASSWORD\"},"
                + "\"publishers\":[],\"bindingProviders\":[]}},\"listener\":{\"address\":\"127.0.0.1\","
                + "\"port\":" + configuration.listener().port() + ",\"tlsProvider\":" + tlsJson
                + ",\"clientCertificateRequired\":true,\"maximumHeaderBytes\":16384,"
                + "\"maximumBodyBytes\":1048576},\"authentication\":{\"mode\":\"DIRECT_MTLS\","
                + "\"directClientMappings\":[{\"mappingId\":\"packaged-admin\","
                + "\"principalId\":\"administrator\",\"certificateSha256\":\""
                + configuration.authentication().directClientMappings().get(0).certificateSha256().orElseThrow()
                + "\"}]},\"execution\":" + executionJson() + ",\"publicListener\":{\"enabled\":false},"
                + "\"acmeListener\":{\"enabled\":true,\"listenerId\":\"packaged-acme\","
                + "\"address\":\"127.0.0.1\",\"port\":" + configuration.acmeListener().orElseThrow().port()
                + ",\"tlsProvider\":" + tlsJson + ",\"transportMode\":\"DIRECT_TLS\","
                + "\"externalBaseUri\":\"" + configuration.acmeListener().orElseThrow().externalBaseUri()
                + "\",\"maximumHeaderBytes\":16384,\"maximumBodyBytes\":1048576,\"execution\":"
                + executionJson() + ",\"validationExecution\":" + executionJson()
                + ",\"nonceLifetimeMillis\":300000,\"maximumOutstandingNonces\":256,"
                + "\"maximumAccountsPresented\":32,\"maximumOrdersPresented\":32,"
                + "\"admissionWindowMillis\":60000,\"maximumNewAccountsPerWindow\":32,"
                + "\"maximumNewOrdersPerAccountWindow\":32,\"maximumPendingOrdersPerAccount\":16,"
                + "\"maximumChallengeValidationsPerAccountWindow\":32,\"maximumConcurrentFinalizations\":2,"
                + "\"challengeProviders\":[" + providerJson(http) + "],\"eabProviders\":[]},"
                + "\"runtime\":{\"keyUnlockEnvironmentVariable\":\"ZEROECHO_TEST_KEYRING_PASSWORD\"}}";
    }

    private static String executionJson() {
        return "{\"transportWorkers\":2,\"transportQueueCapacity\":4,\"operationWorkers\":2,"
                + "\"operationQueueCapacity\":4,\"maximumAdmittedRequests\":4,"
                + "\"defaultDeadlineMillis\":10000,\"maximumDeadlineMillis\":20000,"
                + "\"gracefulShutdownMillis\":2000,\"forcedShutdownMillis\":2000}";
    }

    private static String providerJson(ProviderConfig provider) {
        StringBuilder out = new StringBuilder("{\"id\":\"").append(provider.backendId())
                .append("\",\"properties\":{");
        int index = 0;
        for (Map.Entry<String, String> property : new java.util.TreeMap<>(provider.properties()).entrySet()) {
            if (index++ != 0) out.append(',');
            out.append('\"').append(json(property.getKey())).append("\":\"")
                    .append(json(property.getValue())).append('\"');
        }
        return out.append("}}").toString();
    }

    private static String json(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void awaitDirectory(HttpClient client, URI directory, Process process, Path output)
            throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        Throwable last = null;
        while (System.nanoTime() < deadline && process.isAlive()) {
            try {
                java.net.http.HttpResponse<Void> response = client.send(java.net.http.HttpRequest.newBuilder(directory)
                        .timeout(Duration.ofSeconds(1)).GET().build(), java.net.http.HttpResponse.BodyHandlers.discarding());
                if (response.statusCode() == 200) return;
            } catch (java.io.IOException unavailable) {
                last = unavailable;
            }
        }
        String diagnostics = java.nio.file.Files.exists(output) ? java.nio.file.Files.readString(output) : "";
        throw new AssertionError("Packaged ACME listener did not become ready: " + diagnostics, last);
    }

    private static BuiltInCertificateProfileTemplate template(String id) {
        return BuiltInCertificateProfileCatalog.load(AcmeEndToEndTest.class.getClassLoader()).stream()
                .filter(value -> id.equals(value.definition().profileId())).findFirst().orElseThrow();
    }

    private static byte[] csr(KeyPair key) throws Exception {
        ExtensionsGenerator extensions = new ExtensionsGenerator();
        extensions.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, IDENTIFIER)));
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=" + IDENTIFIER), key.getPublic());
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded();
    }

    private static List<X509Certificate> certificates(String pem) throws Exception {
        List<X509Certificate> result = new ArrayList<>();
        String begin = "-----BEGIN CERTIFICATE-----";
        String end = "-----END CERTIFICATE-----";
        int offset = 0;
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        while ((offset = pem.indexOf(begin, offset)) >= 0) {
            int last = pem.indexOf(end, offset);
            String encoded = pem.substring(offset + begin.length(), last).replaceAll("\\s", "");
            result.add((X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(Base64.getDecoder().decode(encoded))));
            offset = last + end.length();
        }
        return List.copyOf(result);
    }

    private static KeyPair rsa(byte seed) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, random(seed));
        return generator.generateKeyPair();
    }

    private static KeyPair ec(byte seed) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"), random(seed));
        return generator.generateKeyPair();
    }

    private static SecureRandom random(byte seed) throws Exception {
        SecureRandom result = SecureRandom.getInstance("SHA1PRNG");
        result.setSeed(new byte[] { 2, 4, 6, 8, seed });
        return result;
    }

    private static int reservePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return socket.getLocalPort();
        }
    }

    private record Fixture(PkiServerConfiguration configuration, PkiSessionRuntimeDependencies dependencies,
            ProviderConfig http01) { }

    private static final class Http01Responder implements AutoCloseable {
        private final String token;
        private final String body;
        private final ServerSocket listener;
        private final CountDownLatch completed = new CountDownLatch(1);
        private final AtomicReference<Throwable> failure = new AtomicReference<>();
        private Thread thread;

        Http01Responder(int port, String token, String body) throws Exception {
            this.token = token;
            this.body = body;
            listener = new ServerSocket(port, 1, InetAddress.getByName("127.0.0.1"));
        }

        void start() {
            thread = new Thread(this::serve, "zeroecho-acme-http01-fixture");
            thread.start();
        }

        void await() throws Exception {
            assertTrue(completed.await(10, TimeUnit.SECONDS));
            if (failure.get() != null) throw new AssertionError("HTTP-01 responder failed", failure.get());
        }

        private void serve() {
            try (Socket connection = listener.accept()) {
                connection.setSoTimeout(5_000);
                ByteArrayOutputStream request = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                while (!request.toString(StandardCharsets.US_ASCII).contains("\r\n\r\n")) {
                    int count = connection.getInputStream().read(buffer);
                    if (count < 0 || request.size() + count > 16_384) throw new IllegalStateException("bad request");
                    request.write(buffer, 0, count);
                }
                assertTrue(request.toString(StandardCharsets.US_ASCII)
                        .startsWith("GET /.well-known/acme-challenge/" + token + " HTTP/1.1\r\n"));
                byte[] content = body.getBytes(StandardCharsets.US_ASCII);
                connection.getOutputStream().write(("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                        + content.length + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                connection.getOutputStream().write(content);
                connection.getOutputStream().flush();
            } catch (Throwable problem) {
                failure.set(problem);
            } finally {
                completed.countDown();
            }
        }

        @Override public void close() throws Exception {
            listener.close();
            if (thread != null) thread.join(5_000);
        }
    }
}
