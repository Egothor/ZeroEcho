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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
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
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
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
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.revocation.RevocationQuery;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.RevocationExecutionEvidence;
import zeroecho.pki.impl.framework.x509.bc.SimpleAttributeSet;
import zeroecho.pki.server.acme.AcmeService;
import zeroecho.pki.server.acme.AcmeState;
import zeroecho.pki.server.acme.Http01ChallengeProvider;
import zeroecho.pki.server.acme.TestAcmeEabProvider;
import zeroecho.pki.server.http.AcmeTestClient;
import zeroecho.pki.server.http.TestTlsProvider;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.store.RevocationHistory;
import zeroecho.pki.spi.store.RevocationSnapshot;

/** Complete wire-level ACME account-to-revocation integration. */
@SuppressWarnings("PMD")
class AcmeEndToEndTest {
    // The installed signing provider and the subprocess use the real UTC clock.
    private static final Clock CLOCK = Clock.systemUTC();
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
        int publicPort = reservePort();
        int challengePort = reservePort();
        KeyPair rootKey = rsa((byte) 21);
        KeyPair leafKey = rsa((byte) 22);
        KeyPair accountKey = ec((byte) 23);
        KeyPair replacementKey = ec((byte) 24);
        KeyPair otherAccountKey = ec((byte) 26);
        Fixture fixture = fixture(tls, acmePort, publicPort, challengePort, rootKey);
        seed(fixture);

        URI directoryUri = URI.create("https://localhost:" + acmePort + "/acme/" + DIRECTORY_ALIAS
                + "/directory");
        HttpClient wire = HttpClient.newBuilder().sslContext(tls.anonymousContext())
                .connectTimeout(Duration.ofSeconds(5)).build();
        String accountKid;
        String otherAccountKid;
        URI accountUri;
        URI orderUri;
        URI certificateUri;
        URI confirmationCompleteUri;
        URI nonceUri;
        URI revokeUri;
        PkiId issuedAuthorityId;
        String confirmationCompletionPayload;
        byte[] leafDer;
        String revocationRequestId;
        try (PkiHttpsServer server = start(fixture);
                AcmeTestClient client = new AcmeTestClient(wire, directoryUri, accountKey)) {
            verifyEabOverHttp(wire, acmePort, ec((byte) 25));
            AcmeTestClient.Response directory = client.directory();
            assertEquals(200, directory.status());
            nonceUri = URI.create(AcmeTestClient.text(directory, "newNonce"));
            URI newAccount = URI.create(AcmeTestClient.text(directory, "newAccount"));
            URI newOrder = URI.create(AcmeTestClient.text(directory, "newOrder"));
            URI keyChange = URI.create(AcmeTestClient.text(directory, "keyChange"));
            revokeUri = URI.create(AcmeTestClient.text(directory, "revokeCert"));
            client.nonce(nonceUri);
            AcmeTestClient.Response account = client.createAccount(newAccount,
                    "{\"termsOfServiceAgreed\":true}");
            assertEquals(201, account.status());
            accountKid = client.accountKid();
            accountUri = URI.create(accountKid);
            try (AcmeTestClient other = new AcmeTestClient(wire, directoryUri, otherAccountKey)) {
                other.nonce(nonceUri);
                assertEquals(201, other.createAccount(newAccount,
                        "{\"termsOfServiceAgreed\":true}").status());
                otherAccountKid = other.accountKid();
            }

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
            byte[] newerProfile = new String(template("server-tls").canonicalJson(), StandardCharsets.UTF_8)
                    .replace("\"profileVersion\":1", "\"profileVersion\":2")
                    .getBytes(StandardCharsets.UTF_8);
            server.realm().session().profiles().importProfile(newerProfile);
            server.realm().session().profiles().activateProfile("server-tls", 2L);
            String csr = Base64.getUrlEncoder().withoutPadding().encodeToString(csr(leafKey));
            AcmeTestClient.Response finalized = client.kid(finalizeUri, "{\"csr\":\"" + csr + "\"}");
            finalized = awaitValidOrder(client, orderUri, finalized);
            assertEquals("valid", AcmeTestClient.text(finalized, "status"));
            certificateUri = URI.create(AcmeTestClient.text(finalized, "certificate"));
            AcmeTestClient.Response certificate = client.postAsGet(certificateUri);
            assertEquals(200, certificate.status());
            String orderId = orderUri.getPath().substring(orderUri.getPath().lastIndexOf('/') + 1);
            AcmeState.Order issuedOrder = server.realm().acmeControl().get(AcmeState.Order.class, orderId)
                    .orElseThrow();
            PkiId issuedCredentialId = issuedOrder.credentialId().orElseThrow();
            issuedAuthorityId = issuedOrder.authorityId();
            assertEquals(1L, ((zeroecho.pki.api.credential.EndEntityProfileBinding) server.realm().session()
                    .repository().credential(issuedCredentialId).orElseThrow().profileBinding())
                    .reference().profileVersion());
            assertEquals(zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle.State.PENDING,
                    server.realm().session().confirmations().get(issuedCredentialId).orElseThrow().state());
            PkiOperationValue.ObjectValue confirmation = object(finalized, "credentialConfirmation");
            assertEquals(1L, integer(confirmation, "version"));
            URI confirmationChallengeUri = URI.create(text(confirmation, "challenge"));
            confirmationCompleteUri = URI.create(text(confirmation, "complete"));
            AcmeState.Directory activeDirectory = server.realm().acmeControl()
                    .get(AcmeState.Directory.class, issuedOrder.directoryId()).orElseThrow();
            replaceDirectoryStatus(server, activeDirectory, AcmeState.DirectoryStatus.INACTIVE);
            assertEquals(200, client.postAsGet(orderUri).status());
            assertFalse(client.kid(newOrder,
                    "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"localhost\"}]}").status() == 201);
            AcmeTestClient.Response proofChallenge = client.kid(confirmationChallengeUri, "{}");
            assertEquals(1L, integer(proofChallenge.json(), "version"));
            byte[] presentation = Base64.getUrlDecoder().decode(
                    AcmeTestClient.text(proofChallenge, "presentation"));
            byte[] proof;
            try {
                Signature signer = Signature.getInstance("RSASSA-PSS");
                signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1",
                        MGF1ParameterSpec.SHA256, 32, 1));
                signer.initSign(leafKey.getPrivate());
                signer.update(presentation);
                proof = signer.sign();
            } finally {
                java.util.Arrays.fill(presentation, (byte) 0);
            }
            confirmationCompletionPayload = confirmationCompletionPayload(proofChallenge, proof);
            java.util.Arrays.fill(proof, (byte) 0);
            URI anonymousCertificate = URI.create("https://localhost:" + publicPort
                    + "/public/v1/certificates/" + issuedCredentialId.value());
            java.net.http.HttpResponse<Void> anonymousResponse = wire.send(
                    java.net.http.HttpRequest.newBuilder(anonymousCertificate).GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.discarding());
            assertEquals(404, anonymousResponse.statusCode());
            List<X509Certificate> chain = certificates(certificate.bodyText());
            assertEquals(2, chain.size());
            assertEquals(List.of(IDENTIFIER), chain.get(0).getSubjectAlternativeNames().stream()
                    .filter(value -> Integer.valueOf(2).equals(value.get(0))).map(value -> value.get(1).toString())
                    .toList());
            chain.get(0).verify(chain.get(1).getPublicKey());
            awaitCertificateValidity(chain.get(0));
            leafDer = chain.get(0).getEncoded();
            assertOcsp(wire, publicPort, chain.get(1), chain.get(0), false);
            assertOcspNonce(wire, publicPort, chain.get(1), chain.get(0));
            assertOcspUnknownAndMulti(wire, publicPort, chain.get(1), chain.get(0));
            assertOcspNoncePolicies(wire, publicPort, chain.get(1), chain.get(0));
            assertSignedOcsp(wire, publicPort, chain.get(1), chain.get(0), rsa((byte) 81),
                    requesterCertificate(rsa((byte) 81)), "signed", true, false);
            assertSignedOcsp(wire, publicPort, chain.get(1), chain.get(0), rsa((byte) 81),
                    requesterCertificate(rsa((byte) 81)), "mixed", false, false);

            assertEquals(200, client.rollover(keyChange, replacementKey).status());
            assertEquals(200, client.postAsGet(accountUri).status());
            System.out.println("...https-jws-http01-issuance=true");
        }

        registerManagedRequester(fixture, leafDer, leafKey);
        try (ServerRealmContext context = ServerRealmContext.open(fixture.configuration().realm(),
                fixture.dependencies(), CLOCK, HttpServerTestSupport.random())) {
            assertInstanceOf(zeroecho.pki.application.PkiOperationOutcome.Completed.class,
                    context.session().operations().execute(new zeroecho.pki.application.PkiOperation.TransitionAuthority(
                            issuedAuthorityId, CaState.RETIRED, "ACME frozen-binding continuation test"),
                            zeroecho.core.io.CancellationSignal.NONE));
        }

        try (PkiHttpsServer restarted = start(fixture);
                AcmeTestClient replacement = new AcmeTestClient(wire, directoryUri, replacementKey);
                AcmeTestClient old = new AcmeTestClient(wire, directoryUri, accountKey);
                AcmeTestClient other = new AcmeTestClient(wire, directoryUri, otherAccountKey)) {
            replaceImmediateAuditWithThrowingSink(restarted.realm());
            replacement.nonce(nonceUri); replacement.useAccount(accountKid);
            assertEquals(200, replacement.postAsGet(accountUri).status());
            old.nonce(nonceUri); old.useAccount(accountKid);
            assertEquals(403, old.postAsGet(accountUri).status());
            assertEquals(403, old.kid(confirmationCompleteUri, confirmationCompletionPayload).status());
            other.nonce(nonceUri); other.useAccount(otherAccountKid);
            assertFalse(other.postAsGet(orderUri).status() == 200);
            assertEquals(200, replacement.postAsGet(orderUri).status());
            String emptyResponse = confirmationCompletionPayload.replaceFirst(
                    "\"response\":\"[^\"]+\"", "\"response\":\"\"");
            assertFalse(replacement.kid(confirmationCompleteUri, emptyResponse).status() == 200);
            String paddedResponse = confirmationCompletionPayload.replaceFirst(
                    "\"response\":\"[^\"]+\"", "\"response\":\"AQ==\"");
            assertFalse(replacement.kid(confirmationCompleteUri, paddedResponse).status() == 200);
            String oversizedResponse = confirmationCompletionPayload.replaceFirst(
                    "\"response\":\"[^\"]+\"", "\"response\":\"" + "A".repeat(
                            zeroecho.pki.server.acme.AcmeWireBounds.MAX_PROOF_B64URL_CHARS + 1) + "\"");
            assertFalse(replacement.kid(confirmationCompleteUri, oversizedResponse).status() == 200);
            String staleCas = confirmationCompletionPayload.replaceFirst(
                    "\"expectedChallengeRecordCommitment\":\"[^\"]+\"",
                    "\"expectedChallengeRecordCommitment\":\"" + "f".repeat(64) + "\"");
            assertFalse(replacement.kid(confirmationCompleteUri, staleCas).status() == 200);
            String rejectedPayload = confirmationCompletionPayload.replaceFirst(
                    "\"response\":\"[^\"]+\"", "\"response\":\"AQ\"");
            assertEquals("REJECTED", AcmeTestClient.text(
                    replacement.kid(confirmationCompleteUri, rejectedPayload), "confirmationResult"));
            assertEquals("CONFIRMED", AcmeTestClient.text(
                    replacement.kid(confirmationCompleteUri, confirmationCompletionPayload),
                    "confirmationResult"));
            assertEquals("CONFIRMED", AcmeTestClient.text(
                    replacement.kid(confirmationCompleteUri, confirmationCompletionPayload),
                    "confirmationResult"));
            assertFalse(replacement.postAsGet(orderUri).json().fields().containsKey("credentialConfirmation"));
            assertEquals(200, replacement.postAsGet(certificateUri).status());
            X509Certificate requesterCertificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(leafDer));
            List<X509Certificate> preRevocationChain = certificates(
                    replacement.postAsGet(certificateUri).bodyText());
            assertSignedOcsp(wire, publicPort, preRevocationChain.get(1), requesterCertificate, leafKey,
                    requesterCertificate, "managed", true, false);
            String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(leafDer);
            AcmeTestClient.Response revocation = replacement.kid(revokeUri,
                    "{\"certificate\":\"" + encoded + "\",\"reason\":1}");
            assertEquals(200, revocation.status());
            revocationRequestId = revocation.header("X-ZeroEcho-Request-Id").orElseThrow();
            List<X509Certificate> chain = certificates(replacement.postAsGet(certificateUri).bodyText());
            assertOcsp(wire, publicPort, chain.get(1), chain.get(0), true);
            assertSignedOcsp(wire, publicPort, chain.get(1), chain.get(0), rsa((byte) 81),
                    requesterCertificate(rsa((byte) 81)), "signed", true, true);
            assertSignedOcspUnauthorized(wire, publicPort, chain.get(1), requesterCertificate, leafKey,
                    requesterCertificate, "managed");
            assertFalse(replacement.kid(revokeUri,
                    "{\"certificate\":\"" + encoded + "\",\"reason\":1}").status() == 200);
            System.out.println("...rollover-restart-revocation=true");
        }
        try (ServerRealmContext context = ServerRealmContext.open(fixture.configuration().realm(),
                fixture.dependencies(), CLOCK, HttpServerTestSupport.random());
                RevocationSnapshot snapshot = context.session().revocations().search(new RevocationQuery(
                        Optional.empty(), Optional.of(RevocationReason.KEY_COMPROMISE), Optional.empty(),
                        Optional.empty())); RevocationSnapshot.Cursor cursor = snapshot.openCursor()) {
            assertTrue(cursor.next());
            try (RevocationHistory history = context.session().revocations().history(cursor.current().credentialId())) {
                assertTrue(history.next());
                zeroecho.pki.api.revocation.RevocationTransition transition = history.current();
                assertEquals("ACME_ACCOUNT", stringAttribute(transition, RevocationExecutionEvidence.ACTOR_TYPE));
                assertEquals("ACME_ACCOUNT_JWS",
                        stringAttribute(transition, RevocationExecutionEvidence.AUTHENTICATION));
                assertEquals("ACME_OWNERSHIP",
                        stringAttribute(transition, RevocationExecutionEvidence.AUTHORIZATION));
                assertEquals(revocationRequestId,
                        stringAttribute(transition, RevocationExecutionEvidence.REQUEST_ID));
                assertEquals(accountUri.getPath().substring(accountUri.getPath().lastIndexOf('/') + 1),
                        stringAttribute(transition, RevocationExecutionEvidence.ACTOR_ID));
                assertFalse(transition.attributes().ids().contains(RevocationExecutionEvidence.AUTHORIZATION_PATH));
                assertFalse(transition.attributes().ids().contains(RevocationExecutionEvidence.OPERATION_COMMITMENT));
            }
            assertFalse(cursor.next());
        }
        System.out.println("...ok");
    }

    private static String confirmationCompletionPayload(AcmeTestClient.Response challenge, byte[] proof) {
        return "{\"expectedLifecycleRevision\":" + integer(challenge.json(), "expectedLifecycleRevision")
                + ",\"expectedLifecycleRecordCommitment\":\""
                + AcmeTestClient.text(challenge, "expectedLifecycleRecordCommitment")
                + "\",\"expectedChallengeRecordCommitment\":\""
                + AcmeTestClient.text(challenge, "expectedChallengeRecordCommitment")
                + "\",\"response\":\"" + Base64.getUrlEncoder().withoutPadding().encodeToString(proof)
                + "\"}";
    }

    private static PkiOperationValue.ObjectValue object(AcmeTestClient.Response response, String field) {
        PkiOperationValue value = response.json().fields().get(field);
        return assertInstanceOf(PkiOperationValue.ObjectValue.class, value);
    }

    private static long integer(PkiOperationValue.ObjectValue value, String field) {
        return assertInstanceOf(PkiOperationValue.IntegerValue.class, value.fields().get(field)).value();
    }

    private static String text(PkiOperationValue.ObjectValue value, String field) {
        return assertInstanceOf(PkiOperationValue.Text.class, value.fields().get(field)).value();
    }

    private static AcmeState.Directory replaceDirectoryStatus(PkiHttpsServer server,
            AcmeState.Directory current, AcmeState.DirectoryStatus status) {
        AcmeState.Directory replacement = new AcmeState.Directory(current.directoryId(), current.alias(),
                current.revision(), current.realmId(), current.authorityId(), current.profile(),
                current.issuerId(), current.issuancePathId(), current.issuancePathCommitment(),
                current.identifierTypes(), current.dnsNamespaces(), current.maximumValidity(),
                current.publicKeyAlgorithms(), current.x509BindingPolicies(), current.challengeTypes(),
                current.challengeProviderIds(), current.eabProviderId(), current.eabRequired(),
                current.confirmationPolicy(), current.confirmationPolicyCommitment(), status,
                current.policyCommitment(), current.createdAt(), "0".repeat(64));
        return (AcmeState.Directory) server.realm().acmeControl().replace(List.of(
                new zeroecho.pki.server.acme.AcmeControlStore.Replacement(current, replacement))).get(0);
    }

    private static String stringAttribute(zeroecho.pki.api.revocation.RevocationTransition transition,
            zeroecho.pki.api.attr.AttributeId id) {
        return ((AttributeValue.StringValue) transition.attributes().get(id).orElseThrow()).value();
    }

    private static void replaceImmediateAuditWithThrowingSink(ServerRealmContext context) throws Exception {
        Field field = ServerRealmContext.class.getDeclaredField("audit");
        field.setAccessible(true);
        field.set(context, new SafeAudit(CLOCK, event -> {
            throw new IllegalStateException("immediate ACME audit unavailable");
        }));
    }

    @Test
    void completesInstalledDistributionAccountToRevocationWorkflow() throws Exception {
        System.out.println("completesInstalledDistributionAccountToRevocationWorkflow");
        Path root = temporaryDirectory.resolve("packaged");
        java.nio.file.Files.createDirectories(root);
        try {
            java.nio.file.Files.setPosixFilePermissions(root, java.nio.file.attribute.PosixFilePermissions
                    .fromString("rwx------"));
        } catch (UnsupportedOperationException ignored) { /* Windows */ }
        HttpServerTestSupport.PackagedTls tls = HttpServerTestSupport.packagedTls(root.resolve("tls"));
        int adminPort = reservePort();
        int acmePort = reservePort();
        int publicPort = reservePort();
        int challengePort = reservePort();
        KeyPair rootKey = rsa((byte) 41);
        Fixture fixture = packagedFixture(root, tls, adminPort, acmePort, publicPort, challengePort, rootKey);
        seed(fixture, false);
        Path configuration = root.resolve("server.json");
        java.nio.file.Files.writeString(configuration, packagedJson(fixture.configuration(), tls),
                StandardCharsets.UTF_8);
        String scriptName = System.getProperty("os.name", "").toLowerCase().contains("win")
                ? "zeroecho-pki-server.bat" : "zeroecho-pki-server";
        Path launcher = Path.of(System.getProperty("user.dir"), "build", "install", "zeroecho-pki-server", "bin",
                scriptName).toAbsolutePath();
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
        X509Certificate packagedIssuer = null;
        X509Certificate packagedCertificate = null;
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
                finalized = awaitValidOrder(client, orderUri, finalized);
                URI certificate = URI.create(AcmeTestClient.text(finalized, "certificate"));
                List<X509Certificate> chain = certificates(client.postAsGet(certificate).bodyText());
                awaitCertificateValidity(chain.get(0));
                assertEquals(2, chain.size());
                packagedCertificate = chain.get(0);
                packagedIssuer = chain.get(1);
                assertOcsp(wire, publicPort, chain.get(1), chain.get(0), false);
                assertSignedOcsp(wire, publicPort, chain.get(1), chain.get(0), rsa((byte) 81),
                        requesterCertificate(rsa((byte) 81)), "signed", true, false);
                assertEquals(200, client.rollover(rollover, replacement).status());
                String der = Base64.getUrlEncoder().withoutPadding().encodeToString(chain.get(0).getEncoded());
                assertEquals(200, client.kid(revoke,
                        "{\"certificate\":\"" + der + "\",\"reason\":1}").status());
                assertOcsp(wire, publicPort, chain.get(1), chain.get(0), true);
            }
            System.out.println("...installed-launcher-flow=true");
        } finally {
            destroyProcessTree(process);
        }
        denyPackagedSignedRequester(fixture);
        Process deniedProcess = builder.start();
        try {
            awaitDirectory(wire, directoryUri, deniedProcess, output);
            assertSignedOcspUnauthorized(wire, publicPort,
                    java.util.Objects.requireNonNull(packagedIssuer),
                    java.util.Objects.requireNonNull(packagedCertificate), rsa((byte) 81),
                    requesterCertificate(rsa((byte) 81)), "signed");
        } finally {
            destroyProcessTree(deniedProcess);
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

    private Fixture fixture(HttpServerTestSupport.Fixture tls, int acmePort, int publicPort, int challengePort,
            KeyPair rootKey) throws Exception {
        Path root = temporaryDirectory.resolve("server");
        PkiServerConfiguration base = HttpServerTestSupport.configuration(root, tls.clientCertificate());
        try {
            java.nio.file.Files.setPosixFilePermissions(root, java.nio.file.attribute.PosixFilePermissions
                    .fromString("rwx------"));
        } catch (UnsupportedOperationException ignored) { /* Windows */ }
        Path keyring = root.resolve("signing-keyring.zek");
        try (KeyringPassword password = new KeyringPassword(KEYRING_PASSWORD.clone());
                KeyringStore store = KeyringStore.create(keyring, password)) {
            store.putPrivate("root.prv", "RSA", rootKey.getPrivate());
            store.putPublic("root.pub", "RSA", rootKey.getPublic());
        }
        ProviderConfig workflow = new ProviderConfig("zeroecho-lib", Map.of(
                "keyringPath", keyring.toString(),
                "keyRefPrefix", "acme-test:", "requireComponentSuffix", "true"));
        PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                workflow, zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(),
                Duration.ofSeconds(10), Optional.empty(),
                signingTopology(), java.util.OptionalLong.empty());
        PkiSessionConfiguration session = new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                base.realm().pkiSessionConfiguration().store(), base.realm().pkiSessionConfiguration().audit(),
                Optional.of(signing), List.of(), List.of());
        ServerRealmConfiguration realm = new ServerRealmConfiguration(base.realm().realmId(),
                base.realm().displayName(), base.realm().confirmationProofPolicy(), session,
                base.realm().authorityExposure(),
                base.realm().authorizationCommitment(), base.realm().approvalCommitment(),
                base.realm().extendedApprovalCommitment(),
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
        PkiServerConfiguration.PublicListener publicListener = new PkiServerConfiguration.PublicListener(
                InetAddress.getByName("127.0.0.1"), publicPort,
                Optional.of(new ProviderConfig("test-tls", Map.of())), false, base.authentication(),
                16_384, 65_536, lane, Duration.ofSeconds(20), Duration.ofMinutes(5),
                Duration.ofSeconds(30), true);
        PkiServerConfiguration configuration = new PkiServerConfiguration(base.version(), base.serverName(), realm,
                base.listener(), base.authentication(), base.execution(), base.runtime(), Optional.of(publicListener),
                Optional.of(acme));
        PkiSessionRuntimeDependencies dependencies = PkiSessionRuntimeDependencies.withKeyringUnlockProvider(
                () -> new KeyringPassword(KEYRING_PASSWORD.clone()));
        return new Fixture(configuration, dependencies, http01);
    }

    private void seed(Fixture fixture) throws Exception {
        seed(fixture, true);
    }

    private static PkiSessionConfiguration.SigningTopology signingTopology() {
        return new PkiSessionConfiguration.SigningTopology(
                new PkiSessionConfiguration.SigningCoordinatorLimits(2, Duration.ofSeconds(10),
                        Duration.ofSeconds(5), Duration.ofMillis(10), Duration.ofSeconds(5)),
                List.of(), new PkiSessionConfiguration.SigningLanePool(2, 3));
    }

    private static zeroecho.pki.api.signing.SemanticSigningOperation awaitSigning(
            zeroecho.pki.api.SemanticSigningService service, PkiId id) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            zeroecho.pki.api.signing.SemanticSigningOperation value = service.find(id).orElseThrow();
            if (value.state() != zeroecho.pki.api.signing.SemanticSigningState.SIGNING
                    && value.state() != zeroecho.pki.api.signing.SemanticSigningState.PUBLISHING) {
                assertEquals(zeroecho.pki.api.signing.SemanticSigningState.COMPLETED, value.state());
                return value;
            }
            java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
        }
        throw new AssertionError("Root preparation did not complete");
    }

    private void seed(Fixture fixture, boolean includeEab) throws Exception {
        try (ServerRealmContext context = ServerRealmContext.open(fixture.configuration().realm(),
                fixture.dependencies(), CLOCK, HttpServerTestSupport.random())) {
            BuiltInCertificateProfileTemplate root = template("root-ca");
            BuiltInCertificateProfileTemplate leaf = template("server-tls");
            context.session().profiles().importBuiltIn(root);
            context.session().profiles().activateProfile("root-ca", root.definition().profileVersion());
            context.session().profiles().importBuiltIn(leaf);
            context.session().profiles().activateProfile("server-tls", leaf.definition().profileVersion());
            zeroecho.pki.api.SemanticSigningService signing = context.session().semanticSigning().orElseThrow();
            zeroecho.pki.api.signing.PreparedSemanticSigningRequest prepared = signing.prepareRootCreation(
                    new zeroecho.pki.api.audit.AccessContext(new zeroecho.pki.api.audit.Principal("SYSTEM", "test"),
                            new zeroecho.pki.api.audit.Purpose("ca.create"), Optional.empty(), Optional.empty()),
                    new CaCreateCommand(
                    root.definition().formatId(), new SubjectRef("CN=ZeroEcho ACME E2E Root"), "root-ca",
                    new KeyRef("acme-test:root.prv"), new SimpleAttributeSet()),
                    zeroecho.core.io.CancellationSignal.NONE);
            zeroecho.pki.api.signing.SigningAcceptanceResult accepted = signing.accept(prepared);
            assertEquals(zeroecho.pki.api.signing.SigningAcceptanceDisposition.ACCEPTED, accepted.disposition());
            PkiId rootCredential = awaitSigning(signing, accepted.receipt().operationId())
                    .completedCredentialId().orElseThrow();
            X509Certificate rootCertificate;
            try (zeroecho.pki.application.PkiRepositoryContent content = context.session().repository()
                    .openCredential(rootCredential); java.io.InputStream input = content.openStream()) {
                rootCertificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(input);
            }
            zeroecho.pki.api.Validity rootValidity = context.session().repository()
                    .credential(rootCredential).orElseThrow().validity();
            assertEquals(rootValidity.notBefore(), rootCertificate.getNotBefore().toInstant());
            assertEquals(rootValidity.notAfter(), rootCertificate.getNotAfter().toInstant());
            awaitCertificateValidity(rootCertificate);
            PkiId authority = context.session().repository().credential(rootCredential).orElseThrow().issuerRef().caId();
            zeroecho.pki.api.ca.CaRecord authorityRecord = context.session().repository().authority(authority)
                    .orElseThrow();
            zeroecho.pki.api.ca.IssuerGeneration issuer = context.session().repository()
                    .issuer(authorityRecord.currentIssuanceIssuerId()).orElseThrow();
            OcspResponderService.Responder responder = context.ocspResponders().create("ocsp-e2e-root", "root",
                    authority, issuer.issuerId(), OcspResponderService.SigningMode.ISSUER_SIGNED,
                    issuer.credentialId(), issuer.signingKeyRef(), authorityRecord.issuanceChainPathId(),
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), Optional.empty(),
                    context.session().algorithmBindings().commitment(),
                    zeroecho.pki.application.OcspResponseService.ResponderId.BY_KEY, Duration.ofMinutes(5),
                    OcspResponderService.NoncePolicy.OPTIONAL_ECHO, 64,
                    Set.of(zeroecho.pki.application.OcspResponseService.CertIdHash.SHA1,
                            zeroecho.pki.application.OcspResponseService.CertIdHash.SHA256),
                    16_384, 8, Duration.ofMinutes(1));
            context.ocspResponders().setActive(context.ocspResponders().register(responder).responderId(), true);
            registerSignedResponder(context, responder, authority, issuer.issuerId());
            registerNonceResponder(context, responder, "ocsp-e2e-reject", "reject",
                    OcspResponderService.NoncePolicy.REJECT);
            registerNonceResponder(context, responder, "ocsp-e2e-required", "required",
                    OcspResponderService.NoncePolicy.REQUIRED);
            ActiveCertificateProfile active = context.session().profiles().requireActiveProfile("server-tls");
            AcmeService service = new AcmeService(context, CLOCK, HttpServerTestSupport.random(),
                    Map.of(Http01ChallengeProvider.ID, new Http01ChallengeProvider()),
                    Map.of(Http01ChallengeProvider.ID, fixture.http01()),
                    Map.of(TestAcmeEabProvider.ID, new TestAcmeEabProvider()),
                    Map.of(TestAcmeEabProvider.ID, new ProviderConfig(TestAcmeEabProvider.ID, Map.of())));
            AcmeState.Directory directory = service.registerDirectory(new AcmeService.DirectoryRegistration(
                    DIRECTORY_ALIAS, authority, "server-tls", Set.of(IDENTIFIER), Duration.ofDays(30),
                    active.definition().leafPolicy().allowedSubjectKeyAlgorithmIds(), Set.of("STANDARD_ONLY"),
                    Set.of(AcmeState.ChallengeType.HTTP_01), Set.of(Http01ChallengeProvider.ID), Optional.empty(),
                    false));
            service.activateDirectory(directory.directoryId());
            if (includeEab) {
                AcmeState.Directory eab = service.registerDirectory(new AcmeService.DirectoryRegistration(
                        EAB_DIRECTORY_ALIAS, authority, "server-tls", Set.of(IDENTIFIER), Duration.ofDays(30),
                        active.definition().leafPolicy().allowedSubjectKeyAlgorithmIds(), Set.of("STANDARD_ONLY"),
                        Set.of(AcmeState.ChallengeType.HTTP_01), Set.of(Http01ChallengeProvider.ID),
                        Optional.of(TestAcmeEabProvider.ID), true));
                service.activateDirectory(eab.directoryId());
            }
            assertEquals(authority, context.session().repository().authority(authority).orElseThrow().caId());
        }
    }

    private static void awaitCertificateValidity(X509Certificate certificate) throws Exception {
        Instant notBefore = certificate.getNotBefore().toInstant();
        // Inward DER normalization can move the approved start to the next whole second.
        assertFalse(notBefore.isAfter(CLOCK.instant().plusSeconds(1)),
                "Fresh certificate starts beyond the whole-second normalization boundary");
        while (CLOCK.instant().isBefore(notBefore)) {
            java.util.concurrent.TimeUnit.NANOSECONDS.sleep(Math.max(1,
                    Duration.between(CLOCK.instant(), notBefore).toNanos()));
        }
        certificate.checkValidity(java.util.Date.from(CLOCK.instant()));
    }

    private static void registerNonceResponder(ServerRealmContext context,
            OcspResponderService.Responder template, String responderId, String alias,
            OcspResponderService.NoncePolicy noncePolicy) {
        OcspResponderService.Responder responder = context.ocspResponders().create(responderId, alias,
                template.authorityId(), template.issuerId(), template.signingMode(),
                template.responderCredentialId(), template.signingKeyRef(), template.chainPathId(),
                template.signatureAlgorithm(), template.signatureBindingId(),
                template.signatureBindingCommitment(), template.responderIdForm(), template.responseValidity(),
                noncePolicy, template.maximumNonceBytes(), template.acceptedHashes(),
                template.maximumRequestBytes(), template.maximumEntries(), template.cacheLifetime());
        context.ocspResponders().setActive(context.ocspResponders().register(responder).responderId(), true);
    }

    private static void registerManagedRequester(Fixture fixture, byte[] requesterDer, KeyPair requesterKey)
            throws Exception {
        X509Certificate requester = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(requesterDer));
        try (ServerRealmContext context = ServerRealmContext.open(fixture.configuration().realm(),
                fixture.dependencies(), CLOCK, HttpServerTestSupport.random())) {
            OcspResponderService.Responder template = context.ocspResponders().requireAlias("root");
            String commitment = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(requesterDer));
            context.createPrincipal(new SecurityPrincipal("managed-ocsp-requester", SecurityPrincipal.Type.SERVICE,
                    "Managed OCSP requester", Optional.empty(), Map.of(), true), "system");
            Permission.Scope scope = new Permission.Scope(context.configuration().realmId(),
                    Optional.of(template.authorityId()), Optional.of(template.issuerId()), Optional.empty(),
                    Optional.of("ocsp-e2e-managed"));
            context.grant(new Permission.Grant("ocsp-query-managed-e2e", "managed-ocsp-requester",
                    Permission.Effect.ALLOW, Permission.Action.OCSP_STATUS_QUERY,
                    Permission.ResourceType.OCSP_RESPONDER, scope, Permission.Relationship.ANY,
                    Permission.DataView.METADATA_REDACTED, Set.of(), Optional.empty(), true), "system");
            zeroecho.pki.api.algorithm.X509AlgorithmBinding binding = context.session().algorithmBindings()
                    .standard(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                            zeroecho.pki.api.algorithm.X509AlgorithmBinding.Role.OCSP_REQUEST_SIGNATURE)
                    .orElseThrow();
            OcspResponderService.RequesterTrustPolicy policy = new OcspResponderService.RequesterTrustPolicy(
                    List.of(new OcspResponderService.TrustSelector(
                            OcspResponderService.TrustSelectorType.MANAGED_ISSUER_GENERATIONS,
                            Set.of(template.issuerId().value()))),
                    List.of(new OcspResponderService.PrincipalMapping("managed-requester-cert",
                            "managed-ocsp-requester",
                            OcspResponderService.PrincipalMappingType.SHA256_CERTIFICATE_COMMITMENT, commitment)),
                    List.of(new OcspResponderService.RequestSignatureBinding(binding.bindingId(),
                            binding.semanticCommitment())),
                    OcspResponderService.RequesterRevocationPolicy.LOCAL_AUTHORITATIVE_REQUIRED, 3, 131_072);
            assertTrue(context.session().repository().credential(template.issuerId(), requester.getSerialNumber())
                    .isPresent());
            OcspResponderService.Responder responder = context.ocspResponders().create("ocsp-e2e-managed",
                    "managed", template.authorityId(), template.issuerId(), template.signingMode(),
                    template.responderCredentialId(), template.signingKeyRef(), template.chainPathId(),
                    template.signatureAlgorithm(), template.signatureBindingId(),
                    template.signatureBindingCommitment(), template.responderIdForm(), template.responseValidity(),
                    template.noncePolicy(), template.maximumNonceBytes(), template.acceptedHashes(),
                    template.maximumRequestBytes(), template.maximumEntries(), template.cacheLifetime(),
                    OcspResponderService.RequestAuthenticationMode.AUTHORIZED_SIGNED_REQUIRED,
                    Optional.of(policy));
            OcspResponderService.Responder active = context.ocspResponders().setActive(
                    context.ocspResponders().register(responder).responderId(), true);
            assertRequesterService(context, active, requesterKey, requester);
        }
    }

    private static void denyPackagedSignedRequester(Fixture fixture) throws Exception {
        try (ServerRealmContext context = ServerRealmContext.open(fixture.configuration().realm(),
                fixture.dependencies(), CLOCK, HttpServerTestSupport.random())) {
            OcspResponderService.Responder responder = context.ocspResponders().requireAlias("signed");
            Permission.Scope scope = new Permission.Scope(context.configuration().realmId(),
                    Optional.of(responder.authorityId()), Optional.of(responder.issuerId()), Optional.empty(),
                    Optional.of(responder.responderId()));
            context.grant(new Permission.Grant("ocsp-query-e2e-deny", "ocsp-requester",
                    Permission.Effect.DENY, Permission.Action.OCSP_STATUS_QUERY,
                    Permission.ResourceType.OCSP_RESPONDER, scope, Permission.Relationship.ANY,
                    Permission.DataView.METADATA_REDACTED, Set.of(), Optional.empty(), true), "system");
        }
    }

    private static void registerSignedResponder(ServerRealmContext context,
            OcspResponderService.Responder template, PkiId authority, PkiId issuerId) throws Exception {
        KeyPair requesterKey = rsa((byte) 81);
        X509Certificate requesterCertificate = requesterCertificate(requesterKey);
        String certificateCommitment = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(requesterCertificate.getEncoded()));
        context.createPrincipal(new SecurityPrincipal("ocsp-requester", SecurityPrincipal.Type.SERVICE,
                "OCSP requester", Optional.empty(), Map.of(), true), "system");
        Permission.Scope scope = new Permission.Scope(context.configuration().realmId(), Optional.of(authority),
                Optional.of(issuerId), Optional.empty(), Optional.of("ocsp-e2e-signed"));
        context.grant(new Permission.Grant("ocsp-query-e2e", "ocsp-requester", Permission.Effect.ALLOW,
                Permission.Action.OCSP_STATUS_QUERY, Permission.ResourceType.OCSP_RESPONDER, scope,
                Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED, Set.of(), Optional.empty(),
                true), "system");
        Permission.Scope mixedScope = new Permission.Scope(context.configuration().realmId(),
                Optional.of(authority), Optional.of(issuerId), Optional.empty(), Optional.of("ocsp-e2e-mixed"));
        context.grant(new Permission.Grant("ocsp-query-mixed-e2e", "ocsp-requester", Permission.Effect.ALLOW,
                Permission.Action.OCSP_STATUS_QUERY, Permission.ResourceType.OCSP_RESPONDER, mixedScope,
                Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED, Set.of(), Optional.empty(),
                true), "system");
        zeroecho.pki.api.algorithm.X509AlgorithmBinding requestBinding = context.session().algorithmBindings()
                .standard(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                        zeroecho.pki.api.algorithm.X509AlgorithmBinding.Role.OCSP_REQUEST_SIGNATURE).orElseThrow();
        OcspResponderService.RequesterTrustPolicy policy = new OcspResponderService.RequesterTrustPolicy(
                List.of(new OcspResponderService.TrustSelector(
                        OcspResponderService.TrustSelectorType.EXACT_REQUESTER_CERTIFICATE_COMMITMENTS,
                        Set.of(certificateCommitment))),
                List.of(new OcspResponderService.PrincipalMapping("ocsp-requester-cert", "ocsp-requester",
                        OcspResponderService.PrincipalMappingType.SHA256_CERTIFICATE_COMMITMENT,
                        certificateCommitment)),
                List.of(new OcspResponderService.RequestSignatureBinding(requestBinding.bindingId(),
                        requestBinding.semanticCommitment())),
                OcspResponderService.RequesterRevocationPolicy.VALIDITY_AND_TRUST_ONLY, 2, 65_536);
        OcspResponderService.Responder responder = context.ocspResponders().create("ocsp-e2e-signed", "signed",
                authority, issuerId, template.signingMode(), template.responderCredentialId(),
                template.signingKeyRef(), template.chainPathId(), template.signatureAlgorithm(),
                template.signatureBindingId(), template.signatureBindingCommitment(), template.responderIdForm(),
                template.responseValidity(), template.noncePolicy(), template.maximumNonceBytes(),
                template.acceptedHashes(), template.maximumRequestBytes(), template.maximumEntries(),
                template.cacheLifetime(), OcspResponderService.RequestAuthenticationMode.AUTHORIZED_SIGNED_REQUIRED,
                Optional.of(policy));
        OcspResponderService.Responder active = context.ocspResponders().setActive(
                context.ocspResponders().register(responder).responderId(), true);
        assertTrue(context.authorizeOcspQuery("ocsp-requester", active).allowed());
        assertRequesterService(context, active, requesterKey, requesterCertificate);
        OcspResponderService.Responder mixed = context.ocspResponders().create("ocsp-e2e-mixed", "mixed",
                authority, issuerId, template.signingMode(), template.responderCredentialId(),
                template.signingKeyRef(), template.chainPathId(), template.signatureAlgorithm(),
                template.signatureBindingId(), template.signatureBindingCommitment(), template.responderIdForm(),
                template.responseValidity(), template.noncePolicy(), template.maximumNonceBytes(),
                template.acceptedHashes(), template.maximumRequestBytes(), template.maximumEntries(),
                template.cacheLifetime(),
                OcspResponderService.RequestAuthenticationMode.UNSIGNED_OR_AUTHORIZED_SIGNED,
                Optional.of(policy));
        context.ocspResponders().setActive(context.ocspResponders().register(mixed).responderId(), true);
    }

    private static void assertRequesterService(ServerRealmContext context,
            OcspResponderService.Responder responder, KeyPair requesterKey, X509Certificate requesterCertificate)
            throws Exception {
        X509Certificate issuerCertificate;
        try (zeroecho.pki.application.PkiRepositoryContent content = context.session().repository()
                .openCredential(context.session().repository().issuer(responder.issuerId()).orElseThrow()
                        .credentialId()); java.io.InputStream input = content.openStream()) {
            issuerCertificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
        }
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(new CertificateID(new JcaDigestCalculatorProviderBuilder().build()
                .get(CertificateID.HASH_SHA1), new JcaX509CertificateHolder(issuerCertificate), BigInteger.ONE));
        builder.setRequestorName(new GeneralName(new JcaX509CertificateHolder(requesterCertificate).getSubject()));
        org.bouncycastle.cert.ocsp.OCSPReq request = builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .build(requesterKey.getPrivate()), new org.bouncycastle.cert.X509CertificateHolder[] {
                    new JcaX509CertificateHolder(requesterCertificate) });
        org.bouncycastle.asn1.ocsp.OCSPRequest structure = org.bouncycastle.asn1.ocsp.OCSPRequest.getInstance(
                org.bouncycastle.asn1.ASN1Primitive.fromByteArray(request.getEncoded()));
        org.bouncycastle.asn1.ocsp.Signature signature = structure.getOptionalSignature();
        org.bouncycastle.cert.ocsp.CertificateID certificateId = request.getRequestList()[0].getCertID();
        OcspRequesterService.SignedRequest signed = new OcspRequesterService.SignedRequest(
                structure.getTbsRequest().getEncoded(), requesterCertificate.getSubjectX500Principal().getEncoded(),
                signature.getSignatureAlgorithm().getEncoded(), signature.getSignature().getOctets(),
                List.of(requesterCertificate.getEncoded()));
        try {
            new OcspRequesterService(context, CLOCK).authenticate(responder, signed,
                    List.of(new zeroecho.pki.application.OcspResponseService.CertId(
                            zeroecho.pki.application.OcspResponseService.CertIdHash.SHA1,
                            certificateId.getIssuerNameHash(), certificateId.getIssuerKeyHash(),
                            certificateId.getSerialNumber())));
        } catch (OcspRequesterService.UnauthorizedException failure) {
            throw new AssertionError("Requester service rejected fixture: " + failure.classification(), failure);
        }
    }

    private PkiHttpsServer start(Fixture fixture) throws Exception {
        return PkiHttpsServer.start(fixture.configuration(), fixture.dependencies(), CLOCK,
                HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader());
    }

    private Fixture packagedFixture(Path root, HttpServerTestSupport.PackagedTls tls, int adminPort, int acmePort,
            int publicPort, int challengePort, KeyPair rootKey) throws Exception {
        Path keyring = root.resolve("signing-keyring.zek");
        try (KeyringPassword password = new KeyringPassword(KEYRING_PASSWORD.clone());
                KeyringStore store = KeyringStore.create(keyring, password)) {
            store.putPrivate("root.prv", "RSA", rootKey.getPrivate());
            store.putPublic("root.pub", "RSA", rootKey.getPublic());
        }
        ProviderConfig workflow = new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString(),
                "keyRefPrefix", "acme-test:",
                "requireComponentSuffix", "true"));
        PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                workflow, zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(),
                Duration.ofSeconds(10),
                Optional.of("ZEROECHO_TEST_KEYRING_PASSWORD"), signingTopology(), java.util.OptionalLong.empty());
        PkiSessionConfiguration session = new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", root.resolve("pki").toString())),
                new ProviderConfig("memory", Map.of("size", "256")), Optional.of(signing), List.of(), List.of());
        ApprovalService.Policy approval = new ApprovalService.Policy("high-risk", 1, Set.of("approver"), Set.of(),
                true, Duration.ofHours(1), true);
        ServerRealmConfiguration realm = new ServerRealmConfiguration(ServerTestSupport.REALM, "Packaged ACME",
                ServerTestSupport.CONFIRMATION_PROOF_POLICY, session,
                new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(),
                        true), ServerTestSupport.DIGEST, approval.commitment(),
                ServerRealmConfiguration.extendedApprovalCommitment(
                        Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, approval)),
                ServerTestSupport.DIGEST,
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
        PkiServerConfiguration.PublicListener publicListener = new PkiServerConfiguration.PublicListener(
                InetAddress.getByName("127.0.0.1"), publicPort, Optional.of(tlsProvider), false,
                authentication, 16_384, 65_536, lane, Duration.ofSeconds(20), Duration.ofMinutes(5),
                Duration.ofSeconds(30), true);
        PkiServerConfiguration configuration = new PkiServerConfiguration(PkiServerConfiguration.CURRENT_VERSION,
                "packaged-acme", realm,
                new PkiServerConfiguration.Listener(InetAddress.getByName("127.0.0.1"), adminPort, tlsProvider,
                        true, 16_384, 1_048_576), authentication, lane,
                new PkiServerConfiguration.RuntimeCapabilities(Optional.of("ZEROECHO_TEST_KEYRING_PASSWORD"),
                        Optional.empty(), Optional.empty()),
                Optional.of(publicListener), Optional.of(acme));
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
        String workflow = providerJson(signing.provider());
        String store = providerJson(realm.pkiSessionConfiguration().store());
        String audit = providerJson(realm.pkiSessionConfiguration().audit());
        String authenticationJson = "{\"mode\":\"DIRECT_MTLS\",\"directClientMappings\":[{"
                + "\"mappingId\":\"packaged-admin\",\"principalId\":\"administrator\","
                + "\"certificateSha256\":\""
                + configuration.authentication().directClientMappings().get(0).certificateSha256().orElseThrow()
                + "\"}]}";
        PkiServerConfiguration.PublicListener publicListener = configuration.publicListener().orElseThrow();
        return "{\"version\":" + PkiServerConfiguration.CURRENT_VERSION
                + ",\"serverName\":\"packaged-acme\",\"realm\":{"
                + "\"realmId\":\"production\",\"displayName\":\"Packaged ACME\","
                + "\"confirmationProof\":{\"audience\":\""
                + realm.confirmationProofPolicy().audience().value()
                + "\",\"challengeTtlMillis\":"
                + realm.confirmationProofPolicy().challengeTimeToLive().toMillis()
                + ",\"rsaMaximumModulusBits\":"
                + realm.confirmationProofPolicy().rsaMaximumModulusBits() + "},"
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
                + "\"pkiSession\":{\"version\":6,\"store\":" + store + ",\"audit\":" + audit
                + ",\"signing\":{\"provider\":" + workflow + ",\"signatureAlgorithm\":\""
                + json(signing.signatureAlgorithm()) + "\","
                + "\"signingTtlMillis\":10000,"
                + "\"topology\":{\"coordinator\":{\"pageSize\":2,\"claimLeaseMillis\":10000,"
                + "\"providerCallTimeoutMillis\":5000,\"idlePollIntervalMillis\":10,\"closeTimeoutMillis\":5000},"
                + "\"exactGroups\":[],\"catchAll\":{\"laneCount\":2,\"prefetchSize\":3}},"
                + "\"unlockEnvironmentVariable\":\"ZEROECHO_TEST_KEYRING_PASSWORD\"},"
                + "\"publishers\":[],\"bindingProviders\":[]}},\"listener\":{\"address\":\"127.0.0.1\","
                + "\"port\":" + configuration.listener().port() + ",\"tlsProvider\":" + tlsJson
                + ",\"clientCertificateRequired\":true,\"maximumHeaderBytes\":16384,"
                + "\"maximumBodyBytes\":1048576},\"authentication\":" + authenticationJson
                + ",\"execution\":" + executionJson()
                + ",\"auditProjection\":{\"maxRecords\":256,\"maxSinkCalls\":64,"
                + "\"idleIntervalMillis\":2000},\"publicListener\":{\"enabled\":true,"
                + "\"address\":\"127.0.0.1\",\"port\":" + publicListener.port()
                + ",\"tlsProvider\":" + tlsJson + ",\"allowPlaintextLoopback\":false,"
                + "\"authentication\":" + authenticationJson
                + ",\"maximumHeaderBytes\":16384,\"maximumBodyBytes\":65536,\"execution\":" + executionJson()
                + ",\"maximumStreamDurationMillis\":20000,\"publicImmutableCacheMillis\":300000,"
                + "\"publicAliasCacheMillis\":30000,\"authorityListExposed\":true},"
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
                + "\"estListener\":{\"enabled\":false},"
                + "\"scepListener\":{\"enabled\":false},"
                + "\"cmpListener\":{\"enabled\":false},"
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

    private static AcmeTestClient.Response awaitValidOrder(AcmeTestClient client, URI orderUri,
            AcmeTestClient.Response finalized) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        AcmeTestClient.Response current = finalized;
        while (true) {
            assertEquals(200, current.status(), current.bodyText());
            String status = AcmeTestClient.text(current, "status");
            if ("valid".equals(status)) {
                return current;
            }
            assertEquals("processing", status, "Accepted order must remain processing until valid");
            assertTrue(System.nanoTime() < deadline, "Accepted order did not become valid");
            TimeUnit.MILLISECONDS.sleep(5);
            // Finalize is submitted once; polling observes the same retained issuance.
            current = client.postAsGet(orderUri);
        }
    }

    private static void awaitDirectory(HttpClient client, URI directory, Process process, Path output)
            throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
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

    private static void destroyProcessTree(Process process) throws Exception {
        boolean windows = System.getProperty("os.name", "").toLowerCase().contains("win");
        if (windows) {
            // taskkill /F /T kills the entire process tree, including any Java child spawned by CMD.exe
            new ProcessBuilder("taskkill", "/F", "/T", "/PID", String.valueOf(process.pid()))
                    .redirectErrorStream(true).start().waitFor(10, TimeUnit.SECONDS);
        }
        process.destroy();
        if (!process.waitFor(10, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            assertTrue(process.waitFor(5, TimeUnit.SECONDS));
        }
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

    private static void assertOcsp(HttpClient client, int publicPort, X509Certificate issuer,
            X509Certificate certificate, boolean revoked) throws Exception {
        JcaX509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuer);
        org.bouncycastle.operator.DigestCalculator digest = new JcaDigestCalculatorProviderBuilder().build().get(
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                        org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256));
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(new CertificateID(digest, issuerHolder, certificate.getSerialNumber()));
        byte[] request = builder.build().getEncoded();
        URI endpoint = URI.create("https://localhost:" + publicPort + "/ocsp/root");
        java.net.http.HttpRequest wireRequest;
        if (revoked) {
            String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(request);
            wireRequest = java.net.http.HttpRequest.newBuilder(URI.create(endpoint + "/" + encoded))
                    .header("Accept", "application/ocsp-response").GET().build();
        } else {
            wireRequest = java.net.http.HttpRequest.newBuilder(endpoint)
                    .header("Accept", "application/ocsp-response")
                    .header("Content-Type", "application/ocsp-request")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(request)).build();
        }
        java.net.http.HttpResponse<byte[]> response = client.send(wireRequest,
                java.net.http.HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, response.statusCode());
        assertEquals("application/ocsp-response", response.headers().firstValue("Content-Type").orElseThrow());
        String etag = response.headers().firstValue("ETag").orElseThrow();
        OCSPResp parsed = new OCSPResp(response.body());
        assertEquals(0, parsed.getStatus());
        BasicOCSPResp basic = assertInstanceOf(BasicOCSPResp.class, parsed.getResponseObject());
        assertEquals(1, basic.getResponses().length);
        assertTrue(basic.isSignatureValid(new JcaContentVerifierProviderBuilder().build(issuerHolder)));
        assertTrue(basic.getResponses()[0].getThisUpdate() != null);
        assertTrue(basic.getResponses()[0].getNextUpdate() != null);
        if (revoked) {
            assertInstanceOf(RevokedStatus.class, basic.getResponses()[0].getCertStatus());
        } else {
            assertEquals(null, basic.getResponses()[0].getCertStatus());
            String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(request);
            java.net.http.HttpResponse<byte[]> conditional = client.send(java.net.http.HttpRequest.newBuilder(
                    URI.create(endpoint + "/" + encoded)).header("Accept", "application/ocsp-response")
                    .header("If-None-Match", etag).GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(304, conditional.statusCode());
            assertEquals(0, conditional.body().length);
        }
    }

    private static void assertOcspNonce(HttpClient client, int publicPort, X509Certificate issuer,
            X509Certificate certificate) throws Exception {
        JcaX509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuer);
        org.bouncycastle.operator.DigestCalculator digest = new JcaDigestCalculatorProviderBuilder().build()
                .get(CertificateID.HASH_SHA1);
        byte[] nonce = new byte[] { 9, 8, 7, 6, 5, 4, 3, 2 };
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(new CertificateID(digest, issuerHolder, certificate.getSerialNumber()));
        builder.setRequestExtensions(new Extensions(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                false, new DEROctetString(new DEROctetString(nonce).getEncoded()))));
        java.net.http.HttpResponse<byte[]> response = client.send(java.net.http.HttpRequest.newBuilder(
                URI.create("https://localhost:" + publicPort + "/ocsp/root"))
                .header("Accept", "application/ocsp-response")
                .header("Content-Type", "application/ocsp-request")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(builder.build().getEncoded())).build(),
                java.net.http.HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, response.statusCode());
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
        assertTrue(response.headers().firstValue("ETag").isEmpty());
        BasicOCSPResp basic = assertInstanceOf(BasicOCSPResp.class,
                new OCSPResp(response.body()).getResponseObject());
        Extension echoed = basic.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        assertTrue(echoed != null);
        assertEquals(java.util.HexFormat.of().formatHex(nonce), java.util.HexFormat.of().formatHex(
                org.bouncycastle.asn1.ASN1OctetString.getInstance(echoed.getParsedValue()).getOctets()));
    }

    private static void assertOcspUnknownAndMulti(HttpClient client, int publicPort, X509Certificate issuer,
            X509Certificate certificate) throws Exception {
        JcaX509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuer);
        org.bouncycastle.operator.DigestCalculator digest = new JcaDigestCalculatorProviderBuilder().build()
                .get(CertificateID.HASH_SHA1);
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(new CertificateID(digest, issuerHolder, certificate.getSerialNumber()));
        digest = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
        builder.addRequest(new CertificateID(digest, issuerHolder, certificate.getSerialNumber().add(BigInteger.ONE)));
        java.net.http.HttpResponse<byte[]> response = client.send(java.net.http.HttpRequest.newBuilder(
                URI.create("https://localhost:" + publicPort + "/ocsp/root"))
                .header("Accept", "application/ocsp-response").header("Content-Type", "application/ocsp-request")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(builder.build().getEncoded())).build(),
                java.net.http.HttpResponse.BodyHandlers.ofByteArray());
        BasicOCSPResp basic = assertInstanceOf(BasicOCSPResp.class,
                new OCSPResp(response.body()).getResponseObject());
        assertEquals(2, basic.getResponses().length);
        assertEquals(null, basic.getResponses()[0].getCertStatus());
        assertInstanceOf(org.bouncycastle.cert.ocsp.UnknownStatus.class,
                basic.getResponses()[1].getCertStatus());
    }

    private static void assertOcspNoncePolicies(HttpClient client, int publicPort, X509Certificate issuer,
            X509Certificate certificate) throws Exception {
        JcaX509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuer);
        byte[] nonce = new byte[] { 3, 1, 4, 1, 5, 9, 2, 6 };
        OCSPReqBuilder nonceBuilder = new OCSPReqBuilder();
        nonceBuilder.addRequest(new CertificateID(new JcaDigestCalculatorProviderBuilder().build()
                .get(CertificateID.HASH_SHA1), issuerHolder, certificate.getSerialNumber()));
        nonceBuilder.setRequestExtensions(new Extensions(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                false, new DEROctetString(new DEROctetString(nonce).getEncoded()))));
        byte[] withNonce = nonceBuilder.build().getEncoded();
        OCSPReqBuilder plainBuilder = new OCSPReqBuilder();
        plainBuilder.addRequest(new CertificateID(new JcaDigestCalculatorProviderBuilder().build()
                .get(CertificateID.HASH_SHA1), issuerHolder, certificate.getSerialNumber()));
        byte[] withoutNonce = plainBuilder.build().getEncoded();
        assertEquals(org.bouncycastle.cert.ocsp.OCSPRespBuilder.MALFORMED_REQUEST,
                postOcsp(client, publicPort, "reject", withNonce).getStatus());
        assertEquals(org.bouncycastle.cert.ocsp.OCSPRespBuilder.MALFORMED_REQUEST,
                postOcsp(client, publicPort, "required", withoutNonce).getStatus());
        assertEquals(org.bouncycastle.cert.ocsp.OCSPRespBuilder.SUCCESSFUL,
                postOcsp(client, publicPort, "required", withNonce).getStatus());
        assertEquals(org.bouncycastle.cert.ocsp.OCSPRespBuilder.MALFORMED_REQUEST,
                postOcsp(client, publicPort, "required", withNonce).getStatus());
    }

    private static void assertSignedOcsp(HttpClient client, int publicPort, X509Certificate issuer,
            X509Certificate certificate, KeyPair requesterKey, X509Certificate requesterCertificate,
            String alias, boolean signatureRequired, boolean revoked)
            throws Exception {
        JcaX509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuer);
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(new CertificateID(new JcaDigestCalculatorProviderBuilder().build()
                .get(CertificateID.HASH_SHA1), issuerHolder, certificate.getSerialNumber()));
        builder.setRequestorName(new GeneralName(new JcaX509CertificateHolder(requesterCertificate).getSubject()));
        byte[] request = builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .build(requesterKey.getPrivate()),
                new org.bouncycastle.cert.X509CertificateHolder[] {
                    new JcaX509CertificateHolder(requesterCertificate) }).getEncoded();
        URI endpoint = URI.create("https://localhost:" + publicPort + "/ocsp/" + alias);
        java.net.http.HttpResponse<byte[]> post = client.send(java.net.http.HttpRequest.newBuilder(endpoint)
                .header("Accept", "application/ocsp-response").header("Content-Type", "application/ocsp-request")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(request)).build(),
                java.net.http.HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, post.statusCode());
        OCSPResp decoded = new OCSPResp(post.body());
        assertEquals(org.bouncycastle.cert.ocsp.OCSPRespBuilder.SUCCESSFUL, decoded.getStatus());
        BasicOCSPResp basic = assertInstanceOf(BasicOCSPResp.class, decoded.getResponseObject());
        assertEquals(1, basic.getResponses().length);
        if (revoked) assertInstanceOf(org.bouncycastle.cert.ocsp.RevokedStatus.class,
                basic.getResponses()[0].getCertStatus());
        else assertEquals(null, basic.getResponses()[0].getCertStatus());
        assertEquals("private, no-store", post.headers().firstValue("Cache-Control").orElseThrow());
        assertEquals("no-cache", post.headers().firstValue("Pragma").orElseThrow());
        assertTrue(post.headers().firstValue("ETag").isEmpty());
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(request);
        java.net.http.HttpResponse<byte[]> get = client.send(java.net.http.HttpRequest.newBuilder(
                URI.create(endpoint + "/" + encoded)).header("Accept", "application/ocsp-response").GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(org.bouncycastle.cert.ocsp.OCSPRespBuilder.SUCCESSFUL, new OCSPResp(get.body()).getStatus());
        OCSPReqBuilder unsigned = new OCSPReqBuilder();
        unsigned.addRequest(new CertificateID(new JcaDigestCalculatorProviderBuilder().build()
                .get(CertificateID.HASH_SHA1), issuerHolder, certificate.getSerialNumber()));
        assertEquals(signatureRequired ? org.bouncycastle.cert.ocsp.OCSPRespBuilder.SIG_REQUIRED
                        : org.bouncycastle.cert.ocsp.OCSPRespBuilder.SUCCESSFUL,
                postOcsp(client, publicPort, alias, unsigned.build().getEncoded()).getStatus());
        if ("mixed".equals(alias)) {
            byte[] invalidSignature = builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                    .build(rsa((byte) 82).getPrivate()),
                    new org.bouncycastle.cert.X509CertificateHolder[] {
                        new JcaX509CertificateHolder(requesterCertificate) }).getEncoded();
            assertEquals(org.bouncycastle.cert.ocsp.OCSPRespBuilder.UNAUTHORIZED,
                    postOcsp(client, publicPort, alias, invalidSignature).getStatus());

            OCSPReqBuilder partlyForeign = new OCSPReqBuilder();
            partlyForeign.addRequest(new CertificateID(new JcaDigestCalculatorProviderBuilder().build()
                    .get(CertificateID.HASH_SHA1), issuerHolder, certificate.getSerialNumber()));
            partlyForeign.addRequest(new CertificateID(new JcaDigestCalculatorProviderBuilder().build()
                    .get(CertificateID.HASH_SHA1), new JcaX509CertificateHolder(requesterCertificate),
                    certificate.getSerialNumber().add(BigInteger.ONE)));
            partlyForeign.setRequestorName(new GeneralName(
                    new JcaX509CertificateHolder(requesterCertificate).getSubject()));
            byte[] partlyForeignRequest = partlyForeign.build(new JcaContentSignerBuilder("SHA256withRSA")
                    .build(requesterKey.getPrivate()),
                    new org.bouncycastle.cert.X509CertificateHolder[] {
                        new JcaX509CertificateHolder(requesterCertificate) }).getEncoded();
            assertEquals(org.bouncycastle.cert.ocsp.OCSPRespBuilder.UNAUTHORIZED,
                    postOcsp(client, publicPort, alias, partlyForeignRequest).getStatus());
        }
        if (signatureRequired) {
            assertEquals(org.bouncycastle.cert.ocsp.OCSPRespBuilder.UNAUTHORIZED,
                    postOcsp(client, publicPort, "root", request).getStatus());
        }
    }

    private static void assertSignedOcspUnauthorized(HttpClient client, int publicPort, X509Certificate issuer,
            X509Certificate certificate, KeyPair requesterKey, X509Certificate requesterCertificate,
            String alias) throws Exception {
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(new CertificateID(new JcaDigestCalculatorProviderBuilder().build()
                .get(CertificateID.HASH_SHA1), new JcaX509CertificateHolder(issuer),
                certificate.getSerialNumber()));
        builder.setRequestorName(new GeneralName(new JcaX509CertificateHolder(requesterCertificate).getSubject()));
        byte[] request = builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .build(requesterKey.getPrivate()), new org.bouncycastle.cert.X509CertificateHolder[] {
                    new JcaX509CertificateHolder(requesterCertificate) }).getEncoded();
        java.net.http.HttpResponse<byte[]> response = client.send(java.net.http.HttpRequest.newBuilder(
                URI.create("https://localhost:" + publicPort + "/ocsp/" + alias))
                .header("Accept", "application/ocsp-response").header("Content-Type", "application/ocsp-request")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(request)).build(),
                java.net.http.HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, response.statusCode());
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
        assertEquals(org.bouncycastle.cert.ocsp.OCSPRespBuilder.UNAUTHORIZED,
                new OCSPResp(response.body()).getStatus());
    }

    private static X509Certificate requesterCertificate(KeyPair keys) throws Exception {
        X500Name name = new X500Name("CN=ZeroEcho OCSP Requester Fixture");
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(name, BigInteger.valueOf(8801),
                java.util.Date.from(Instant.parse("2025-01-01T00:00:00Z")),
                java.util.Date.from(Instant.parse("2035-01-01T00:00:00Z")), name,
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded()));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        byte[] encoded = builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .build(keys.getPrivate())).getEncoded();
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(encoded));
    }

    private static OCSPResp postOcsp(HttpClient client, int publicPort, String alias, byte[] request)
            throws Exception {
        java.net.http.HttpResponse<byte[]> response = client.send(java.net.http.HttpRequest.newBuilder(
                URI.create("https://localhost:" + publicPort + "/ocsp/" + alias))
                .header("Accept", "application/ocsp-response").header("Content-Type", "application/ocsp-request")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(request)).build(),
                java.net.http.HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, response.statusCode());
        return new OCSPResp(response.body());
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
