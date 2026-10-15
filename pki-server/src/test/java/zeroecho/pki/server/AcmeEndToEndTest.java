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
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
import java.util.Arrays;
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
import zeroecho.pki.api.revocation.RevocationState;
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
    void cmpProtectedApprovalRestartConfirmationReplacementAndRevocationUseRealDomain() throws Exception {
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        KeyPair rootKey = rsa((byte) 101);
        KeyPair requesterKey = rsa((byte) 102);
        KeyPair issuedKey = rsa((byte) 103);
        Fixture base = fixture(tls, reservePort(), reservePort(), reservePort(), rootKey);
        seed(base);
        int port = reservePort();
        PkiServerConfiguration source = base.configuration();
        PkiServerConfiguration.CmpListener listener = new PkiServerConfiguration.CmpListener("cmp-test",
                InetAddress.getLoopbackAddress(), port, new ProviderConfig("test-tls", Map.of()), source.execution(), 16_384, 8192);
        Fixture fixture = new Fixture(new PkiServerConfiguration(source.version(), source.serverName(), source.realm(),
                source.listener(), source.authentication(), source.execution(), source.runtime(), source.publicListener(),
                source.acmeListener(), source.estListener(), source.scepListener(), Optional.of(listener), source.auditProjection()),
                base.dependencies(), base.http01());
        CmpProvisioned provisioned = provisionCmp(fixture, rootKey, requesterKey);
        HttpClient wire = HttpClient.newBuilder().sslContext(tls.anonymousContext()).build();
        URI endpoint = URI.create("https://localhost:" + port + "/pkix/managed");
        byte[] transaction = CmpTestClient.nonce(1);
        byte[] initialNonce = CmpTestClient.nonce(2);
        org.bouncycastle.asn1.cmp.PKIBody originalCrmf = CmpTestClient.enrollment(issuedKey, null);
        byte[] original = CmpTestClient.signed(originalCrmf, transaction, initialNonce, null, requesterKey,
                provisioned.requester(), provisioned.responders().getFirst(), false);
        byte[] waiting;
        String enrollmentId;
        try (PkiHttpsServer server = startScep(fixture, provisioned.runtime())) {
            HttpResponse<byte[]> result = cmpPost(wire, endpoint, original);
            assertEquals(200, result.statusCode(), new String(result.body(), StandardCharsets.UTF_8));
            waiting = result.body();
            assertTrue(CmpTestClient.signatureResponse(waiting, transaction, initialNonce, provisioned.responders().getFirst()).pending());
            assertArrayEquals(waiting, cmpPost(wire, endpoint, original).body());
            zeroecho.pki.server.enrollment.CmpTransaction manifest = cmpTransaction(server, "managed", transaction);
            enrollmentId = manifest.enrollmentId().orElseThrow();
            zeroecho.pki.server.enrollment.EnrollmentTransaction enrollment = server.realm().enrollmentCoordinator().orElseThrow().find(enrollmentId).orElseThrow();
            zeroecho.pki.api.CertificationRequestService requests = server.realm().session().requests().orElseThrow();
            assertArrayEquals(org.bouncycastle.asn1.crmf.CertReqMessages.getInstance(originalCrmf.getContent()).toCertReqMsgArray()[0].getEncoded(),
                    requests.encodedX509Request(requests.get(enrollment.intent().requestId()).orElseThrow()).der());
            assertEquals(413, cmpPost(wire, endpoint, new byte[8193]).statusCode());
            byte[] tampered = original.clone(); tampered[tampered.length - 1] ^= 1;
            assertEquals(400, cmpPost(wire, endpoint, tampered).statusCode());
            byte[] wrongRecipient = CmpTestClient.signed(CmpTestClient.discovery(), CmpTestClient.nonce(8), initialNonce, null,
                    requesterKey, provisioned.requester(), provisioned.responders().getLast(), false);
            assertEquals(400, cmpPost(wire, endpoint, wrongRecipient).statusCode());
        }
        zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration runtime = provisioned.runtime();
        zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.CredentialSet second = runtime.credentialSets().get(1);
        zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration rotated = new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration(
                runtime.budgets(), runtime.keyrings(), runtime.credentialSets(), List.of(
                new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.ActiveCredential(second.protocol(), second.authorityId(), second.credentialId()),
                runtime.activeCredentials().getLast()),
                Optional.empty());
        CmpCompletion completed;
        try (PkiHttpsServer server = startScep(fixture, rotated)) {
            assertArrayEquals(waiting, cmpPost(wire, endpoint, original).body());
            approveEnrollment(server, enrollmentId, tls.forwardedCertificate());
            completed = awaitCmp(wire, endpoint, transaction,
                    CmpTestClient.signatureResponse(waiting, transaction, initialNonce, provisioned.responders().getFirst()),
                    requesterKey, provisioned.requester(), provisioned.responders().getFirst());
            completed.certificate().verify(provisioned.authority().getPublicKey());
            assertArrayEquals(issuedKey.getPublic().getEncoded(), completed.certificate().getPublicKey().getEncoded());
            assertEquals("cmp-a", cmpTransaction(server, "managed", transaction).frozen().source().credentialId().orElseThrow());
            assertEquals(zeroecho.pki.server.enrollment.CmpTransaction.Confirmation.AWAITING,
                    cmpTransaction(server, "managed", transaction).response().orElseThrow().confirmation());
        }
        try (PkiHttpsServer server = startScep(fixture, rotated)) {
            assertArrayEquals(completed.response(), cmpPost(wire, endpoint, completed.request()).body());
            byte[] confirmationNonce = CmpTestClient.nonce(71);
            byte[] confirmation = CmpTestClient.signed(CmpTestClient.confirmation(completed.certificate(), true), transaction,
                    confirmationNonce, completed.reply().nonce(), requesterKey, provisioned.requester(), provisioned.responders().getFirst(), false);
            byte[] confirmed = cmpPost(wire, endpoint, confirmation).body();
            assertEquals(19, CmpTestClient.signatureResponse(confirmed, transaction, confirmationNonce, provisioned.responders().getFirst()).type());
            assertArrayEquals(confirmed, cmpPost(wire, endpoint, confirmation).body());
            assertEquals(zeroecho.pki.server.enrollment.CmpTransaction.Confirmation.ACCEPTED,
                    cmpTransaction(server, "managed", transaction).response().orElseThrow().confirmation());
            awaitCertificateValidity(completed.certificate());
            KeyPair replacementKey = rsa((byte) 104);
            byte[] replacementTransaction = CmpTestClient.nonce(3);
            byte[] replacementNonce = CmpTestClient.nonce(4);
            byte[] replacement = CmpTestClient.signed(CmpTestClient.enrollment(replacementKey, completed.certificate()), replacementTransaction,
                    replacementNonce, null, issuedKey, completed.certificate(), provisioned.responders().getLast(), true);
            HttpResponse<byte[]> replacementHttp = cmpPost(wire, endpoint, replacement);
            assertEquals(200, replacementHttp.statusCode(), new String(replacementHttp.body(), StandardCharsets.UTF_8));
            byte[] replacementWaiting = replacementHttp.body();
            assertTrue(CmpTestClient.signatureResponse(replacementWaiting, replacementTransaction, replacementNonce, provisioned.responders().getLast()).pending());
            approveEnrollment(server, cmpTransaction(server, "managed", replacementTransaction).enrollmentId().orElseThrow(), tls.forwardedCertificate());
            CmpCompletion replaced = awaitCmp(wire, endpoint, replacementTransaction,
                    CmpTestClient.signatureResponse(replacementWaiting, replacementTransaction, replacementNonce, provisioned.responders().getLast()),
                    issuedKey, completed.certificate(), provisioned.responders().getLast());
            replaced.certificate().verify(provisioned.authority().getPublicKey());
            assertArrayEquals(replacementKey.getPublic().getEncoded(), replaced.certificate().getPublicKey().getEncoded());
            assertFalse(Arrays.equals(completed.certificate().getPublicKey().getEncoded(), replaced.certificate().getPublicKey().getEncoded()));
            assertEquals(zeroecho.pki.server.enrollment.EnrollmentTransaction.Operation.REPLACE, server.realm().enrollmentCoordinator().orElseThrow()
                    .find(cmpTransaction(server, "managed", replacementTransaction).enrollmentId().orElseThrow()).orElseThrow().intent().operation());
            assertEquals(zeroecho.pki.server.enrollment.CmpTransaction.Confirmation.ACCEPTED,
                    cmpTransaction(server, "managed", replacementTransaction).response().orElseThrow().confirmation());
            awaitCertificateValidity(replaced.certificate());
            byte[] revocationTransaction = CmpTestClient.nonce(5);
            byte[] revocationNonce = CmpTestClient.nonce(6);
            byte[] revoke = CmpTestClient.signed(CmpTestClient.revoke(replaced.certificate()), revocationTransaction, revocationNonce, null,
                    replacementKey, replaced.certificate(), provisioned.responders().getLast(), false);
            byte[] revoked = cmpPost(wire, endpoint, revoke).body();
            assertEquals(12, CmpTestClient.signatureResponse(revoked, revocationTransaction, revocationNonce, provisioned.responders().getLast()).type());
            assertArrayEquals(revoked, cmpPost(wire, endpoint, revoke).body());
            PkiId revokedId = new PkiId("x509:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(replaced.certificate().getEncoded())));
            assertEquals(RevocationState.PERMANENTLY_REVOKED, server.realm().session().revocations().get(revokedId).orElseThrow().transition().state());
            byte[] deniedTransaction = CmpTestClient.nonce(9);
            byte[] denied = cmpPost(wire, endpoint, CmpTestClient.signed(CmpTestClient.discovery(), deniedTransaction, revocationNonce, null,
                    replacementKey, replaced.certificate(), provisioned.responders().getLast(), false)).body();
            assertEquals(23, CmpTestClient.signatureResponse(denied, deniedTransaction, revocationNonce, provisioned.responders().getLast()).type());
            URI pbmEndpoint = URI.create("https://localhost:" + port + "/pkix/pbm");
            byte[] pbmTransaction = CmpTestClient.nonce(10);
            byte[] pbmNonce = CmpTestClient.nonce(11);
            byte[] pbmDenied = cmpPost(wire, pbmEndpoint, CmpTestClient.pbm(CmpTestClient.revoke(completed.certificate()),
                    pbmTransaction, pbmNonce, null, provisioned.secret(), provisioned.authority())).body();
            assertEquals(23, CmpTestClient.pbmResponse(pbmDenied, pbmTransaction, pbmNonce, provisioned.secret()).type());
            assertTrue(server.realm().enrollmentCoordinator().orElseThrow().findCmp("pbm",
                    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(pbmTransaction))).isEmpty());
            cmpPbmAndAuthorityIsolation(server, wire, endpoint, pbmEndpoint, URI.create("https://localhost:" + port + "/pkix/other"),
                    provisioned, requesterKey, tls.forwardedCertificate(), transaction);
        }
    }

    private record CmpProvisioned(zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration runtime,
            X509Certificate authority, X509Certificate requester, List<X509Certificate> responders, byte[] secret,
            X509Certificate otherAuthority, X509Certificate otherResponder, X509Certificate otherRequester) { }
    private record CmpCompletion(X509Certificate certificate, byte[] request, byte[] response, CmpTestClient.Reply reply) { }

    private static void cmpPbmAndAuthorityIsolation(PkiHttpsServer server, HttpClient wire, URI endpoint, URI pbmEndpoint,
            URI otherEndpoint, CmpProvisioned provisioned, KeyPair requesterKey, X509Certificate approver, byte[] originalTransaction) throws Exception {
        KeyPair pbmKey = rsa((byte) 107);
        byte[] transaction = CmpTestClient.nonce(12);
        byte[] nonce = CmpTestClient.nonce(13);
        byte[] request = CmpTestClient.pbm(CmpTestClient.enrollment(pbmKey, null), transaction, nonce, null, provisioned.secret(), provisioned.authority());
        byte[] waiting = cmpPost(wire, pbmEndpoint, request).body();
        CmpTestClient.Reply reply = CmpTestClient.pbmResponse(waiting, transaction, nonce, provisioned.secret());
        assertTrue(reply.pending());
        assertArrayEquals(waiting, cmpPost(wire, pbmEndpoint, request).body());
        approveEnrollment(server, cmpTransaction(server, "pbm", transaction).enrollmentId().orElseThrow(), approver);
        X509Certificate issued = null;
        for (int value = 80; value < 120; value++) {
            byte[] pollNonce = CmpTestClient.nonce(value);
            byte[] poll = CmpTestClient.pbm(CmpTestClient.poll(), transaction, pollNonce, reply.nonce(), provisioned.secret(), provisioned.authority());
            HttpResponse<byte[]> polled = cmpPost(wire, pbmEndpoint, poll); assertEquals(200, polled.statusCode());
            reply = CmpTestClient.pbmResponse(polled.body(), transaction, pollNonce, provisioned.secret());
            if (reply.certificate().isPresent()) { issued = reply.certificate().orElseThrow(); break; }
            assertTrue(reply.pending()); TimeUnit.MILLISECONDS.sleep(10);
        }
        org.junit.jupiter.api.Assertions.assertNotNull(issued);
        issued.verify(provisioned.authority().getPublicKey());
        assertArrayEquals(pbmKey.getPublic().getEncoded(), issued.getPublicKey().getEncoded());
        byte[] confirmationNonce = CmpTestClient.nonce(121);
        byte[] confirmation = CmpTestClient.pbm(CmpTestClient.confirmation(issued, true), transaction, confirmationNonce,
                reply.nonce(), provisioned.secret(), provisioned.authority());
        assertEquals(19, CmpTestClient.pbmResponse(cmpPost(wire, pbmEndpoint, confirmation).body(), transaction,
                confirmationNonce, provisioned.secret()).type());

        // The configured RA grant is independent of holder identity and scoped to its authority.
        byte[] raTransaction = CmpTestClient.nonce(14);
        byte[] revoke = CmpTestClient.signed(CmpTestClient.revoke(issued), raTransaction, nonce, null,
                requesterKey, provisioned.requester(), provisioned.responders().getLast(), false);
        assertEquals(12, CmpTestClient.signatureResponse(cmpPost(wire, endpoint, revoke).body(), raTransaction,
                nonce, provisioned.responders().getLast()).type());
        PkiId id = new PkiId("x509:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(issued.getEncoded())));
        assertEquals(RevocationState.PERMANENTLY_REVOKED, server.realm().session().revocations().get(id).orElseThrow().transition().state());

        byte[] discovery = CmpTestClient.signed(CmpTestClient.discovery(), originalTransaction, nonce, null,
                requesterKey, provisioned.otherRequester(), provisioned.otherResponder(), false);
        assertEquals(22, CmpTestClient.signatureResponse(cmpPost(wire, otherEndpoint, discovery).body(), originalTransaction,
                nonce, provisioned.otherResponder()).type());
        assertFalse(cmpTransaction(server, "managed", originalTransaction).id().equals(cmpTransaction(server, "other", originalTransaction).id()));
        assertEquals(400, cmpPost(wire, otherEndpoint, CmpTestClient.signed(CmpTestClient.discovery(), CmpTestClient.nonce(15), nonce,
                null, requesterKey, provisioned.requester(), provisioned.otherResponder(), false)).statusCode());
        byte[] forbiddenTransaction = CmpTestClient.nonce(16);
        byte[] forbidden = CmpTestClient.signed(CmpTestClient.revoke(provisioned.otherAuthority()), forbiddenTransaction,
                nonce, null, requesterKey, provisioned.otherRequester(), provisioned.otherResponder(), false);
        assertEquals(23, CmpTestClient.signatureResponse(cmpPost(wire, otherEndpoint, forbidden).body(), forbiddenTransaction,
                nonce, provisioned.otherResponder()).type());
    }

    private static HttpResponse<byte[]> cmpPost(HttpClient client, URI endpoint, byte[] body) throws Exception {
        return client.send(HttpRequest.newBuilder(endpoint).header("Content-Type", "application/pkixcmp")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private static zeroecho.pki.server.enrollment.CmpTransaction cmpTransaction(PkiHttpsServer server, String label, byte[] transaction) throws Exception {
        return server.realm().enrollmentCoordinator().orElseThrow().findCmp(label,
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(transaction))).orElseThrow();
    }

    private static CmpCompletion awaitCmp(HttpClient client, URI endpoint, byte[] transaction, CmpTestClient.Reply previous,
            KeyPair requester, X509Certificate requesterCertificate, X509Certificate responder) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        CmpTestClient.Reply current = previous;
        for (int nonce = 20; nonce < 200; nonce++) {
            byte[] requestNonce = CmpTestClient.nonce(nonce);
            byte[] request = CmpTestClient.signed(CmpTestClient.poll(), transaction, requestNonce, current.nonce(),
                    requester, requesterCertificate, responder, false);
            HttpResponse<byte[]> response = cmpPost(client, endpoint, request);
            assertEquals(200, response.statusCode(), new String(response.body(), StandardCharsets.UTF_8));
            current = CmpTestClient.signatureResponse(response.body(), transaction, requestNonce, responder);
            Optional<X509Certificate> certificate = current.certificate();
            if (certificate.isPresent()) return new CmpCompletion(certificate.orElseThrow(), request, response.body(), current);
            assertTrue(current.pending(), "CMP did not retain an issuance continuation");
            assertTrue(System.nanoTime() < deadline, "CMP issuance did not complete");
            TimeUnit.MILLISECONDS.sleep(10);
        }
        throw new AssertionError("CMP polling exceeded its bounded attempts");
    }

    private CmpProvisioned provisionCmp(Fixture fixture, KeyPair rootKey, KeyPair requesterKey) throws Exception {
        Path ringPath = temporaryDirectory.resolve("cmp-custody.zek");
        KeyPair otherRootKey = rsa((byte) 110);
        try (KeyringPassword password = new KeyringPassword(KEYRING_PASSWORD.clone());
                KeyringStore signing = KeyringStore.open(temporaryDirectory.resolve("server/signing-keyring.zek"), password)) {
            signing.putPrivate("other.prv", "RSA", otherRootKey.getPrivate());
            signing.putPublic("other.pub", "RSA", otherRootKey.getPublic());
        }
        List<zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.CredentialSet> sets = new java.util.ArrayList<>();
        List<X509Certificate> responders = new java.util.ArrayList<>();
        byte[] secret = CmpTestClient.nonce(0); secret = Arrays.copyOf(secret, 32); Arrays.fill(secret, 1, secret.length, (byte) 0x80);
        X509Certificate authority;
        X509Certificate requester;
        X509Certificate otherRoot;
        X509Certificate otherResponder;
        X509Certificate otherRequester;
        try (ServerRealmContext context = ServerRealmContext.open(fixture.configuration().realm(), fixture.dependencies(), CLOCK, HttpServerTestSupport.random());
                KeyringPassword password = new KeyringPassword(KEYRING_PASSWORD.clone());
                KeyringStore ring = KeyringStore.create(ringPath, password)) {
            AcmeState.Directory directory = context.acmeControl().page(AcmeState.Directory.class, 0, 256).values().getFirst();
            zeroecho.pki.api.ca.IssuerGeneration issuer = context.session().repository().issuer(directory.issuerId()).orElseThrow();
            try (zeroecho.pki.application.PkiRepositoryContent content = context.session().repository().openCredential(issuer.credentialId());
                    java.io.InputStream input = content.openStream()) {
                authority = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
            }
            Path rootPath = temporaryDirectory.resolve("cmp-root.der"); java.nio.file.Files.write(rootPath, authority.getEncoded());
            requester = cmpCertificate("CMP requester", 9500, requesterKey, rootKey, authority);
            ring.putSecret("pbm", "HMAC", new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"));
            for (int index = 0; index < 2; index++) {
                KeyPair pair = rsa((byte) (105 + index));
                String id = index == 0 ? "cmp-a" : "cmp-b";
                X509Certificate response = cmpCertificate(id, 9600 + index, pair, rootKey, authority);
                responders.add(response);
                Path certificate = temporaryDirectory.resolve(id + ".der"); java.nio.file.Files.write(certificate, response.getEncoded());
                ring.putPrivate(id, "RSA", pair.getPrivate());
                zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Pbm pbm =
                        new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Pbm(1000, 2000, 16, 32,
                        Set.of(zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.PbmDigest.SHA256),
                        Set.of(zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.PbmMac.HMAC_SHA256),
                        List.of(new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.PbmIdentity("0102", "pbm-requester",
                        new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.KeyReference("cmp", "pbm"), List.of("pbm-owner"))));
                sets.add(new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.CredentialSet(id,
                        zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Protocol.CMP, directory.authorityId().value(),
                        directory.issuerId().value(), directory.issuancePathId().value(), Optional.of(
                        new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Signer(
                        new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.KeyReference("cmp", id), List.of(certificate, rootPath))),
                        List.of(rootPath), List.of(zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(requesterKey.getPublic().getEncoded()).canonicalSha256()),
                        Optional.of(pbm)));
            }
            context.enrollmentProfiles().register(new zeroecho.pki.server.enrollment.EnrollmentProfile("cmp-enrollment", "CMP approval",
                    zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE, "server-tls", Set.of(directory.authorityId().value()), Optional.empty(), List.of(), true));
            context.enrollmentEndpoints().register(new zeroecho.pki.server.cmp.CmpEndpoint("managed", directory.authorityId().value(),
                    "server-tls", "cmp-enrollment", zeroecho.pki.server.cmp.CmpProtectionPolicy.SIGNATURE_BASED));
            context.enrollmentEndpoints().register(new zeroecho.pki.server.cmp.CmpEndpoint("pbm", directory.authorityId().value(),
                    "server-tls", "cmp-enrollment", zeroecho.pki.server.cmp.CmpProtectionPolicy.SHARED_SECRET_MAC));
            context.createPrincipal(ServerTestSupport.principal("approver"), "bootstrap");
            zeroecho.pki.api.SemanticSigningService signing = context.session().semanticSigning().orElseThrow();
            zeroecho.pki.api.signing.PreparedSemanticSigningRequest prepared = signing.prepareRootCreation(
                    new zeroecho.pki.api.audit.AccessContext(new zeroecho.pki.api.audit.Principal("SYSTEM", "test"),
                    new zeroecho.pki.api.audit.Purpose("ca.create"), Optional.empty(), Optional.empty()),
                    new CaCreateCommand(template("root-ca").definition().formatId(), new SubjectRef("CN=Other CMP authority"),
                    "root-ca", new KeyRef("acme-test:other.prv"), new SimpleAttributeSet()), zeroecho.core.io.CancellationSignal.NONE);
            PkiId otherCredential = awaitSigning(signing, signing.accept(prepared).receipt().operationId()).completedCredentialId().orElseThrow();
            try (zeroecho.pki.application.PkiRepositoryContent content = context.session().repository().openCredential(otherCredential);
                    java.io.InputStream input = content.openStream()) {
                otherRoot = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
            }
            awaitCertificateValidity(otherRoot);
            zeroecho.pki.api.ca.CaRecord other = context.session().repository().authority(
                    context.session().repository().credential(otherCredential).orElseThrow().issuerRef().caId()).orElseThrow();
            KeyPair otherRaKey = rsa((byte) 111);
            otherResponder = cmpCertificate("Other CMP RA", 9700, otherRaKey, otherRootKey, otherRoot);
            otherRequester = cmpCertificate("Other CMP requester", 9701, requesterKey, otherRootKey, otherRoot);
            Path otherCaFile = temporaryDirectory.resolve("cmp-other-ca.der"); java.nio.file.Files.write(otherCaFile, otherRoot.getEncoded());
            Path otherRaFile = temporaryDirectory.resolve("cmp-other-ra.der"); java.nio.file.Files.write(otherRaFile, otherResponder.getEncoded());
            ring.putPrivate("other-ra", "RSA", otherRaKey.getPrivate());
            sets.add(new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.CredentialSet("cmp-other",
                    zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Protocol.CMP, other.caId().value(),
                    other.currentIssuanceIssuerId().value(), other.issuanceChainPathId().value(), Optional.of(
                    new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Signer(
                    new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.KeyReference("cmp", "other-ra"),
                    List.of(otherRaFile, otherCaFile))), List.of(otherCaFile), List.of(), Optional.empty()));
            context.enrollmentProfiles().register(new zeroecho.pki.server.enrollment.EnrollmentProfile("cmp-other-enrollment", "Other CMP approval",
                    zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE, "server-tls", Set.of(other.caId().value()), Optional.empty(), List.of(), true));
            context.enrollmentEndpoints().register(new zeroecho.pki.server.cmp.CmpEndpoint("other", other.caId().value(), "server-tls",
                    "cmp-other-enrollment", zeroecho.pki.server.cmp.CmpProtectionPolicy.SIGNATURE_BASED));
        }
        zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration runtime = new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration(
                new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Budgets(100, 50, 64_000_000, 1_048_576, 2, Duration.ofMinutes(10), Duration.ofSeconds(1)),
                List.of(new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Keyring("cmp", ringPath)), sets,
                List.of(new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.ActiveCredential(sets.getFirst().protocol(),
                        sets.getFirst().authorityId(), sets.getFirst().credentialId()),
                        new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.ActiveCredential(sets.getLast().protocol(),
                        sets.getLast().authorityId(), sets.getLast().credentialId())), Optional.empty());
        return new CmpProvisioned(runtime, authority, requester, List.copyOf(responders), secret, otherRoot, otherResponder, otherRequester);
    }

    private static X509Certificate cmpCertificate(String name, int serial, KeyPair subject, KeyPair issuer, X509Certificate authority) {
        return zeroecho.pkix.Pkix.certificateBuilder().subject(new javax.security.auth.x500.X500Principal("CN=" + name))
                .issuer(authority.getSubjectX500Principal()).publicKey(subject.getPublic()).serialNumber(BigInteger.valueOf(serial))
                .validity(authority.getNotBefore().toInstant(), authority.getNotBefore().toInstant().plus(Duration.ofDays(1)))
                .basicConstraints(zeroecho.pkix.BasicConstraints.endEntity(), true).keyUsage(Set.of(zeroecho.pkix.KeyUsage.DIGITAL_SIGNATURE), true)
                .build(zeroecho.pkix.Pkix.signer(issuer.getPrivate(), zeroecho.pkix.AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11")));
    }

    @Test
    void scepDurableApprovalUsesAdvertisedRaAndRetainedCredentialAfterRollover() throws Exception {
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        KeyPair rootKey = rsa((byte) 61);
        KeyPair requesterKey = rsa((byte) 62);
        X509Certificate requester = requesterCertificate(requesterKey);
        int port = reservePort();
        Fixture base = fixture(tls, reservePort(), reservePort(), reservePort(), rootKey);
        seed(base);
        PkiServerConfiguration source = base.configuration();
        PkiServerConfiguration.ScepListener listener = new PkiServerConfiguration.ScepListener("scep-test",
                InetAddress.getLoopbackAddress(), port, new ProviderConfig("test-tls", Map.of()), source.execution(), 16_384, 8192);
        Fixture fixture = new Fixture(new PkiServerConfiguration(source.version(), source.serverName(), source.realm(),
                source.listener(), source.authentication(), source.execution(), source.runtime(), source.publicListener(),
                source.acmeListener(), source.estListener(), Optional.of(listener), source.cmpListener(), source.auditProjection()),
                base.dependencies(), base.http01());
        zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration runtime = provisionScep(fixture, rootKey);
        URI endpoint = URI.create("https://localhost:" + port + "/scep/managed");
        HttpClient wire = HttpClient.newBuilder().sslContext(tls.anonymousContext()).build();
        byte[] nonce = new byte[16]; nonce[0] = 1;
        byte[] csr = ScepTestClient.csr(requesterKey, "scep-secret");
        String id;
        X509Certificate originalRa;
        X509Certificate authority;
        X509Certificate otherRa;
        X509Certificate otherAuthority;
        URI otherEndpoint = URI.create("https://localhost:" + port + "/scep/other");
        try (PkiHttpsServer server = startScep(fixture, runtime)) {
            HttpResponse<byte[]> caps = wire.send(HttpRequest.newBuilder(URI.create(endpoint + "?operation=GetCACaps")).GET().build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            assertEquals("POSTPKIOperation\nSHA-256\nAES\n", new String(caps.body(), StandardCharsets.US_ASCII));
            HttpResponse<byte[]> advertised = wire.send(HttpRequest.newBuilder(URI.create(endpoint + "?operation=GetCACert")).GET().build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            assertEquals("application/x-x509-ca-ra-cert", advertised.headers().firstValue("Content-Type").orElseThrow());
            List<X509Certificate> chain = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(advertised.body()))
                    .stream().map(X509Certificate.class::cast).toList();
            originalRa = chain.stream().filter(cert -> cert.getBasicConstraints() < 0).findFirst().orElseThrow();
            authority = chain.stream().filter(cert -> cert.getBasicConstraints() >= 0).findFirst().orElseThrow();
            originalRa.verify(rootKey.getPublic()); authority.verify(rootKey.getPublic());
            byte[] request = ScepTestClient.request(csr, "durable-one", nonce, 19, requesterKey, requester, originalRa);
            assertEquals("3", ScepTestClient.response(scepPost(wire, endpoint, request).body(), originalRa, requesterKey, nonce).status());
            assertEquals("3", ScepTestClient.response(scepPost(wire, endpoint, request).body(), originalRa, requesterKey, nonce).status());
            id = server.realm().enrollmentCoordinator().orElseThrow().list(0, 256).values().getFirst().id();
            assertScepRequestDisclosure(server.realm(), id, csr);
            assertEquals(1, server.realm().enrollmentCoordinator().orElseThrow().list(0, 256).values().size());
            assertEquals(413, scepPost(wire, endpoint, new byte[8193]).statusCode());
            assertEquals(400, scepPost(wire, endpoint, ScepTestClient.request(csr, "wrong-ra", nonce, 19,
                    requesterKey, requester, requester)).statusCode());
            assertEquals(503, scepPost(wire, endpoint, ScepTestClient.request(ScepTestClient.csr(requesterKey, "changed"),
                    "durable-one", nonce, 19, requesterKey, requester, originalRa)).statusCode());
            assertEquals(413, wire.send(HttpRequest.newBuilder(URI.create(endpoint + "?operation=PKIOperation&message="
                    + Base64.getEncoder().encodeToString(new byte[8193]))).GET().build(), HttpResponse.BodyHandlers.ofByteArray()).statusCode());
            assertEquals(400, scepPost(wire, endpoint, ScepTestClient.request(csr, "bad", nonce, 19,
                    requesterKey, requester, originalRa, "badSignature")).statusCode());
            assertEquals("2", ScepTestClient.response(scepPost(wire, endpoint, ScepTestClient.request(
                    ScepTestClient.csr(requesterKey, "wrong"), "wrong-challenge", nonce, 19, requesterKey, requester, originalRa)).body(),
                    originalRa, requesterKey, nonce).status());
            assertEquals("2", ScepTestClient.response(scepPost(wire, endpoint, ScepTestClient.request(
                    ScepTestClient.poll(authority), "unknown", nonce, 20, requesterKey, requester, originalRa)).body(),
                    originalRa, requesterKey, nonce).status());
            String encoded = java.net.URLEncoder.encode(Base64.getEncoder().encodeToString(request), StandardCharsets.UTF_8);
            HttpResponse<byte[]> get = wire.send(HttpRequest.newBuilder(URI.create(endpoint + "?operation=PKIOperation&message=" + encoded)).GET().build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            assertEquals("3", ScepTestClient.response(get.body(), originalRa, requesterKey, nonce).status());
            HttpResponse<byte[]> otherAdvertisement = wire.send(HttpRequest.newBuilder(URI.create(otherEndpoint + "?operation=GetCACert")).GET().build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            List<X509Certificate> otherChain = CertificateFactory.getInstance("X.509").generateCertificates(
                    new ByteArrayInputStream(otherAdvertisement.body())).stream().map(X509Certificate.class::cast).toList();
            otherRa = otherChain.stream().filter(cert -> cert.getBasicConstraints() < 0).findFirst().orElseThrow();
            otherAuthority = otherChain.stream().filter(cert -> cert.getBasicConstraints() >= 0).findFirst().orElseThrow();
            otherRa.verify(otherAuthority.getPublicKey()); otherAuthority.verify(otherAuthority.getPublicKey());
            org.junit.jupiter.api.Assertions.assertThrows(java.security.GeneralSecurityException.class, () -> otherRa.verify(authority.getPublicKey()));
            assertEquals(400, scepPost(wire, otherEndpoint, request).statusCode());
            assertEquals("3", ScepTestClient.response(scepPost(wire, otherEndpoint, ScepTestClient.request(csr, "durable-one", nonce, 19,
                    requesterKey, requester, otherRa)).body(), otherRa, requesterKey, nonce).status());
            assertEquals(2, server.realm().enrollmentCoordinator().orElseThrow().list(0, 256).values().size());
            assertEquals(2, server.realm().enrollmentCoordinator().orElseThrow().list(0, 256).values().stream()
                    .map(value -> value.intent().authorityId()).distinct().count());
            KeyPair otherRequester = rsa((byte) 67);
            assertEquals("2", ScepTestClient.response(scepPost(wire, otherEndpoint, ScepTestClient.request(
                    ScepTestClient.poll(otherAuthority), "durable-one", nonce, 20, otherRequester,
                    requesterCertificate(otherRequester), otherRa)).body(), otherRa, otherRequester, nonce).status());
            assertEquals(400, scepPost(wire, otherEndpoint, ScepTestClient.request(ScepTestClient.poll(authority),
                    "durable-one", nonce, 20, requesterKey, requester, otherRa)).statusCode());
        }
        zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.CredentialSet second = runtime.credentialSets().get(1);
        zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration rotated = new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration(
                runtime.budgets(), runtime.keyrings(), runtime.credentialSets(), List.of(
                new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.ActiveCredential(second.protocol(), second.authorityId(), second.credentialId()),
                runtime.activeCredentials().getLast()),
                Optional.empty());
        byte[] pollNonce = new byte[16]; pollNonce[0] = 9;
        byte[] poll = ScepTestClient.request(ScepTestClient.poll(authority), "durable-one", pollNonce, 20, requesterKey, requester, originalRa);
        byte[] completed;
        try (PkiHttpsServer server = startScep(fixture, rotated)) {
            HttpResponse<byte[]> advertised = wire.send(HttpRequest.newBuilder(URI.create(endpoint + "?operation=GetCACert")).GET().build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            assertFalse(CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(advertised.body())).contains(originalRa));
            HttpResponse<byte[]> pendingPoll = scepPost(wire, endpoint, poll);
            assertEquals(200, pendingPoll.statusCode(), new String(pendingPoll.body(), StandardCharsets.UTF_8));
            assertEquals("3", ScepTestClient.response(pendingPoll.body(), originalRa, requesterKey, pollNonce).status());
            approveEnrollment(server, id, tls.forwardedCertificate());
            zeroecho.pki.server.enrollment.EnrollmentProfile policy = server.realm().enrollmentProfiles().find("scep-enrollment").orElseThrow();
            server.realm().enrollmentProfiles().setState(policy.id(), zeroecho.pki.server.enrollment.EnrollmentProfileState.SUSPENDED);
            assertEquals(503, scepPost(wire, endpoint, poll).statusCode());
            server.realm().enrollmentProfiles().setState(policy.id(), zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            ScepTestClient.Response response;
            do {
                HttpResponse<byte[]> wireResponse = scepPost(wire, endpoint, poll);
                assertEquals(200, wireResponse.statusCode(), new String(wireResponse.body(), StandardCharsets.UTF_8));
                completed = wireResponse.body();
                response = ScepTestClient.response(completed, originalRa, requesterKey, pollNonce);
            } while ("3".equals(response.status()) && System.nanoTime() < deadline);
            assertEquals("0", response.status());
            response.certificate().verify(rootKey.getPublic());
            org.junit.jupiter.api.Assertions.assertArrayEquals(requesterKey.getPublic().getEncoded(), response.certificate().getPublicKey().getEncoded());
            assertEquals("scep-a", server.realm().enrollmentCoordinator().orElseThrow().find(id).orElseThrow().intent().source().credentialId().orElseThrow());
        }
        try (PkiHttpsServer server = startScep(fixture, rotated)) {
            assertEquals("0", ScepTestClient.response(scepPost(wire, endpoint, poll).body(), originalRa, requesterKey, pollNonce).status());
            assertEquals(2, server.realm().enrollmentCoordinator().orElseThrow().list(0, 256).values().size());
            zeroecho.pki.server.scep.ScepEndpoint endpointRecord = server.realm().enrollmentEndpoints()
                    .find(zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry.Protocol.SCEP, "managed")
                    .map(zeroecho.pki.server.scep.ScepEndpoint.class::cast).orElseThrow();
            server.realm().enrollmentEndpoints().register(new zeroecho.pki.server.scep.ScepEndpoint("managed", endpointRecord.authorityId(),
                    endpointRecord.profileId(), endpointRecord.enrollmentProfileId(), "f".repeat(64)));
            assertEquals("0", ScepTestClient.response(scepPost(wire, endpoint, ScepTestClient.request(csr, "durable-one", nonce, 19,
                    requesterKey, requester, originalRa)).body(), originalRa, requesterKey, nonce).status());
        }
        try (PkiHttpsServer server = PkiHttpsServer.start(fixture.configuration(), fixture.dependencies(), Clock.offset(CLOCK, Duration.ofHours(2)),
                HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader(), Optional.empty(), Optional.of(rotated))) {
            byte[] expired = ScepTestClient.request(ScepTestClient.poll(otherAuthority), "durable-one", pollNonce, 20,
                    requesterKey, requester, otherRa);
            assertEquals("2", ScepTestClient.response(scepPost(wire, otherEndpoint, expired).body(), otherRa, requesterKey, pollNonce).status());
            assertEquals(zeroecho.pki.server.enrollment.EnrollmentTransaction.State.EXPIRED, server.realm().enrollmentCoordinator().orElseThrow()
                    .list(0, 256).values().stream().filter(value -> value.intent().source().label().equals("other")).findFirst().orElseThrow().state());
        }
    }

    private static HttpResponse<byte[]> scepPost(HttpClient client, URI endpoint, byte[] body) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(endpoint + "?operation=PKIOperation"))
                .header("Content-Type", "application/x-pki-message").POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(),
                HttpResponse.BodyHandlers.ofByteArray());
    }

    private static void assertScepRequestDisclosure(ServerRealmContext realm, String id, byte[] original) {
        zeroecho.pki.server.enrollment.EnrollmentTransaction transaction = realm.enrollmentCoordinator().orElseThrow().find(id).orElseThrow();
        zeroecho.pki.api.CertificationRequestService requests = realm.session().requests().orElseThrow();
        org.junit.jupiter.api.Assertions.assertArrayEquals(original, requests.encodedX509Request(
                requests.get(transaction.intent().requestId()).orElseThrow()).der());
        for (zeroecho.pki.application.PkiOperation operation : List.of(
                new zeroecho.pki.application.PkiOperation.InspectRequest(transaction.intent().requestId()),
                new zeroecho.pki.application.PkiOperation.ListRequests(10, Optional.empty()))) {
            zeroecho.pki.application.PkiOperationOutcome outcome = realm.session().operations().execute(operation, zeroecho.core.io.CancellationSignal.NONE);
            assertInstanceOf(zeroecho.pki.application.PkiOperationOutcome.Completed.class, outcome);
            assertFalse(outcome.toString().contains("scep-secret"));
            assertFalse(outcome.toString().contains(Base64.getEncoder().encodeToString(original)));
        }
        Permission.Scope scope = new Permission.Scope(realm.configuration().realmId(), Optional.empty(), Optional.empty(), Optional.empty());
        realm.grant(ServerTestSupport.grant("scep-request-read", "approver", Permission.Effect.ALLOW, Permission.Action.REQUEST_READ_ANY,
                Permission.ResourceType.ENROLLMENT_REQUEST, scope, Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED), "bootstrap");
        Permission.Resource resource = new Permission.Resource(Permission.ResourceType.ENROLLMENT_REQUEST, scope, Optional.empty(), Optional.empty());
        for (ServerControlOperation operation : List.of(new ServerControlOperation.InspectEnrollmentRequest(id), new ServerControlOperation.ListEnrollmentRequests(0, 10))) {
            ServerOperationGateway.Outcome outcome = realm.gateway().execute(new ServerOperationGateway.Request(realm.configuration().realmId(), "approver",
                    AdministrativeAuthenticationMode.DIRECT_MTLS, Optional.empty(), Optional.empty(), new AdministrativeOperation.Control(operation),
                    resource, Permission.Relationship.ANY, Permission.Context.empty(), Optional.empty(), "scep-disclosure-test"), zeroecho.core.io.CancellationSignal.NONE);
            ServerOperationGateway.Outcome.ControlExecuted executed = assertInstanceOf(ServerOperationGateway.Outcome.ControlExecuted.class, outcome);
            assertInstanceOf(zeroecho.pki.application.PkiOperationOutcome.Completed.class,
                    assertInstanceOf(ServerControlOperationOutcome.Ordinary.class, executed.outcome()).outcome());
            assertFalse(outcome.toString().contains("scep-secret"));
            assertFalse(outcome.toString().contains(Base64.getEncoder().encodeToString(original)));
        }
    }

    private PkiHttpsServer startScep(Fixture fixture, zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration runtime) throws Exception {
        return PkiHttpsServer.start(fixture.configuration(), fixture.dependencies(), CLOCK, HttpServerTestSupport.random(),
                TestTlsProvider.class.getClassLoader(), Optional.empty(), Optional.of(runtime));
    }

    private zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration provisionScep(Fixture fixture, KeyPair rootKey) throws Exception {
        Path ringPath = temporaryDirectory.resolve("scep-custody.zek");
        List<zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.CredentialSet> sets = new java.util.ArrayList<>();
        KeyPair otherRootKey = rsa((byte) 65);
        try (KeyringPassword password = new KeyringPassword(KEYRING_PASSWORD.clone());
                KeyringStore signing = KeyringStore.open(temporaryDirectory.resolve("server/signing-keyring.zek"), password)) {
            signing.putPrivate("other.prv", "RSA", otherRootKey.getPrivate());
            signing.putPublic("other.pub", "RSA", otherRootKey.getPublic());
        }
        try (ServerRealmContext context = ServerRealmContext.open(fixture.configuration().realm(), fixture.dependencies(), CLOCK, HttpServerTestSupport.random());
                KeyringPassword password = new KeyringPassword(KEYRING_PASSWORD.clone());
                KeyringStore ring = KeyringStore.create(ringPath, password)) {
            AcmeState.Directory directory = context.acmeControl().page(AcmeState.Directory.class, 0, 256).values().getFirst();
            zeroecho.pki.api.ca.IssuerGeneration issuer = context.session().repository().issuer(directory.issuerId()).orElseThrow();
            X509Certificate authority;
            try (zeroecho.pki.application.PkiRepositoryContent content = context.session().repository().openCredential(issuer.credentialId());
                    java.io.InputStream input = content.openStream()) {
                authority = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
            }
            Path rootPath = temporaryDirectory.resolve("scep-root.der"); java.nio.file.Files.write(rootPath, authority.getEncoded());
            for (int index = 0; index < 2; index++) {
                KeyPair key = rsa((byte) (63 + index));
                String id = index == 0 ? "scep-a" : "scep-b";
                X509Certificate ra = zeroecho.pkix.Pkix.certificateBuilder().subject(new javax.security.auth.x500.X500Principal("CN=" + id))
                        .issuer(authority.getSubjectX500Principal()).publicKey(key.getPublic()).serialNumber(BigInteger.valueOf(9100 + index))
                        .validity(authority.getNotBefore().toInstant(), authority.getNotBefore().toInstant().plus(Duration.ofDays(1)))
                        .basicConstraints(zeroecho.pkix.BasicConstraints.endEntity(), true)
                        .keyUsage(Set.of(zeroecho.pkix.KeyUsage.DIGITAL_SIGNATURE, zeroecho.pkix.KeyUsage.KEY_ENCIPHERMENT), true)
                        .build(zeroecho.pkix.Pkix.signer(rootKey.getPrivate(), zeroecho.pkix.AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11")));
                Path certificate = temporaryDirectory.resolve(id + ".der"); java.nio.file.Files.write(certificate, ra.getEncoded());
                ring.putPrivate(id, "RSA", key.getPrivate());
                sets.add(new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.CredentialSet(id,
                        zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Protocol.SCEP, directory.authorityId().value(),
                        directory.issuerId().value(), directory.issuancePathId().value(), Optional.of(
                        new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Signer(
                                new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.KeyReference("scep", id),
                                List.of(certificate, rootPath))), List.of(), List.of(), Optional.empty()));
            }
            context.enrollmentProfiles().register(new zeroecho.pki.server.enrollment.EnrollmentProfile("scep-enrollment", "SCEP approval",
                    zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE, "server-tls", Set.of(directory.authorityId().value()),
                    Optional.empty(), List.of(), true));
            context.enrollmentEndpoints().register(new zeroecho.pki.server.scep.ScepEndpoint("managed", directory.authorityId().value(),
                    "server-tls", "scep-enrollment", HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest("scep-secret".getBytes(StandardCharsets.UTF_8)))));
            context.createPrincipal(ServerTestSupport.principal("approver"), "bootstrap");
            zeroecho.pki.api.SemanticSigningService signing = context.session().semanticSigning().orElseThrow();
            zeroecho.pki.api.signing.PreparedSemanticSigningRequest prepared = signing.prepareRootCreation(
                    new zeroecho.pki.api.audit.AccessContext(new zeroecho.pki.api.audit.Principal("SYSTEM", "test"),
                            new zeroecho.pki.api.audit.Purpose("ca.create"), Optional.empty(), Optional.empty()),
                    new CaCreateCommand(template("root-ca").definition().formatId(), new SubjectRef("CN=Other SCEP authority"),
                            "root-ca", new KeyRef("acme-test:other.prv"), new SimpleAttributeSet()), zeroecho.core.io.CancellationSignal.NONE);
            PkiId otherCredential = awaitSigning(signing, signing.accept(prepared).receipt().operationId()).completedCredentialId().orElseThrow();
            X509Certificate otherRoot;
            try (zeroecho.pki.application.PkiRepositoryContent content = context.session().repository().openCredential(otherCredential);
                    java.io.InputStream input = content.openStream()) {
                otherRoot = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
            }
            awaitCertificateValidity(otherRoot);
            zeroecho.pki.api.ca.CaRecord otherAuthority = context.session().repository().authority(
                    context.session().repository().credential(otherCredential).orElseThrow().issuerRef().caId()).orElseThrow();
            KeyPair otherRaKey = rsa((byte) 66);
            X509Certificate otherRa = zeroecho.pkix.Pkix.certificateBuilder().subject(new javax.security.auth.x500.X500Principal("CN=Other SCEP RA"))
                    .issuer(otherRoot.getSubjectX500Principal()).publicKey(otherRaKey.getPublic()).serialNumber(BigInteger.valueOf(9200))
                    .validity(otherRoot.getNotBefore().toInstant(), otherRoot.getNotBefore().toInstant().plus(Duration.ofDays(1)))
                    .basicConstraints(zeroecho.pkix.BasicConstraints.endEntity(), true)
                    .keyUsage(Set.of(zeroecho.pkix.KeyUsage.DIGITAL_SIGNATURE, zeroecho.pkix.KeyUsage.KEY_ENCIPHERMENT), true)
                    .build(zeroecho.pkix.Pkix.signer(otherRootKey.getPrivate(), zeroecho.pkix.AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11")));
            Path otherCaFile = temporaryDirectory.resolve("scep-other-ca.der"); java.nio.file.Files.write(otherCaFile, otherRoot.getEncoded());
            Path otherRaFile = temporaryDirectory.resolve("scep-other-ra.der"); java.nio.file.Files.write(otherRaFile, otherRa.getEncoded());
            ring.putPrivate("other-ra", "RSA", otherRaKey.getPrivate());
            sets.add(new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.CredentialSet("scep-other",
                    zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Protocol.SCEP, otherAuthority.caId().value(),
                    otherAuthority.currentIssuanceIssuerId().value(), otherAuthority.issuanceChainPathId().value(), Optional.of(
                    new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Signer(
                            new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.KeyReference("scep", "other-ra"),
                            List.of(otherRaFile, otherCaFile))), List.of(), List.of(), Optional.empty()));
            context.enrollmentProfiles().register(new zeroecho.pki.server.enrollment.EnrollmentProfile("scep-other-enrollment", "Other SCEP approval",
                    zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE, "server-tls", Set.of(otherAuthority.caId().value()),
                    Optional.empty(), List.of(), true));
            context.enrollmentEndpoints().register(new zeroecho.pki.server.scep.ScepEndpoint("other", otherAuthority.caId().value(),
                    "server-tls", "scep-other-enrollment", HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest("scep-secret".getBytes(StandardCharsets.UTF_8)))));
        }
        return new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration(EnrollmentTestSupport.runtimeConfiguration().budgets(),
                List.of(new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Keyring("scep", ringPath)), sets,
                List.of(new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.ActiveCredential(sets.getFirst().protocol(),
                        sets.getFirst().authorityId(), sets.getFirst().credentialId()),
                        new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.ActiveCredential(sets.getLast().protocol(),
                        sets.getLast().authorityId(), sets.getLast().credentialId())), Optional.empty());
    }

    @Test
    void estGeneratedKeyApprovalRestartRolloverDeliveryAndExpiryUseRealHttps() throws Exception {
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        KeyPair rootKey = rsa((byte) 121);
        KeyPair recipientKey = HttpServerTestSupport.keyPair((byte) 3);
        int port = reservePort();
        Fixture base = fixture(tls, reservePort(), reservePort(), reservePort(), rootKey);
        seed(base);
        PkiServerConfiguration source = base.configuration();
        PkiServerConfiguration.EstListener listener = new PkiServerConfiguration.EstListener("est-keygen",
                InetAddress.getLoopbackAddress(), port, new ProviderConfig("test-tls", Map.of()), source.execution(), 16_384, 8192);
        Fixture fixture = new Fixture(new PkiServerConfiguration(source.version(), source.serverName(), source.realm(), source.listener(),
                source.authentication(), source.execution(), source.runtime(), source.publicListener(), source.acmeListener(), Optional.of(listener),
                source.scepListener(), source.cmpListener(), source.auditProjection()), base.dependencies(), base.http01());
        zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration runtime = provisionEstGenerator(fixture, rootKey);
        X509Certificate generatorCertificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(java.nio.file.Files.readAllBytes(temporaryDirectory.resolve("est-generator-a.der"))));
        org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder request = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=localhost"), recipientKey.getPublic());
        request.addAttribute(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.840.113549.1.9.15"),
                new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.DERSequence(
                        new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.840.113549.1.1.1"))));
        request.addAttribute(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.54"),
                new org.bouncycastle.asn1.DEROctetString(MessageDigest.getInstance("SHA-256").digest(recipientKey.getPublic().getEncoded())));
        request.addAttribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                new org.bouncycastle.asn1.x509.Extensions(new org.bouncycastle.asn1.x509.Extension(
                        org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false,
                        new org.bouncycastle.asn1.x509.GeneralNames(new org.bouncycastle.asn1.x509.GeneralName(
                                org.bouncycastle.asn1.x509.GeneralName.dNSName, "localhost")).getEncoded())));
        byte[] template = request.build(new JcaContentSignerBuilder("SHA256withRSA").build(recipientKey.getPrivate())).getEncoded();
        template[template.length - 1] ^= 1; // Original template signature is deliberately irrelevant.
        byte[] body = Base64.getMimeEncoder().encode(template);
        URI endpoint = URI.create("https://localhost:" + port + "/.well-known/est/managed/serverkeygen");
        HttpClient wire = HttpClient.newBuilder().sslContext(tls.clientContext()).build();
        String enrollmentId;
        byte[] ciphertext;
        try (PkiHttpsServer server = startScep(fixture, runtime)) {
            AcmeState.Directory directory = server.realm().acmeControl().page(AcmeState.Directory.class, 0, 256).values().getFirst();
            server.realm().enrollmentEndpoints().register(new zeroecho.pki.server.est.EstEndpoint("managed", directory.authorityId().value(),
                    "server-tls", "est-keygen", new zeroecho.pki.server.est.KeygenPolicy(true, List.of("RSA"), 2048, false)));
            HttpResponse<byte[]> pending = estPost(wire, endpoint, body);
            assertEquals(202, pending.statusCode(), new String(pending.body(), StandardCharsets.UTF_8));
            assertTrue(Long.parseLong(pending.headers().firstValue("Retry-After").orElseThrow()) > 0);
            zeroecho.pki.server.enrollment.EnrollmentTransaction enrollment = server.realm().enrollmentCoordinator().orElseThrow().list(0, 10).values().getFirst();
            enrollmentId = enrollment.id();
            assertEquals(zeroecho.pki.server.enrollment.EnrollmentTransaction.State.PENDING, enrollment.state());
            assertTrue(enrollment.receipt().isEmpty());
            ciphertext = java.nio.file.Files.readAllBytes(runtime.keygenArtifacts().orElseThrow().directory()
                    .resolve(enrollment.intent().artifact().orElseThrow().artifactId() + ".cms"));
            assertEquals(202, estPost(wire, endpoint, body).statusCode());
        }
        zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.CredentialSet next = runtime.credentialSets().getLast();
        zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration rotated = new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration(
                runtime.budgets(), runtime.keyrings(), runtime.credentialSets(), List.of(
                new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.ActiveCredential(next.protocol(), next.authorityId(), next.credentialId())), runtime.keygenArtifacts());
        byte[] complete;
        try (PkiHttpsServer server = startScep(fixture, rotated)) {
            approveEnrollment(server, enrollmentId, tls.forwardedCertificate());
            HttpResponse<byte[]> delivered = awaitEst(wire, endpoint, body);
            complete = delivered.body();
            assertEquals("no-store", delivered.headers().firstValue("Cache-Control").orElseThrow());
            verifyGeneratedKeyDelivery(delivered, ciphertext, recipientKey, generatorCertificate, rootKey);
            assertArrayEquals(complete, estPost(wire, endpoint, body).body());
            assertEquals(1, server.realm().enrollmentCoordinator().orElseThrow().list(0, 10).values().size());
        }
        try (PkiHttpsServer server = startScep(fixture, rotated)) {
            assertArrayEquals(complete, estPost(wire, endpoint, body).body());
        }
        try (PkiHttpsServer server = PkiHttpsServer.start(fixture.configuration(), fixture.dependencies(), Clock.offset(CLOCK, Duration.ofMinutes(11)),
                HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader(), Optional.empty(), Optional.of(rotated))) {
            assertEquals(410, estPost(wire, endpoint, body).statusCode());
            assertEquals(1, server.realm().enrollmentCoordinator().orElseThrow().list(0, 10).values().size());
            try (java.util.stream.Stream<Path> artifacts = java.nio.file.Files.list(runtime.keygenArtifacts().orElseThrow().directory())) {
                assertFalse(artifacts.anyMatch(path -> path.getFileName().toString().endsWith(".cms")));
            }
        }
    }

    private zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration provisionEstGenerator(Fixture fixture, KeyPair rootKey) throws Exception {
        Path ringPath = temporaryDirectory.resolve("est-generator.zek");
        java.nio.file.Files.createDirectory(temporaryDirectory.resolve("est-artifacts"));
        java.nio.file.Files.setPosixFilePermissions(temporaryDirectory.resolve("est-artifacts"), java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        List<zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.CredentialSet> sets = new java.util.ArrayList<>();
        try (ServerRealmContext context = ServerRealmContext.open(fixture.configuration().realm(), fixture.dependencies(), CLOCK, HttpServerTestSupport.random());
                KeyringPassword password = new KeyringPassword(KEYRING_PASSWORD.clone()); KeyringStore ring = KeyringStore.create(ringPath, password)) {
            AcmeState.Directory directory = context.acmeControl().page(AcmeState.Directory.class, 0, 256).values().getFirst();
            zeroecho.pki.api.ca.IssuerGeneration issuer = context.session().repository().issuer(directory.issuerId()).orElseThrow();
            X509Certificate authority;
            try (zeroecho.pki.application.PkiRepositoryContent content = context.session().repository().openCredential(issuer.credentialId());
                    java.io.InputStream input = content.openStream()) { authority = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input); }
            Path root = temporaryDirectory.resolve("est-root.der"); java.nio.file.Files.write(root, authority.getEncoded());
            for (int index = 0; index < 2; index++) {
                KeyPair key = rsa((byte) (122 + index));
                String id = index == 0 ? "est-generator-a" : "est-generator-b";
                X509Certificate certificate = zeroecho.pkix.Pkix.certificateBuilder().subject(new javax.security.auth.x500.X500Principal("CN=" + id))
                        .issuer(authority.getSubjectX500Principal()).serialNumber(BigInteger.valueOf(9300 + index)).publicKey(key.getPublic())
                        .validity(authority.getNotBefore().toInstant(), authority.getNotBefore().toInstant().plus(Duration.ofDays(1)))
                        .basicConstraints(zeroecho.pkix.BasicConstraints.endEntity(), true).keyUsage(Set.of(zeroecho.pkix.KeyUsage.DIGITAL_SIGNATURE), true)
                        .build(zeroecho.pkix.Pkix.signer(rootKey.getPrivate(), zeroecho.pkix.AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11")));
                Path file = temporaryDirectory.resolve(id + ".der"); java.nio.file.Files.write(file, certificate.getEncoded()); ring.putPrivate(id, "RSA", key.getPrivate());
                sets.add(new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.CredentialSet(id,
                        zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Protocol.EST, directory.authorityId().value(), directory.issuerId().value(),
                        directory.issuancePathId().value(), Optional.of(new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Signer(
                                new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.KeyReference("est", id), List.of(file, root))), List.of(), List.of(), Optional.empty()));
            }
            context.enrollmentProfiles().register(new zeroecho.pki.server.enrollment.EnrollmentProfile("est-keygen", "EST generated key approval",
                    zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE, "server-tls", Set.of(directory.authorityId().value()), Optional.empty(), List.of(), true));
            context.createPrincipal(ServerTestSupport.principal("approver"), "bootstrap");
        }
        return new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration(EnrollmentTestSupport.runtimeConfiguration().budgets(),
                List.of(new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.Keyring("est", ringPath)), sets,
                List.of(new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.ActiveCredential(sets.getFirst().protocol(),
                        sets.getFirst().authorityId(), sets.getFirst().credentialId())), Optional.of(
                new zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.KeygenArtifacts(temporaryDirectory.resolve("est-artifacts"), 65_536, 131_072, 4, 1, Duration.ofMinutes(10))));
    }

    private static void verifyGeneratedKeyDelivery(HttpResponse<byte[]> response, byte[] ciphertext, KeyPair recipient,
            X509Certificate generator, KeyPair authority) throws Exception {
        String media = response.headers().firstValue("Content-Type").orElseThrow();
        assertTrue(media.startsWith("multipart/mixed; boundary=\""));
        String boundary = media.substring(media.indexOf('"') + 1, media.lastIndexOf('"'));
        String[] parts = new String(response.body(), StandardCharsets.US_ASCII).split(java.util.regex.Pattern.quote("--" + boundary));
        assertEquals(4, parts.length);
        assertTrue(parts[1].contains("smime-type=server-generated-key"));
        assertTrue(parts[2].contains("smime-type=certs-only"));
        byte[] encrypted = Base64.getMimeDecoder().decode(parts[1].substring(parts[1].indexOf("\r\n\r\n") + 4));
        assertArrayEquals(ciphertext, encrypted);
        org.bouncycastle.cms.CMSEnvelopedData envelope = new org.bouncycastle.cms.CMSEnvelopedData(encrypted);
        assertEquals(org.bouncycastle.asn1.cms.CMSObjectIdentifiers.signedData,
                org.bouncycastle.asn1.cms.EnvelopedData.getInstance(envelope.toASN1Structure().getContent()).getEncryptedContentInfo().getContentType());
        assertEquals(1, envelope.getRecipientInfos().size());
        byte[] signedDer = envelope.getRecipientInfos().getRecipients().iterator().next().getContent(
                new org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient(recipient.getPrivate()).setProvider("BC"));
        org.bouncycastle.cms.CMSSignedData signed = new org.bouncycastle.cms.CMSSignedData(new org.bouncycastle.asn1.cms.ContentInfo(
                org.bouncycastle.asn1.cms.CMSObjectIdentifiers.signedData, org.bouncycastle.asn1.ASN1Primitive.fromByteArray(signedDer)));
        assertEquals("2.16.840.1.101.2.1.2.78.5", signed.getSignedContentTypeOID());
        assertEquals(1, signed.getSignerInfos().size());
        assertTrue(signed.getSignerInfos().getSigners().iterator().next().verify(new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(generator)));
        org.bouncycastle.asn1.ASN1Sequence keys = org.bouncycastle.asn1.ASN1Sequence.getInstance(signed.getSignedContent().getContent());
        assertEquals(1, keys.size());
        java.security.PrivateKey key = java.security.KeyFactory.getInstance("RSA").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(keys.getObjectAt(0).toASN1Primitive().getEncoded("DER")));
        byte[] chain = Base64.getMimeDecoder().decode(parts[2].substring(parts[2].indexOf("\r\n\r\n") + 4));
        X509Certificate leaf = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(chain)).stream()
                .map(X509Certificate.class::cast).filter(value -> value.getBasicConstraints() < 0).findFirst().orElseThrow();
        leaf.verify(authority.getPublic());
        assertEquals(List.of(List.of(2, "localhost")), List.copyOf(leaf.getSubjectAlternativeNames()));
        java.security.Signature proof = java.security.Signature.getInstance("SHA256withRSA");
        proof.initSign(key); proof.update(new byte[] {1, 2, 3}); byte[] signature = proof.sign();
        proof.initVerify(leaf); proof.update(new byte[] {1, 2, 3}); assertTrue(proof.verify(signature));
        assertFalse(java.util.Arrays.equals(recipient.getPublic().getEncoded(), leaf.getPublicKey().getEncoded()));
    }

    @Test
    void estApprovalRetriesAndRenewalSurviveHttpsRestart() throws Exception {
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        KeyPair rootKey = rsa((byte) 51);
        KeyPair leafKey = rsa((byte) 52);
        int estPort = reservePort();
        Fixture base = fixture(tls, reservePort(), reservePort(), reservePort(), rootKey);
        PkiServerConfiguration source = base.configuration();
        PkiServerConfiguration.EstListener listener = new PkiServerConfiguration.EstListener("est-test",
                InetAddress.getLoopbackAddress(), estPort, new ProviderConfig("test-tls", Map.of()),
                source.execution(), 16_384, 4096);
        Fixture fixture = new Fixture(new PkiServerConfiguration(source.version(), source.serverName(), source.realm(),
                source.listener(), source.authentication(), source.execution(), source.runtime(), source.publicListener(),
                source.acmeListener(), Optional.of(listener), source.scepListener(), source.cmpListener(), source.auditProjection()),
                base.dependencies(), base.http01());
        seed(fixture);
        byte[] body = Base64.getMimeEncoder().encode(csr(leafKey));
        URI enroll = URI.create("https://localhost:" + estPort + "/.well-known/est/managed/simpleenroll");
        HttpClient wire = HttpClient.newBuilder().sslContext(tls.clientContext()).build();
        String pendingId;
        X509Certificate leaf;
        X509Certificate authorityCertificate;
        try (PkiHttpsServer server = start(fixture)) {
            AcmeState.Directory directory = server.realm().acmeControl().page(AcmeState.Directory.class, 0, 256).values().getFirst();
            byte[] profile = new String(template("server-tls").canonicalJson(), StandardCharsets.UTF_8)
                    .replace("server-tls", "client-tls").replace("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2")
                    .getBytes(StandardCharsets.UTF_8);
            server.realm().session().profiles().importProfile(profile);
            server.realm().session().profiles().activateProfile("client-tls", 1L);
            server.realm().enrollmentProfiles().register(new zeroecho.pki.server.enrollment.EnrollmentProfile(
                    "est-enrollment", "EST approval", zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE,
                    "client-tls", Set.of(directory.authorityId().value()), Optional.empty(), List.of(), true));
            server.realm().enrollmentEndpoints().register(new zeroecho.pki.server.est.EstEndpoint(
                    "managed", directory.authorityId().value(), "client-tls", "est-enrollment",
                    zeroecho.pki.server.est.KeygenPolicy.DISABLED));
            server.realm().createPrincipal(ServerTestSupport.principal("approver"), "bootstrap");
            HttpClient anonymous = HttpClient.newBuilder().sslContext(tls.anonymousContext()).build();
            org.junit.jupiter.api.Assertions.assertThrows(java.io.IOException.class, () -> estPost(anonymous, enroll, body));
            assertEquals(413, estPost(wire, enroll, new byte[4097]).statusCode());
            HttpResponse<byte[]> pending = estPost(wire, enroll, body);
            assertEquals(202, pending.statusCode(), new String(pending.body(), StandardCharsets.UTF_8));
            assertTrue(Long.parseLong(pending.headers().firstValue("Retry-After").orElseThrow()) > 0);
            assertEquals(0, pending.body().length);
            pendingId = server.realm().enrollmentCoordinator().orElseThrow().list(0, 256).values().getFirst().id();
            assertEquals(202, estPost(wire, enroll, body).statusCode());
            assertEquals(1, server.realm().enrollmentCoordinator().orElseThrow().list(0, 256).values().size());
        }
        try (PkiHttpsServer server = start(fixture)) {
            approveEnrollment(server, pendingId, tls.forwardedCertificate());
            HttpResponse<byte[]> completed = awaitEst(wire, enroll, body);
            java.util.Collection<? extends java.security.cert.Certificate> chain = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(completed.body())));
            leaf = chain.stream().map(X509Certificate.class::cast).filter(value -> value.getBasicConstraints() < 0).findFirst().orElseThrow();
            authorityCertificate = chain.stream().map(X509Certificate.class::cast).filter(value -> value.getBasicConstraints() >= 0).findFirst().orElseThrow();
            leaf.verify(rootKey.getPublic());
            org.junit.jupiter.api.Assertions.assertArrayEquals(leafKey.getPublic().getEncoded(), leaf.getPublicKey().getEncoded());
            org.junit.jupiter.api.Assertions.assertArrayEquals(completed.body(), estPost(wire, enroll, body).body());
        }
        // The next TLS server trusts the issuing CA for certificate-authenticated reenrollment.
        HttpServerTestSupport.tls(authorityCertificate);
        HttpClient renewing = HttpClient.newBuilder().sslContext(HttpServerTestSupport.context(leafKey, leaf,
                tls.rootCertificate(), true, authorityCertificate)).build();
        URI renew = URI.create("https://localhost:" + estPort + "/.well-known/est/managed/simplereenroll");
        try (PkiHttpsServer server = start(fixture)) {
            assertEquals(202, estPost(renewing, renew, body).statusCode());
            zeroecho.pki.server.enrollment.EnrollmentTransaction pending = server.realm().enrollmentCoordinator().orElseThrow()
                    .list(0, 256).values().stream().filter(value -> value.intent().operation()
                            == zeroecho.pki.server.enrollment.EnrollmentTransaction.Operation.RENEW).findFirst().orElseThrow();
            approveEnrollment(server, pending.id(), tls.forwardedCertificate());
            HttpResponse<byte[]> completed = awaitEst(renewing, renew, body);
            X509Certificate renewed = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(completed.body())))
                    .stream().map(X509Certificate.class::cast).filter(value -> value.getBasicConstraints() < 0).findFirst().orElseThrow();
            renewed.verify(rootKey.getPublic());
            org.junit.jupiter.api.Assertions.assertArrayEquals(leaf.getPublicKey().getEncoded(), renewed.getPublicKey().getEncoded());
            assertFalse(leaf.getSerialNumber().equals(renewed.getSerialNumber()));
            assertEquals(2, server.realm().enrollmentCoordinator().orElseThrow().list(0, 256).values().size());
            byte[] rejectedBody = Base64.getEncoder().encode(csr(rsa((byte) 53)));
            assertEquals(202, estPost(wire, enroll, rejectedBody).statusCode());
            zeroecho.pki.server.enrollment.EnrollmentCoordinator coordinator = server.realm().enrollmentCoordinator().orElseThrow();
            zeroecho.pki.server.enrollment.EnrollmentTransaction rejected = coordinator.list(0, 256).values().stream()
                    .filter(value -> value.state() == zeroecho.pki.server.enrollment.EnrollmentTransaction.State.PENDING).findFirst().orElseThrow();
            coordinator.decide(rejected.id(), rejected.commitment(), new AdministrativeDecisionActor("approver", Optional.of(
                    CertificateIdentityEvidence.fromCertificate(server.realm().configuration().realmId(), tls.forwardedCertificate()))),
                    ApprovalService.Choice.REJECT, "Rejected requested identity");
            assertEquals(403, estPost(wire, enroll, rejectedBody).statusCode());
        }
    }

    private static void approveEnrollment(PkiHttpsServer server, String id, X509Certificate administrator) throws Exception {
        zeroecho.pki.server.enrollment.EnrollmentCoordinator coordinator = server.realm().enrollmentCoordinator().orElseThrow();
        zeroecho.pki.server.enrollment.EnrollmentTransaction pending = coordinator.find(id).orElseThrow();
        coordinator.decide(id, pending.commitment(), new AdministrativeDecisionActor("approver", Optional.of(
                CertificateIdentityEvidence.fromCertificate(server.realm().configuration().realmId(), administrator))),
                ApprovalService.Choice.APPROVE, "Verified exact retained CSR");
    }

    private static HttpResponse<byte[]> estPost(HttpClient client, URI uri, byte[] body) throws Exception {
        return client.send(HttpRequest.newBuilder(uri).header("Content-Type", "application/pkcs10")
                .header("Content-Transfer-Encoding", "base64").POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(),
                HttpResponse.BodyHandlers.ofByteArray());
    }

    private static HttpResponse<byte[]> awaitEst(HttpClient client, URI uri, byte[] body) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        HttpResponse<byte[]> result;
        do {
            result = estPost(client, uri, body);
            if (result.statusCode() != 202) break;
            assertTrue(System.nanoTime() < deadline, "EST issuance did not complete");
            TimeUnit.MILLISECONDS.sleep(5);
        } while (true);
        assertEquals(200, result.statusCode(), new String(result.body(), StandardCharsets.UTF_8));
        return result;
    }

    @Test
    void approvalSurvivesRestartAndAccountRolloverBeforeAuthenticatedPollDispatch() throws Exception {
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        int port = reservePort();
        int challengePort = reservePort();
        KeyPair rootKey = rsa((byte) 41);
        KeyPair leafKey = rsa((byte) 42);
        KeyPair accountKey = ec((byte) 43);
        KeyPair replacement = ec((byte) 44);
        KeyPair finalKey = ec((byte) 46);
        Fixture fixture = fixture(tls, port, reservePort(), challengePort, rootKey);
        seed(fixture);
        URI directoryUri = URI.create("https://localhost:" + port + "/acme/" + DIRECTORY_ALIAS + "/directory");
        HttpClient wire = HttpClient.newBuilder().sslContext(tls.anonymousContext()).build();
        URI orderUri;
        String accountKid;
        String transactionId;
        String originalRequesterKey;
        try (PkiHttpsServer server = start(fixture);
                AcmeTestClient client = new AcmeTestClient(wire, directoryUri, accountKey)) {
            requireHumanApproval(server);
            AcmeTestClient.Response directory = client.directory();
            client.nonce(URI.create(AcmeTestClient.text(directory, "newNonce")));
            assertEquals(201, client.createAccount(URI.create(AcmeTestClient.text(directory, "newAccount")),
                    "{\"termsOfServiceAgreed\":true}").status());
            accountKid = client.accountKid();
            AcmeTestClient.Response ready = readyOrder(client, directory, challengePort);
            orderUri = URI.create(ready.header("Location").orElseThrow());
            URI finalizeUri = URI.create(AcmeTestClient.text(ready, "finalize"));
            String csr = Base64.getUrlEncoder().withoutPadding().encodeToString(csr(leafKey));
            AcmeTestClient.Response pending = client.kid(finalizeUri, "{\"csr\":\"" + csr + "\"}");
            assertEquals(200, pending.status(), pending.bodyText());
            assertEquals("processing", AcmeTestClient.text(pending, "status"));
            String orderId = orderUri.getPath().substring(orderUri.getPath().lastIndexOf('/') + 1);
            AcmeState.Order stored = server.realm().acmeControl().get(AcmeState.Order.class, orderId).orElseThrow();
            assertTrue(stored.signingOperationId().isEmpty());
            zeroecho.pki.server.enrollment.EnrollmentTransaction transaction =
                    server.realm().enrollmentCoordinator().orElseThrow().list(0, 256).values().getFirst();
            assertEquals(zeroecho.pki.server.enrollment.EnrollmentTransaction.State.PENDING, transaction.state());
            transactionId = transaction.id();
            originalRequesterKey = transaction.intent().requester().canonicalKeySha256().orElseThrow();
            assertEquals("processing", AcmeTestClient.text(client.postAsGet(orderUri), "status"));
            String changedCsr = Base64.getUrlEncoder().withoutPadding().encodeToString(csr(rsa((byte) 45)));
            assertEquals(403, client.kid(finalizeUri, "{\"csr\":\"" + changedCsr + "\"}").status());
            assertEquals(200, client.rollover(URI.create(AcmeTestClient.text(directory, "keyChange")), replacement).status());
            assertEquals(200, client.rollover(URI.create(AcmeTestClient.text(directory, "keyChange")), finalKey).status());
        }
        try (PkiHttpsServer server = start(fixture);
                AcmeTestClient client = new AcmeTestClient(wire, directoryUri, finalKey)) {
            AcmeTestClient.Response directory = client.directory();
            client.nonce(URI.create(AcmeTestClient.text(directory, "newNonce")));
            assertEquals(200, client.createAccount(URI.create(AcmeTestClient.text(directory, "newAccount")),
                    "{\"onlyReturnExisting\":true}").status());
            assertEquals(accountKid, client.accountKid());
            zeroecho.pki.server.enrollment.EnrollmentCoordinator coordinator = server.realm().enrollmentCoordinator().orElseThrow();
            zeroecho.pki.server.enrollment.EnrollmentTransaction pending = coordinator.find(transactionId).orElseThrow();
            assertEquals(originalRequesterKey, pending.intent().requester().canonicalKeySha256().orElseThrow());
            for (KeyPair owned : List.of(accountKey, replacement, finalKey)) {
                zeroecho.pkix.PublicKeyIdentity identity = zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(owned.getPublic().getEncoded());
                CertificateIdentityEvidence evidence = new CertificateIdentityEvidence(server.realm().configuration().realmId(),
                        "a".repeat(64), identity.canonicalSha256(), identity.equivalentSubjectPublicKeyInfoSha256(), "b".repeat(64));
                org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class, () -> coordinator.decide(pending.id(),
                        pending.commitment(), new AdministrativeDecisionActor("approver", Optional.of(evidence)),
                        ApprovalService.Choice.APPROVE, "Attempted same-account approval"));
            }
            assertEquals(3, server.realm().acmeControl().get(AcmeState.Account.class,
                    pending.intent().requester().actorId()).orElseThrow().keyHistory().size());
            coordinator.decide(pending.id(), pending.commitment(), new AdministrativeDecisionActor("approver",
                    Optional.of(CertificateIdentityEvidence.fromCertificate(server.realm().configuration().realmId(),
                            tls.clientCertificate()))), ApprovalService.Choice.APPROVE, "Reviewed exact identity");
            AcmeTestClient.Response completed = awaitValidOrder(client, orderUri, client.postAsGet(orderUri));
            AcmeTestClient.Response certificate = client.postAsGet(URI.create(AcmeTestClient.text(completed, "certificate")));
            assertEquals(200, certificate.status());
            X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new java.io.ByteArrayInputStream(certificate.body()));
            leaf.verify(rootKey.getPublic());
            org.junit.jupiter.api.Assertions.assertArrayEquals(leafKey.getPublic().getEncoded(), leaf.getPublicKey().getEncoded());
            assertEquals(zeroecho.pki.server.enrollment.EnrollmentTransaction.State.ISSUED,
                    coordinator.find(transactionId).orElseThrow().state());
            assertEquals(1, coordinator.list(0, 256).values().size());
        }
    }

    private static void requireHumanApproval(PkiHttpsServer server) {
        zeroecho.pki.server.enrollment.EnrollmentProfile current = server.realm().enrollmentProfiles().find("acme-enrollment").orElseThrow();
        server.realm().enrollmentProfiles().update(new zeroecho.pki.server.enrollment.EnrollmentProfile(
                current.id(), current.displayName(), current.state(), current.certificateProfileId(), current.allowedAuthorityIds(),
                current.subjectDnPattern(), current.requiredSanDomains(), true));
        server.realm().createPrincipal(ServerTestSupport.principal("approver"), "bootstrap");
    }

    private static AcmeTestClient.Response readyOrder(AcmeTestClient client, AcmeTestClient.Response directory,
            int challengePort) throws Exception {
        AcmeTestClient.Response order = client.kid(URI.create(AcmeTestClient.text(directory, "newOrder")),
                "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"localhost\"}]}");
        assertEquals(201, order.status());
        URI authorizationUri = URI.create(AcmeTestClient.textList(order, "authorizations").getFirst());
        URI challengeUri = AcmeTestClient.challenge(client.postAsGet(authorizationUri)).url();
        String token = AcmeTestClient.text(client.postAsGet(challengeUri), "token");
        try (Http01Responder responder = new Http01Responder(challengePort, token, client.keyAuthorization(token))) {
            responder.start();
            assertEquals("valid", AcmeTestClient.text(client.kid(challengeUri, "{}"), "status"));
            responder.await();
        }
        return order;
    }

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
                current.enrollmentProfileId(), current.issuerId(), current.issuancePathId(), current.issuancePathCommitment(),
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
        Path enrollment = root.resolve("enrollment.json");
        java.nio.file.Files.writeString(enrollment, EnrollmentTestSupport.runtimeJson(), StandardCharsets.UTF_8);
        ProcessBuilder builder = new ProcessBuilder(launcher.toString(), "--config", configuration.toString(),
                "--enrollment-config", enrollment.toString());
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
        Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> approvals = new java.util.HashMap<>(base.realm().approvalPolicies());
        approvals.put(OperationSecurityDescriptors.ApprovalCategory.ISSUANCE_SINGLE,
                new ApprovalService.Policy("enrollment", 1, Set.of("approver"), Set.of(), true, Duration.ofHours(1), true));
        ServerRealmConfiguration realm = new ServerRealmConfiguration(base.realm().realmId(),
                base.realm().displayName(), base.realm().confirmationProofPolicy(), session,
                base.realm().authorityExposure(),
                base.realm().authorizationCommitment(), base.realm().approvalCommitment(),
                ServerRealmConfiguration.extendedApprovalCommitment(approvals),
                base.realm().disclosureCommitment(), base.realm().disclosureDefaults(),
                base.realm().controlLogPath(), base.realm().controlStoreId(), approvals);
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
            context.enrollmentProfiles().register(new zeroecho.pki.server.enrollment.EnrollmentProfile(
                    "acme-enrollment", "ACME test policy", zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE,
                    "server-tls", Set.of(authority.value()), Optional.empty(), List.of(), false));
            AcmeService service = new AcmeService(context, CLOCK, HttpServerTestSupport.random(),
                    Map.of(Http01ChallengeProvider.ID, new Http01ChallengeProvider()),
                    Map.of(Http01ChallengeProvider.ID, fixture.http01()),
                    Map.of(TestAcmeEabProvider.ID, new TestAcmeEabProvider()),
                    Map.of(TestAcmeEabProvider.ID, new ProviderConfig(TestAcmeEabProvider.ID, Map.of())));
            AcmeState.Directory directory = service.registerDirectory(new AcmeService.DirectoryRegistration(
                    DIRECTORY_ALIAS, authority, "server-tls", "acme-enrollment", Set.of(IDENTIFIER), Duration.ofDays(30),
                    active.definition().leafPolicy().allowedSubjectKeyAlgorithmIds(), Set.of("STANDARD_ONLY"),
                    Set.of(AcmeState.ChallengeType.HTTP_01), Set.of(Http01ChallengeProvider.ID), Optional.empty(),
                    false));
            service.activateDirectory(directory.directoryId());
            if (includeEab) {
                AcmeState.Directory eab = service.registerDirectory(new AcmeService.DirectoryRegistration(
                        EAB_DIRECTORY_ALIAS, authority, "server-tls", "acme-enrollment", Set.of(IDENTIFIER), Duration.ofDays(30),
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
                HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader(), Optional.empty(),
                Optional.of(EnrollmentTestSupport.runtimeConfiguration()));
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
