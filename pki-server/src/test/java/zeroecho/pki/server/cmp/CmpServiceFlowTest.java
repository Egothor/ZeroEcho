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
package zeroecho.pki.server.cmp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.enrollment.CmpTransaction;
import zeroecho.pki.server.enrollment.EnrollmentCoordinator;
import zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry;
import zeroecho.pki.server.enrollment.EnrollmentProfile;
import zeroecho.pki.server.enrollment.EnrollmentProfileState;
import zeroecho.pki.server.enrollment.EnrollmentRuntime;
import zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration;
import zeroecho.pki.server.enrollment.EnrollmentTransaction;
import zeroecho.pkix.cmp.CmpProtectedMessage;

/** Adapter behavior with independent protected wire messages and explicit custody boundaries. */
class CmpServiceFlowTest {
    @BeforeAll static void certificates() throws Exception { CmpAuthenticationTest.certificates(); }

    @Test void protectedDiscoveryPersistsBeforeDeliveryAndExactReplayBypassesFreshStatus() throws Exception {
        Fixture fixture = new Fixture();
        byte[] request = CmpAuthenticationTest.signed(CmpAuthenticationTest.client,
                CmpAuthenticationTest.CLIENT_NAME, CmpAuthenticationTest.SERVER_NAME).encoded();
        byte[] response = fixture.service.processMessage(fixture.endpoint, request);
        assertEquals(22, protectedResponse(response).getBody().getType());
        assertArrayEquals(response, fixture.response.get());
        assertTrue(fixture.retained.get().frozen().maximumResponseBytes() > 1_048_576);
        fixture.status.set(EffectiveCredentialStatus.PERMANENTLY_REVOKED);
        fixture.known(CmpAuthenticationTest.client);
        assertArrayEquals(response, fixture.service.processMessage(fixture.endpoint, request));
        verify(fixture.coordinator).reserveCmp(any());
        byte[] changed = signed(new PKIBody(21, new org.bouncycastle.asn1.cmp.GenMsgContent(
                new org.bouncycastle.asn1.cmp.InfoTypeAndValue(org.bouncycastle.asn1.cmp.CMPObjectIdentifiers.id_it_caCerts))), 9);
        assertEquals(23, protectedResponse(fixture.service.processMessage(fixture.endpoint, changed)).getBody().getType());
        assertArrayEquals(response, fixture.response.get());
    }

    @Test void heldRevokedSignerOrValidatedAnchorCannotObtainFreshTransaction() throws Exception {
        for (EffectiveCredentialStatus status : List.of(EffectiveCredentialStatus.HELD, EffectiveCredentialStatus.PERMANENTLY_REVOKED)) {
            for (java.security.cert.X509Certificate blocked : List.of(CmpAuthenticationTest.client, CmpAuthenticationTest.ca)) {
                Fixture fixture = new Fixture();
                fixture.known(blocked); fixture.status.set(status);
                byte[] request = CmpAuthenticationTest.signed(CmpAuthenticationTest.client,
                        CmpAuthenticationTest.CLIENT_NAME, CmpAuthenticationTest.SERVER_NAME).encoded();
                assertEquals(23, protectedResponse(fixture.service.processMessage(fixture.endpoint, request)).getBody().getType());
                verify(fixture.coordinator, never()).reserveCmp(any());
            }
        }
    }

    @Test void uncommittedResponseNeverEscapesAndFrozenCredentialRemainsSelected() throws Exception {
        Fixture fixture = new Fixture();
        byte[] request = CmpAuthenticationTest.signed(CmpAuthenticationTest.client,
                CmpAuthenticationTest.CLIENT_NAME, CmpAuthenticationTest.SERVER_NAME).encoded();
        org.mockito.Mockito.doThrow(new IllegalStateException("Unknown durable acknowledgement"))
                .when(fixture.coordinator).storeCmpResponse(any(), any(), any());
        assertEquals(503, assertThrows(CmpProtocolException.class, () -> fixture.service.processMessage(fixture.endpoint, request)).httpStatus());
        when(fixture.runtime.activeCredentialId(any(), anyString())).thenReturn("rotated");
        assertEquals(503, assertThrows(CmpProtocolException.class, () -> fixture.service.processMessage(fixture.endpoint, request)).httpStatus());
        verify(fixture.runtime, org.mockito.Mockito.times(2)).acquire("original");
        verify(fixture.runtime, never()).acquire("rotated");
    }

    @Test void unrelatedSignatureCannotRevokeAnotherCertificateBeforeReservation() throws Exception {
        Fixture fixture = new Fixture();
        Credential target = fixture.known(CmpAuthenticationTest.server);
        when(fixture.session.repository().credential(new PkiId("issuer"), CmpAuthenticationTest.server.getSerialNumber()))
                .thenReturn(Optional.of(target));
        PKIBody revoke = new PKIBody(11, new RevReqContent(new RevDetails(new CertTemplateBuilder()
                .setIssuer(CmpAuthenticationTest.CA_NAME).setSerialNumber(new org.bouncycastle.asn1.ASN1Integer(
                        CmpAuthenticationTest.server.getSerialNumber())).build())));
        byte[] response = fixture.service.processMessage(fixture.endpoint, signed(revoke, 2));
        assertEquals(23, protectedResponse(response).getBody().getType());
        verify(fixture.coordinator, never()).reserveCmp(any());
        verify(fixture.session, never()).operations();
    }

    @Test void waitingPollCertificateAndExplicitConfirmationKeepExactRequestAndNonceChain() throws Exception {
        Fixture fixture = new Fixture();
        byte[] crmf = new org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder(BigInteger.valueOf(7))
                .setSubject(CmpAuthenticationTest.CLIENT_NAME)
                .setPublicKey(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(CmpAuthenticationTest.clientKey.getPublic().getEncoded()))
                .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA256withRSA")
                        .build(CmpAuthenticationTest.clientKey.getPrivate())).build().getEncoded();
        PKIBody initialBody = new PKIBody(0, new org.bouncycastle.asn1.crmf.CertReqMessages(
                org.bouncycastle.asn1.crmf.CertReqMsg.getInstance(crmf)));
        EnrollmentTransaction enrollment = mock(EnrollmentTransaction.class);
        when(enrollment.id()).thenReturn("enrollment");
        AtomicReference<EnrollmentTransaction.State> state = new AtomicReference<>(EnrollmentTransaction.State.PENDING);
        when(enrollment.state()).thenAnswer(call -> state.get());
        Credential issued = fixture.known(CmpAuthenticationTest.client);
        PkiId issuedId = issued.credentialId();
        when(enrollment.credentialId()).thenReturn(Optional.of(issuedId));
        when(fixture.coordinator.admitCmp(any(), any())).thenAnswer(call -> {
            EnrollmentCoordinator.Admission admission = call.getArgument(0);
            assertArrayEquals(crmf, admission.payload().der());
            when(fixture.retained.get().enrollmentId()).thenReturn(Optional.of("enrollment"));
            return enrollment;
        });
        when(fixture.coordinator.find("enrollment")).thenReturn(Optional.of(enrollment));
        when(fixture.coordinator.dispatch(anyString(), any(), any())).thenAnswer(call -> {
            if (state.get() == EnrollmentTransaction.State.APPROVED) ((Runnable) call.getArgument(2)).run();
            return enrollment;
        });
        byte[] original = signed(initialBody, 2);
        byte[] waiting = fixture.service.processMessage(fixture.endpoint, original);
        org.bouncycastle.asn1.cmp.PKIMessage first = protectedResponse(waiting);
        assertEquals(3, org.bouncycastle.asn1.cmp.CertRepMessage.getInstance(first.getBody().getContent())
                .getResponse()[0].getStatus().getStatus().intValueExact());
        assertArrayEquals(waiting, fixture.service.processMessage(fixture.endpoint, original));
        byte[] firstNonce = first.getHeader().getSenderNonce().getOctets();
        byte[] badPoll = signed(new PKIBody(25, new org.bouncycastle.asn1.cmp.PollReqContent(BigInteger.valueOf(7))), 3, new byte[16]);
        assertEquals(23, protectedResponse(fixture.service.processMessage(fixture.endpoint, badPoll)).getBody().getType());
        assertArrayEquals(waiting, fixture.response.get());
        byte[] poll = signed(new PKIBody(25, new org.bouncycastle.asn1.cmp.PollReqContent(BigInteger.valueOf(7))), 3, firstNonce);
        state.set(EnrollmentTransaction.State.APPROVED); fixture.status.set(EffectiveCredentialStatus.HELD);
        assertEquals(23, protectedResponse(fixture.service.processMessage(fixture.endpoint, poll)).getBody().getType());
        assertArrayEquals(waiting, fixture.response.get());
        state.set(EnrollmentTransaction.State.ISSUED); fixture.status.set(EffectiveCredentialStatus.USABLE);
        byte[] delivered = fixture.service.processMessage(fixture.endpoint, poll);
        org.bouncycastle.asn1.cmp.PKIMessage reply = protectedResponse(delivered);
        org.bouncycastle.asn1.cmp.CertResponse cert = org.bouncycastle.asn1.cmp.CertRepMessage.getInstance(reply.getBody().getContent()).getResponse()[0];
        assertEquals(BigInteger.valueOf(7), cert.getCertReqId().getValue());
        assertArrayEquals(CmpAuthenticationTest.client.getEncoded(), cert.getCertifiedKeyPair().getCertOrEncCert().getCertificate().getEncoded());
        assertEquals(CmpTransaction.Confirmation.AWAITING, fixture.retained.get().response().orElseThrow().confirmation());
        byte[] certHash = MessageDigest.getInstance("SHA-256").digest(CmpAuthenticationTest.client.getEncoded());
        PKIBody confirmation = new PKIBody(24, org.bouncycastle.asn1.cmp.CertConfirmContent.getInstance(
                new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.cmp.CertStatus(certHash, BigInteger.valueOf(7)))));
        byte[] confirm = signed(confirmation, 4, reply.getHeader().getSenderNonce().getOctets());
        byte[] confirmed = fixture.service.processMessage(fixture.endpoint, confirm);
        assertEquals(19, protectedResponse(confirmed).getBody().getType());
        assertEquals(CmpTransaction.Confirmation.ACCEPTED, fixture.retained.get().response().orElseThrow().confirmation());
        assertArrayEquals(confirmed, fixture.service.processMessage(fixture.endpoint, confirm));
        verify(fixture.coordinator).admitCmp(any(), any());
    }

    @Test void binaryPbmCannotAuthorizeRevocationOrReplacementDespiteOwnerAliases() throws Exception {
        Fixture fixture = new Fixture();
        byte[] secret = CmpAuthenticationTest.filled(32, 0x80); secret[0] = 0;
        fixture.endpoint = new CmpEndpoint("managed", "authority", "profile", "policy", CmpProtectionPolicy.SHARED_SECRET_MAC);
        EnrollmentRuntime.CredentialLease lease = fixture.runtime.acquire("original");
        EnrollmentRuntimeConfiguration.PbmIdentity identity = new EnrollmentRuntimeConfiguration.PbmIdentity("0102", "owner",
                new EnrollmentRuntimeConfiguration.KeyReference("ring", "secret"), List.of("administrator"));
        when(lease.configuration().pbm()).thenReturn(Optional.of(new EnrollmentRuntimeConfiguration.Pbm(1000, 2000, 16, 32,
                Set.of(EnrollmentRuntimeConfiguration.PbmDigest.SHA256), Set.of(EnrollmentRuntimeConfiguration.PbmMac.HMAC_SHA256), List.of(identity))));
        javax.crypto.SecretKey key = mock(javax.crypto.SecretKey.class);
        when(key.getEncoded()).thenAnswer(call -> secret.clone()); when(lease.pbmSecret("0102")).thenReturn(key);
        org.bouncycastle.cert.crmf.CertificateRequestMessage replacement = new org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder(BigInteger.ONE)
                .setSubject(CmpAuthenticationTest.CLIENT_NAME)
                .setPublicKey(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(CmpAuthenticationTest.clientKey.getPublic().getEncoded()))
                .addControl(new org.bouncycastle.cert.crmf.Control() {
                    @Override public org.bouncycastle.asn1.ASN1ObjectIdentifier getType() { return org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers.id_regCtrl_oldCertID; }
                    @Override public org.bouncycastle.asn1.ASN1Encodable getValue() { return new org.bouncycastle.asn1.crmf.CertId(
                            new org.bouncycastle.asn1.x509.GeneralName(CmpAuthenticationTest.CA_NAME), BigInteger.TWO); }
                }).setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA256withRSA")
                        .build(CmpAuthenticationTest.clientKey.getPrivate())).build();
        PKIBody kur = new PKIBody(7, new org.bouncycastle.asn1.crmf.CertReqMessages(replacement.toASN1Structure()));
        PKIBody rr = new PKIBody(11, new RevReqContent(new RevDetails(new CertTemplateBuilder()
                .setIssuer(CmpAuthenticationTest.CA_NAME).setSerialNumber(new org.bouncycastle.asn1.ASN1Integer(BigInteger.TWO)).build())));
        org.bouncycastle.asn1.cmp.PBMParameter parameters = new org.bouncycastle.asn1.cmp.PBMParameter(new byte[16],
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256), 1000,
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_hmacWithSHA256));
        for (PKIBody body : List.of(kur, rr)) {
            byte[] request = CmpAuthenticationTest.builder(CmpAuthenticationTest.CLIENT_NAME, CmpAuthenticationTest.CA_NAME)
                    .setSenderKID(new byte[] {1, 2}).setBody(body).build(CmpAuthenticationTest.calculator(parameters, secret)).toASN1Structure().getEncoded();
            org.bouncycastle.asn1.cmp.PKIMessage response = org.bouncycastle.asn1.cmp.PKIMessage.getInstance(
                    fixture.service.processMessage(fixture.endpoint, request));
            assertEquals(23, response.getBody().getType());
            org.bouncycastle.operator.MacCalculator mac = CmpAuthenticationTest.calculator(
                    org.bouncycastle.asn1.cmp.PBMParameter.getInstance(response.getHeader().getProtectionAlg().getParameters()), secret);
            mac.getOutputStream().write(new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                    response.getHeader(), response.getBody() }).getEncoded());
            assertArrayEquals(mac.getMac(), response.getProtection().getOctets());
        }
        verify(fixture.coordinator, never()).reserveCmp(any());
        verify(fixture.session, never()).operations();
    }

    @Test void exactOwnerAndScopedRaRevocationsCarryHonestEvidenceAndRecoverLostResponse() throws Exception {
        for (boolean ra : List.of(false, true)) {
            Fixture fixture = new Fixture();
            java.security.cert.X509Certificate certificate = ra ? CmpAuthenticationTest.server : CmpAuthenticationTest.client;
            Credential target = fixture.known(certificate);
            PkiId targetId = target.credentialId();
            when(fixture.session.repository().credential(new PkiId("issuer"), certificate.getSerialNumber())).thenReturn(Optional.of(target));
            if (ra) {
                String key = zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(CmpAuthenticationTest.client.getPublicKey().getEncoded()).canonicalSha256();
                when(fixture.runtime.acquire("original").configuration().authorizedRaKeys()).thenReturn(List.of(key));
            }
            zeroecho.pki.application.PkiOperationExecutor executor = mock(zeroecho.pki.application.PkiOperationExecutor.class,
                    org.mockito.Mockito.withSettings().extraInterfaces(zeroecho.pki.application.RevocationEvidenceExecutor.class));
            when(fixture.session.operations()).thenReturn(executor);
            AtomicReference<zeroecho.pki.api.revocation.RevocationRecord> revocation = new AtomicReference<>();
            when(fixture.session.revocations().get(targetId)).thenAnswer(call -> Optional.ofNullable(revocation.get()));
            when(((zeroecho.pki.application.RevocationEvidenceExecutor) executor).executeRevocation(any(), any(), any())).thenAnswer(call -> {
                zeroecho.pki.application.RevocationExecutionEvidence evidence = call.getArgument(1);
                assertEquals(ra ? zeroecho.pki.application.RevocationExecutionEvidence.Authorization.CMP_AUTHORIZED_RA
                        : zeroecho.pki.application.RevocationExecutionEvidence.Authorization.CMP_CERTIFICATE_HOLDER, evidence.authorization());
                revocation.set(new zeroecho.pki.api.revocation.RevocationRecord(targetId, new zeroecho.pki.api.revocation.RevocationTransition(1,
                        zeroecho.pki.api.revocation.RevocationState.PERMANENTLY_REVOKED, CmpAuthenticationTest.NOW,
                        Optional.of(zeroecho.pki.api.revocation.RevocationReason.UNSPECIFIED), evidence.attributes())));
                fixture.status.set(EffectiveCredentialStatus.PERMANENTLY_REVOKED);
                org.mockito.Mockito.doThrow(new IllegalStateException("Endpoint suspended after committed revocation"))
                        .when(fixture.coordinator).requireCmpCurrentSource(any());
                return mock(zeroecho.pki.application.PkiOperationOutcome.Completed.class);
            });
            PKIBody body = new PKIBody(11, new RevReqContent(new RevDetails(new CertTemplateBuilder().setIssuer(CmpAuthenticationTest.CA_NAME)
                    .setSerialNumber(new org.bouncycastle.asn1.ASN1Integer(certificate.getSerialNumber())).build())));
            byte[] request = signed(body, 2);
            java.util.concurrent.atomic.AtomicBoolean lost = new java.util.concurrent.atomic.AtomicBoolean(true);
            org.mockito.Mockito.doAnswer(call -> {
                if (lost.getAndSet(false)) throw new IllegalStateException("Lost response acknowledgement");
                byte[] bytes = call.getArgument(1); CmpTransaction.Response metadata = call.getArgument(2);
                fixture.response.set(bytes.clone()); when(fixture.retained.get().response()).thenReturn(Optional.of(metadata)); return null;
            }).when(fixture.coordinator).storeCmpResponse(any(), any(), any());
            assertEquals(503, assertThrows(CmpProtocolException.class, () -> fixture.service.processMessage(fixture.endpoint, request)).httpStatus());
            byte[] response = fixture.service.processMessage(fixture.endpoint, request);
            assertEquals(12, protectedResponse(response).getBody().getType());
            assertArrayEquals(response, fixture.service.processMessage(fixture.endpoint, request));
            verify((zeroecho.pki.application.RevocationEvidenceExecutor) executor).executeRevocation(any(), any(), any());
            verify(fixture.coordinator).requireCmpCurrentSource(any());
        }
    }

    @Test void signatureOwnerReplacementRetainsActualNewKeyCrmfAndPredecessor() throws Exception {
        Fixture fixture = new Fixture();
        Credential predecessor = fixture.known(CmpAuthenticationTest.client);
        PkiId predecessorId = predecessor.credentialId();
        when(fixture.session.repository().credential(new PkiId("issuer"), CmpAuthenticationTest.client.getSerialNumber()))
                .thenReturn(Optional.of(predecessor));
        byte[] replacement = new org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder(BigInteger.valueOf(9))
                .setSubject(CmpAuthenticationTest.CLIENT_NAME)
                .setPublicKey(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(CmpAuthenticationTest.serverKey.getPublic().getEncoded()))
                .addControl(new org.bouncycastle.cert.crmf.Control() {
                    @Override public org.bouncycastle.asn1.ASN1ObjectIdentifier getType() { return org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers.id_regCtrl_oldCertID; }
                    @Override public org.bouncycastle.asn1.ASN1Encodable getValue() { return new org.bouncycastle.asn1.crmf.CertId(
                            new org.bouncycastle.asn1.x509.GeneralName(CmpAuthenticationTest.CA_NAME), CmpAuthenticationTest.client.getSerialNumber()); }
                }).setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA256withRSA")
                        .build(CmpAuthenticationTest.serverKey.getPrivate())).build().getEncoded();
        EnrollmentTransaction pending = mock(EnrollmentTransaction.class);
        when(pending.id()).thenReturn("replacement"); when(pending.state()).thenReturn(EnrollmentTransaction.State.PENDING);
        when(fixture.coordinator.admitCmp(any(), any())).thenAnswer(call -> {
            EnrollmentCoordinator.Admission admission = call.getArgument(0);
            assertEquals(EnrollmentTransaction.Operation.REPLACE, admission.operation());
            assertEquals(Optional.of(predecessorId), admission.predecessorId());
            assertArrayEquals(replacement, admission.payload().der());
            when(fixture.retained.get().enrollmentId()).thenReturn(Optional.of("replacement")); return pending;
        });
        when(fixture.coordinator.dispatch(anyString(), any(), any())).thenReturn(pending);
        byte[] response = fixture.service.processMessage(fixture.endpoint, signed(new PKIBody(7,
                new org.bouncycastle.asn1.crmf.CertReqMessages(org.bouncycastle.asn1.crmf.CertReqMsg.getInstance(replacement))), 2));
        assertEquals(8, protectedResponse(response).getBody().getType());
        assertEquals(BigInteger.valueOf(9), fixture.retained.get().frozen().requestId());
        verify(fixture.coordinator).admitCmp(any(), any());
    }

    private static org.bouncycastle.asn1.cmp.PKIMessage protectedResponse(byte[] der) throws Exception {
        ProtectedPKIMessage message = new ProtectedPKIMessage(new GeneralPKIMessage(der));
        assertTrue(message.verify(new JcaContentVerifierProviderBuilder().build(CmpAuthenticationTest.server.getPublicKey())));
        return message.toASN1Structure();
    }
    private static byte[] signed(PKIBody body, int nonce) throws Exception {
        return signed(body, nonce, null);
    }
    private static byte[] signed(PKIBody body, int nonce, byte[] recipientNonce) throws Exception {
        org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder builder = CmpAuthenticationTest.builder(CmpAuthenticationTest.CLIENT_NAME, CmpAuthenticationTest.SERVER_NAME)
                .setSenderNonce(CmpAuthenticationTest.filled(16, nonce)).setBody(body)
                .setSenderKID(CmpProtectedMessage.certificateKeyId(CmpAuthenticationTest.client))
                .addCMPCertificate(new X509CertificateHolder(CmpAuthenticationTest.client.getEncoded()));
        if (recipientNonce != null) builder.setRecipNonce(recipientNonce);
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(CmpAuthenticationTest.clientKey.getPrivate()))
                .toASN1Structure().getEncoded();
    }

    private static final class Fixture {
        final ServerRealmContext realm = mock(ServerRealmContext.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        final PkiSession session = realm.session();
        final EnrollmentCoordinator coordinator = mock(EnrollmentCoordinator.class);
        final EnrollmentRuntime runtime = mock(EnrollmentRuntime.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        CmpEndpoint endpoint = new CmpEndpoint("managed", "authority", "profile", "policy", CmpProtectionPolicy.SIGNATURE_BASED);
        final AtomicReference<CmpTransaction> retained = new AtomicReference<>();
        final AtomicReference<byte[]> response = new AtomicReference<>();
        final AtomicReference<EffectiveCredentialStatus> status = new AtomicReference<>(EffectiveCredentialStatus.USABLE);
        final CmpService service;
        Fixture() throws Exception {
            when(realm.configuration().realmId()).thenReturn(CmpAuthenticationTest.REALM);
            when(realm.enrollmentCoordinator()).thenReturn(Optional.of(coordinator));
            when(realm.enrollmentRuntime()).thenReturn(Optional.of(runtime));
            when(runtime.activeCredentialId(any(), anyString())).thenReturn("original");
            EnrollmentRuntime.CredentialLease lease = CmpAuthenticationTest.signatureLease();
            EnrollmentRuntimeConfiguration.CredentialSet configuration = mock(EnrollmentRuntimeConfiguration.CredentialSet.class);
            when(configuration.credentialId()).thenReturn("original");
            when(configuration.authorityId()).thenReturn("authority");
            when(configuration.issuerId()).thenReturn("issuer");
            when(configuration.chainPathId()).thenReturn("path");
            when(configuration.authorizedRaKeys()).thenReturn(List.of());
            when(lease.configuration()).thenReturn(configuration);
            when(runtime.acquire("original")).thenReturn(lease);
            when(runtime.admissionDeadline("original")).thenReturn(CmpAuthenticationTest.NOW.plusSeconds(3600));
            when(runtime.configuration().budgets()).thenReturn(new EnrollmentRuntimeConfiguration.Budgets(100, 50, 64_000_000,
                    1_048_576, 4, java.time.Duration.ofMinutes(10), java.time.Duration.ofSeconds(1)));
            zeroecho.pki.api.ca.IssuerChainPath path = mock(zeroecho.pki.api.ca.IssuerChainPath.class);
            when(path.authorityId()).thenReturn(new PkiId("authority")); when(path.issuerId()).thenReturn(new PkiId("issuer"));
            when(path.pathId()).thenReturn(new PkiId("path")); when(path.pathCommitment()).thenReturn("a".repeat(64));
            when(path.orderedCredentialIds()).thenReturn(List.of(new PkiId("ca-certificate")));
            when(session.repository().chainPath(new PkiId("path"))).thenReturn(Optional.of(path));
            content(new PkiId("ca-certificate"), CmpAuthenticationTest.ca.getEncoded());
            zeroecho.pki.api.ca.CaRecord authority = mock(zeroecho.pki.api.ca.CaRecord.class);
            when(authority.caId()).thenReturn(new PkiId("authority"));
            when(session.repository().authority(new PkiId("authority"))).thenReturn(Optional.of(authority));
            when(session.profiles().requireActiveProfile("profile").reference())
                    .thenReturn(new zeroecho.pki.api.profile.CertificateProfileRef("profile", 1, new byte[32]));
            when(realm.enrollmentProfiles().find("policy")).thenReturn(Optional.of(new EnrollmentProfile("policy", "CMP",
                    EnrollmentProfileState.ACTIVE, "profile", Set.of("authority"), Optional.empty(), List.of(), false)));
            when(realm.enrollmentEndpoints().requireCurrent(endpoint)).thenReturn(new EnrollmentEndpointRegistry.Snapshot(endpoint, 1, true, "b".repeat(64)));
            EffectiveCredentialStatusResolver.Evaluation evaluation = mock(EffectiveCredentialStatusResolver.Evaluation.class);
            when(session.credentialStatuses().beginEvaluation()).thenReturn(evaluation);
            when(evaluation.resolve(any())).thenAnswer(call -> status.get());
            when(coordinator.findCmp(anyString(), anyString())).thenAnswer(call -> Optional.ofNullable(retained.get()));
            when(coordinator.reserveCmp(any())).thenAnswer(call -> {
                CmpTransaction manifest = mock(CmpTransaction.class);
                when(manifest.id()).thenReturn("transaction"); when(manifest.frozen()).thenReturn(call.getArgument(0));
                when(manifest.response()).thenReturn(Optional.empty()); when(manifest.enrollmentId()).thenReturn(Optional.empty());
                retained.set(manifest); return manifest;
            });
            org.mockito.Mockito.doAnswer(call -> {
                CmpTransaction.Response metadata = call.getArgument(2);
                response.set(((byte[]) call.getArgument(1)).clone());
                when(retained.get().response()).thenReturn(Optional.of(metadata));
                return null;
            }).when(coordinator).storeCmpResponse(any(), any(), any());
            when(coordinator.cmpResponse(any())).thenAnswer(call -> response.get().clone());
            service = new CmpService(realm, Clock.fixed(CmpAuthenticationTest.NOW, ZoneOffset.UTC), new java.security.SecureRandom());
        }
        Credential known(java.security.cert.X509Certificate certificate) throws Exception {
            byte[] der = certificate.getEncoded();
            String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(der));
            PkiId id = new PkiId("x509:" + hash);
            Credential credential = mock(Credential.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
            when(credential.credentialId()).thenReturn(id); when(credential.content().sha256()).thenReturn(hash);
            when(credential.issuerRef().caId()).thenReturn(new PkiId("authority"));
            when(session.repository().credential(id)).thenReturn(Optional.of(credential));
            content(id, der); return credential;
        }
        private void content(PkiId id, byte[] der) throws Exception {
            PkiRepositoryContent content = mock(PkiRepositoryContent.class);
            when(content.openStream()).thenAnswer(call -> new ByteArrayInputStream(der));
            when(session.repository().openCredential(id)).thenReturn(content);
        }
    }
}
