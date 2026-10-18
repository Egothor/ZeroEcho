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

package zeroecho.pkix.cmp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pkix.Pkix;
import zeroecho.sdk.util.BouncyCastleActivator;

/** Independent BC wire encoders and verifiers exercise the public CMP facade. */
class CmpProtectedMessageTest {
    private static final Instant NOW = Instant.parse("2026-10-10T12:00:00Z");
    private static final X500Name CLIENT = new X500Name("CN=Client");
    private static final X500Name SERVER = new X500Name("CN=Server");
    private static final byte[] TX = new byte[16];
    private static final byte[] NONCE = filled(16, 1);
    private static final byte[] RESPONSE_NONCE = filled(16, 2);
    private static final byte[] SALT = filled(16, 3);
    private static final byte[] SECRET = new byte[32];
    private static final AlgorithmIdentifier SHA256 = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"));
    private static final AlgorithmIdentifier HMAC256 = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.2.9"));
    private static final CmpPbmPolicy POLICY = new CmpPbmPolicy(2, 20, 16, 64,
            Set.of("2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.3"),
            Set.of("1.2.840.113549.2.9", "1.2.840.113549.2.10", "1.2.840.113549.2.11"));
    private static KeyPair clientKey;
    private static KeyPair serverKey;
    private static X509Certificate client;
    private static X509Certificate server;
    private static PKIBody enrollment;

    @BeforeAll static void fixture() throws Exception {
        BouncyCastleActivator.init();
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        random.setSeed(new byte[] {12, 34, 56, 78, 90});
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
        generator.initialize(2048, random);
        clientKey = generator.generateKeyPair(); serverKey = generator.generateKeyPair();
        client = certificate(clientKey, CLIENT, 1);
        server = certificate(serverKey, SERVER, 2);
        SECRET[0] = 0; SECRET[1] = (byte) 255; SECRET[2] = (byte) 128;
        org.bouncycastle.cert.crmf.CertificateRequestMessage csr = new CertificateRequestMessageBuilder(BigInteger.valueOf(37))
                .setSubject(CLIENT).setPublicKey(SubjectPublicKeyInfo.getInstance(clientKey.getPublic().getEncoded()))
                .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA256withRSA").build(clientKey.getPrivate())).build();
        enrollment = new PKIBody(0, new CertReqMessages(csr.toASN1Structure()));
    }

    @Test void signatureProtectionPreservesExactRequestAndProtectsWaitingFinalAndDiscovery() throws Exception {
        byte[] wire = signed(enrollment, "SHA256withRSA");
        CmpProtectedMessage parsed = CmpProtectedMessage.parse(wire);
        assertEquals(BigInteger.valueOf(37), parsed.requestId());
        assertArrayEquals(wire, parsed.encoded());
        assertEquals(CLIENT.toString(), parsed.sender().getName());
        assertFalse(parsed.isPbm());
        byte[] nonce = parsed.senderNonce(); nonce[0] ^= 1;
        assertArrayEquals(NONCE, parsed.senderNonce());
        CmpProtectedMessage.Verified verified = parsed.verifySignature(client);
        assertThrows(IllegalArgumentException.class, () -> parsed.verifySignature(server));
        assertThrows(IllegalArgumentException.class, () -> parsed.verifyPbm(POLICY, SECRET, CancellationSignal.NONE));
        byte[] waiting = verified.sign(verified.waiting(), server, serverKey.getPrivate(), List.of(server.getEncoded()), RESPONSE_NONCE, NOW);
        PKIMessage response = verifiedResponse(waiting);
        assertEquals(1, response.getBody().getType());
        assertArrayEquals(TX, response.getHeader().getTransactionID().getOctets());
        assertArrayEquals(NONCE, response.getHeader().getRecipNonce().getOctets());
        assertArrayEquals(RESPONSE_NONCE, response.getHeader().getSenderNonce().getOctets());
        org.bouncycastle.asn1.cmp.CertResponse cert = org.bouncycastle.asn1.cmp.CertRepMessage.getInstance(response.getBody().getContent()).getResponse()[0];
        assertEquals(BigInteger.valueOf(37), cert.getCertReqId().getValue());
        assertEquals(BigInteger.valueOf(3), cert.getStatus().getStatus());
        assertEquals(null, cert.getCertifiedKeyPair());
        byte[] issued = verified.sign(verified.certificate(0, client.getEncoded(), false, NOW.plusSeconds(60)),
                server, serverKey.getPrivate(), List.of(server.getEncoded()), RESPONSE_NONCE, NOW);
        assertEquals(CMPObjectIdentifiers.it_confirmWaitTime, verifiedResponse(issued).getHeader().getGeneralInfo()[0].getInfoType());
        assertThrows(IllegalArgumentException.class, () -> verified.sign(verified.waiting(), server, clientKey.getPrivate(),
                List.of(server.getEncoded()), RESPONSE_NONCE, NOW));
        CmpProtectedMessage.Verified other = CmpProtectedMessage.parse(signed(new PKIBody(21, new DERSequence(
                new DERSequence(CMPObjectIdentifiers.id_it_caCerts))), "SHA256withRSA")).verifySignature(client);
        assertThrows(IllegalArgumentException.class, () -> verified.sign(other.rejected(), server, serverKey.getPrivate(),
                List.of(server.getEncoded()), RESPONSE_NONCE, NOW));
        PKIMessage discovery = verifiedResponse(other.sign(other.caCertificates(List.of(server.getEncoded())),
                server, serverKey.getPrivate(), List.of(server.getEncoded()), RESPONSE_NONCE, NOW));
        assertEquals(22, discovery.getBody().getType());
        org.bouncycastle.asn1.cmp.InfoTypeAndValue info = org.bouncycastle.asn1.cmp.GenRepContent.getInstance(discovery.getBody().getContent())
                .toInfoTypeAndValueArray()[0];
        assertEquals(CMPObjectIdentifiers.id_it_caCerts, info.getInfoType());
        assertArrayEquals(server.getEncoded(), org.bouncycastle.asn1.ASN1Sequence.getInstance(info.getInfoValue()).getObjectAt(0).toASN1Primitive().getEncoded());
    }

    @Test void binaryPbmUsesConfiguredAlgorithmsAndIndependentResponseVerification() throws Exception {
        for (String digest : POLICY.digestOids()) for (String mac : POLICY.macOids()) {
            PBMParameter parameters = new PBMParameter(SALT, new AlgorithmIdentifier(new ASN1ObjectIdentifier(digest)),
                    3, new AlgorithmIdentifier(new ASN1ObjectIdentifier(mac)));
            byte[] wire = builder(enrollment).build(calculator(parameters, SECRET)).toASN1Structure().getEncoded();
            CmpProtectedMessage parsed = CmpProtectedMessage.parse(wire);
            CmpProtectedMessage.Verified verified = parsed.verifyPbm(POLICY, SECRET, CancellationSignal.NONE);
            assertThrows(IllegalArgumentException.class, () -> parsed.verifySignature(client));
            byte[] wrong = SECRET.clone(); wrong[0] = 1;
            assertThrows(IllegalArgumentException.class, () -> parsed.verifyPbm(POLICY, wrong, CancellationSignal.NONE));
            byte[] response = verified.protectPbm(verified.waiting(), new X500Principal(SERVER.toString()), POLICY, SECRET,
                    filled(16, 4), RESPONSE_NONCE, NOW, CancellationSignal.NONE);
            PKIMessage message = PKIMessage.getInstance(response);
            assertEquals(CMPObjectIdentifiers.passwordBasedMac, message.getHeader().getProtectionAlg().getAlgorithm());
            PBMParameter reply = PBMParameter.getInstance(message.getHeader().getProtectionAlg().getParameters());
            MacCalculator independent = calculator(reply, SECRET);
            independent.getOutputStream().write(new DERSequence(new ASN1Encodable[] { message.getHeader(), message.getBody() }).getEncoded());
            assertArrayEquals(independent.getMac(), message.getProtection().getOctets());
            assertArrayEquals(NONCE, message.getHeader().getRecipNonce().getOctets());
            assertArrayEquals(SECRET, new byte[] {0, -1, -128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
            assertTrue(verified.toString().contains("redacted"));
        }
    }

    @Test void malformedWorkBoundsAreRejectedBeforeAnyDerivationAndCancellationIsObserved() throws Exception {
        AtomicInteger checks = new AtomicInteger();
        CancellationSignal observed = () -> { checks.incrementAndGet(); return false; };
        for (PBMParameter parameters : List.of(new PBMParameter(SALT, SHA256, 0, HMAC256),
                new PBMParameter(SALT, SHA256, 21, HMAC256), new PBMParameter(new byte[15], SHA256, 3, HMAC256),
                new PBMParameter(new byte[65], SHA256, 3, HMAC256),
                new PBMParameter(SALT, new AlgorithmIdentifier(SHA256.getAlgorithm(), new ASN1Integer(3)), 3, HMAC256),
                new PBMParameter(SALT, SHA256, 3, new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3"))))) {
            PKIHeader header = header(new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac, parameters));
            CmpProtectedMessage parsed = CmpProtectedMessage.parse(new PKIMessage(header, enrollment, new DERBitString(new byte[32])).getEncoded());
            assertThrows(IllegalArgumentException.class, () -> parsed.verifyPbm(POLICY, SECRET, observed));
        }
        assertEquals(0, checks.get());
        CmpProtectedMessage parsed = CmpProtectedMessage.parse(builder(enrollment).build(calculator(
                new PBMParameter(SALT, SHA256, 3, HMAC256), SECRET)).toASN1Structure().getEncoded());
        assertThrows(IllegalArgumentException.class, () -> parsed.verifyPbm(POLICY, SECRET,
                () -> true));
    }

    @Test void signatureAndMessageBoundaryTamperingFailsWithoutModeFallback() throws Exception {
        byte[] wire = signed(enrollment, "SHA256withRSA");
        PKIMessage valid = PKIMessage.getInstance(wire);
        byte[] signature = valid.getProtection().getOctets().clone(); signature[0] ^= 1;
        CmpProtectedMessage bad = CmpProtectedMessage.parse(new PKIMessage(valid.getHeader(), valid.getBody(), new DERBitString(signature)).getEncoded());
        assertThrows(IllegalArgumentException.class, () -> bad.verifySignature(client));
        assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.parse(new PKIMessage(valid.getHeader(), valid.getBody()).getEncoded()));
        assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.parse(Arrays.copyOf(wire, wire.length + 1)));
        assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.parse(new byte[CmpProtectedMessage.MAXIMUM_MESSAGE_BYTES + 1]));
        CmpProtectedMessage sha1 = CmpProtectedMessage.parse(signed(enrollment, "SHA1withRSA"));
        assertThrows(IllegalArgumentException.class, () -> sha1.verifySignature(client));
        assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.parse(signed(new PKIBody(21,
                new DERSequence(new DERSequence(CMPObjectIdentifiers.it_keyPairParamRep))), "SHA256withRSA")));
        PKIBody changed = new PKIBody(25, new DERSequence(new DERSequence(new ASN1Integer(37))));
        CmpProtectedMessage bodyTamper = CmpProtectedMessage.parse(new PKIMessage(valid.getHeader(), changed, valid.getProtection()).getEncoded());
        assertThrows(IllegalArgumentException.class, () -> bodyTamper.verifySignature(client));
        PKIHeaderBuilder changedHeader = new PKIHeaderBuilder(2, new GeneralName(CLIENT), new GeneralName(SERVER));
        changedHeader.setTransactionID(TX); changedHeader.setSenderNonce(RESPONSE_NONCE);
        changedHeader.setProtectionAlg(valid.getHeader().getProtectionAlg());
        CmpProtectedMessage headerTamper = CmpProtectedMessage.parse(new PKIMessage(changedHeader.build(), enrollment, valid.getProtection()).getEncoded());
        assertThrows(IllegalArgumentException.class, () -> headerTamper.verifySignature(client));
        // extraCerts are unprotected candidates, never implicitly selected as proof or trust.
        PKIMessage replacedCandidates = new PKIMessage(valid.getHeader(), valid.getBody(), valid.getProtection(),
                new org.bouncycastle.asn1.cmp.CMPCertificate[] {new org.bouncycastle.asn1.cmp.CMPCertificate(
                        org.bouncycastle.asn1.x509.Certificate.getInstance(server.getEncoded()))});
        CmpProtectedMessage candidates = CmpProtectedMessage.parse(replacedCandidates.getEncoded());
        candidates.verifySignature(client);
        assertThrows(IllegalArgumentException.class, () -> candidates.verifySignature(server));
        byte[] candidate = candidates.extraCertificates().getFirst(); candidate[0] ^= 1;
        assertArrayEquals(server.getEncoded(), candidates.extraCertificates().getFirst());
    }

    @Test void namedEcAndSupportedRsaDigestsInteroperateWhileParametersStayExact() throws Exception {
        for (String algorithm : List.of("SHA256withRSA", "SHA384withRSA", "SHA512withRSA")) {
            CmpProtectedMessage.parse(signed(enrollment, algorithm)).verifySignature(client);
        }
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        random.setSeed(new byte[] {91, 14, 63, 27});
        for (String curve : List.of("secp256r1", "secp384r1", "secp521r1")) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new java.security.spec.ECGenParameterSpec(curve), random);
            KeyPair pair = generator.generateKeyPair();
            X509Certificate ec = Pkix.parseCertificate(new JcaX509v3CertificateBuilder(CLIENT, BigInteger.ONE,
                    Date.from(NOW.minusSeconds(60)), Date.from(NOW.plusSeconds(3600)), CLIENT, pair.getPublic())
                    .build(new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate())).getEncoded());
            for (String digest : List.of("SHA256", "SHA384", "SHA512")) {
                PKIMessage message = builder(enrollment).setSenderKID(CmpProtectedMessage.certificateKeyId(ec))
                        .build(new JcaContentSignerBuilder(digest + "withECDSA").build(pair.getPrivate())).toASN1Structure();
                CmpProtectedMessage.Verified proof = CmpProtectedMessage.parse(message.getEncoded()).verifySignature(ec);
                byte[] response = proof.sign(proof.rejected(), ec, pair.getPrivate(), List.of(ec.getEncoded()), RESPONSE_NONCE, NOW);
                assertTrue(new ProtectedPKIMessage(new GeneralPKIMessage(response)).verify(new JcaContentVerifierProviderBuilder().build(pair.getPublic())));
                PKIHeader wrongParameters = header(new AlgorithmIdentifier(message.getHeader().getProtectionAlg().getAlgorithm(), DERNull.INSTANCE));
                CmpProtectedMessage wrong = CmpProtectedMessage.parse(new PKIMessage(wrongParameters, enrollment, message.getProtection()).getEncoded());
                assertThrows(IllegalArgumentException.class, () -> wrong.verifySignature(ec));
            }
        }
    }

    @Test void pbmOverflowFieldCardinalityLengthAndPadBitsRejectBeforeWork() throws Exception {
        AtomicInteger checks = new AtomicInteger();
        CancellationSignal observed = () -> { checks.incrementAndGet(); return false; };
        for (ASN1Encodable parameters : List.of(
                new DERSequence(new ASN1Encodable[] {new DEROctetString(SALT), SHA256, new ASN1Integer(BigInteger.ONE.shiftLeft(80)), HMAC256}),
                new DERSequence(new ASN1Encodable[] {new DEROctetString(SALT), SHA256, new ASN1Integer(-1), HMAC256}),
                new DERSequence(new ASN1Encodable[] {new DEROctetString(SALT), SHA256, new ASN1Integer(3), HMAC256, DERNull.INSTANCE}))) {
            CmpProtectedMessage parsed = CmpProtectedMessage.parse(new PKIMessage(header(new AlgorithmIdentifier(
                    CMPObjectIdentifiers.passwordBasedMac, parameters)), enrollment, new DERBitString(new byte[32])).getEncoded());
            assertThrows(IllegalArgumentException.class, () -> parsed.verifyPbm(POLICY, SECRET, observed));
        }
        PKIHeader header = header(new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac, new PBMParameter(SALT, SHA256, 3, HMAC256)));
        CmpProtectedMessage shortMac = CmpProtectedMessage.parse(new PKIMessage(header, enrollment, new DERBitString(new byte[31])).getEncoded());
        assertThrows(IllegalArgumentException.class, () -> shortMac.verifyPbm(POLICY, SECRET, observed));
        assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.parse(new PKIMessage(header, enrollment,
                new DERBitString(new byte[32], 1)).getEncoded()));
        assertEquals(0, checks.get());
    }

    @Test void pollConfirmationRevocationAndBodyCardinalityAreExplicit() throws Exception {
        PKIBody poll = new PKIBody(25, new DERSequence(new DERSequence(new ASN1Integer(37))));
        CmpProtectedMessage.Verified verified = CmpProtectedMessage.parse(signed(poll, "SHA256withRSA")).verifySignature(client);
        assertEquals(26, verifiedResponse(verified.sign(verified.poll(5), server, serverKey.getPrivate(),
                List.of(server.getEncoded()), RESPONSE_NONCE, NOW)).getBody().getType());
        assertEquals(8, verifiedResponse(verified.sign(verified.certificate(7, client.getEncoded(), false, NOW.plusSeconds(60)),
                server, serverKey.getPrivate(), List.of(server.getEncoded()), RESPONSE_NONCE, NOW)).getBody().getType());
        PKIBody confirmation = new PKIBody(24, new DERSequence(new DERSequence(new ASN1Encodable[] {
                new DEROctetString(new byte[32]), new ASN1Integer(37) })));
        CmpProtectedMessage confirmed = CmpProtectedMessage.parse(signed(confirmation, "SHA256withRSA"));
        assertEquals(BigInteger.valueOf(37), confirmed.requestId());
        assertTrue(confirmed.confirmationAccepted());
        CmpProtectedMessage.Verified confirmationProof = confirmed.verifySignature(client);
        assertEquals(19, verifiedResponse(confirmationProof.sign(confirmationProof.confirmed(), server, serverKey.getPrivate(),
                List.of(server.getEncoded()), RESPONSE_NONCE, NOW)).getBody().getType());
        org.bouncycastle.asn1.crmf.CertTemplate template = new org.bouncycastle.asn1.crmf.CertTemplateBuilder()
                .setIssuer(SERVER).setSerialNumber(new ASN1Integer(10)).build();
        PKIBody rr = new PKIBody(11, new DERSequence(new DERSequence(template)));
        CmpProtectedMessage revoked = CmpProtectedMessage.parse(signed(rr, "SHA256withRSA"));
        assertEquals(BigInteger.TEN, revoked.revokedCertificate().orElseThrow().serialNumber());
        CmpProtectedMessage.Verified revocationProof = revoked.verifySignature(client);
        assertEquals(12, verifiedResponse(revocationProof.sign(revocationProof.revoked(), server, serverKey.getPrivate(),
                List.of(server.getEncoded()), RESPONSE_NONCE, NOW)).getBody().getType());
        PKIBody duplicate = new PKIBody(25, new DERSequence(new ASN1Encodable[] {
                new DERSequence(new ASN1Integer(37)), new DERSequence(new ASN1Integer(38)) }));
        assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.parse(signed(duplicate, "SHA256withRSA")));
    }

    @Test void implicitConfirmationIsExplicitAndHeaderGrammarIsClosed() throws Exception {
        byte[] implicit = builder(enrollment).setSenderKID(CmpProtectedMessage.certificateKeyId(client)).addGeneralInfo(new org.bouncycastle.asn1.cmp.InfoTypeAndValue(
                CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE)).build(
                        new JcaContentSignerBuilder("SHA256withRSA").build(clientKey.getPrivate())).toASN1Structure().getEncoded();
        CmpProtectedMessage parsed = CmpProtectedMessage.parse(implicit);
        assertTrue(parsed.requestsImplicitConfirmation());
        CmpProtectedMessage.Verified verified = parsed.verifySignature(client);
        PKIMessage reply = verifiedResponse(verified.sign(verified.certificate(0, client.getEncoded(), true, null),
                server, serverKey.getPrivate(), List.of(server.getEncoded()), RESPONSE_NONCE, NOW));
        assertEquals(CMPObjectIdentifiers.it_implicitConfirm, reply.getHeader().getGeneralInfo()[0].getInfoType());
        assertEquals(CMPObjectIdentifiers.it_confirmWaitTime, verifiedResponse(verified.sign(
                verified.certificate(0, client.getEncoded(), false, NOW.plusSeconds(60)), server, serverKey.getPrivate(),
                List.of(server.getEncoded()), RESPONSE_NONCE, NOW)).getHeader().getGeneralInfo()[0].getInfoType());
        CmpProtectedMessage.Verified explicitOnly = CmpProtectedMessage.parse(signed(enrollment, "SHA256withRSA")).verifySignature(client);
        assertThrows(IllegalArgumentException.class, () -> explicitOnly.certificate(0, client.getEncoded(), true, null));
        for (org.bouncycastle.asn1.cmp.InfoTypeAndValue information : List.of(
                new org.bouncycastle.asn1.cmp.InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, new ASN1Integer(1)),
                new org.bouncycastle.asn1.cmp.InfoTypeAndValue(new ASN1ObjectIdentifier("1.2.3"), DERNull.INSTANCE))) {
            byte[] invalid = builder(enrollment).addGeneralInfo(information).build(
                    new JcaContentSignerBuilder("SHA256withRSA").build(clientKey.getPrivate())).toASN1Structure().getEncoded();
            assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.parse(invalid));
        }
        PKIMessage standard = PKIMessage.getInstance(signed(enrollment, "SHA256withRSA"));
        org.bouncycastle.asn1.ASN1Sequence header = org.bouncycastle.asn1.ASN1Sequence.getInstance(standard.getHeader());
        org.bouncycastle.asn1.ASN1EncodableVector fields = new org.bouncycastle.asn1.ASN1EncodableVector();
        for (ASN1Encodable field : header) fields.add(field);
        fields.add(new org.bouncycastle.asn1.DERTaggedObject(true, 8, new DERSequence(new DERSequence(new ASN1Encodable[] {
                CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE, DERNull.INSTANCE }))));
        DERSequence malformedHeader = new DERSequence(fields);
        java.security.Signature signer = java.security.Signature.getInstance("SHA256withRSA");
        signer.initSign(clientKey.getPrivate());
        signer.update(new DERSequence(new ASN1Encodable[] {malformedHeader, standard.getBody()}).getEncoded());
        byte[] malformed = new DERSequence(new ASN1Encodable[] {malformedHeader, standard.getBody(),
                new org.bouncycastle.asn1.DERTaggedObject(true, 0, new DERBitString(signer.sign()))}).getEncoded();
        assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.parse(malformed));
    }

    @Test void certificateKeyIdentifiersUseSkiOrExactFallbackAndRejectRoutingMismatch() throws Exception {
        assertArrayEquals(java.security.MessageDigest.getInstance("SHA-256").digest(serverKey.getPublic().getEncoded()),
                CmpProtectedMessage.certificateKeyId(server));
        byte[] clientId = filled(20, 19);
        byte[] serverId = filled(20, 23);
        X509Certificate identifiedClient = identifiedCertificate(clientKey, CLIENT, clientId);
        X509Certificate identifiedServer = identifiedCertificate(serverKey, SERVER, serverId);
        assertArrayEquals(clientId, CmpProtectedMessage.certificateKeyId(identifiedClient));
        assertArrayEquals(serverId, CmpProtectedMessage.certificateKeyId(identifiedServer));
        byte[] wire = builder(enrollment).setSenderKID(clientId).setRecipKID(serverId).build(
                new JcaContentSignerBuilder("SHA256withRSA").build(clientKey.getPrivate())).toASN1Structure().getEncoded();
        CmpProtectedMessage message = CmpProtectedMessage.parse(wire);
        byte[] recipient = message.recipientKid().orElseThrow(); recipient[0] ^= 1;
        assertArrayEquals(serverId, message.recipientKid().orElseThrow());
        CmpProtectedMessage.Verified verified = message.verifySignature(identifiedClient);
        byte[] reply = verified.sign(verified.waiting(), identifiedServer, serverKey.getPrivate(),
                List.of(identifiedServer.getEncoded()), RESPONSE_NONCE, NOW);
        PKIMessage response = PKIMessage.getInstance(reply);
        assertTrue(new ProtectedPKIMessage(new GeneralPKIMessage(reply)).verify(new JcaContentVerifierProviderBuilder().build(serverKey.getPublic())));
        assertArrayEquals(serverId, response.getHeader().getSenderKID().getOctets());
        assertArrayEquals(clientId, response.getHeader().getRecipKID().getOctets());
        // Same mathematical key does not erase an explicitly mismatched certificate routing ID.
        assertThrows(IllegalArgumentException.class, () -> verified.sign(verified.waiting(), server, serverKey.getPrivate(),
                List.of(server.getEncoded()), RESPONSE_NONCE, NOW));
        assertThrows(IllegalArgumentException.class, () -> message.verifySignature(client));
        X509Certificate malformed = identifiedCertificate(serverKey, SERVER, new byte[0]);
        assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.certificateKeyId(malformed));
    }

    private static X509Certificate identifiedCertificate(KeyPair key, X500Name name, byte[] identifier) throws Exception {
        return Pkix.parseCertificate(new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                Date.from(NOW.minusSeconds(60)), Date.from(NOW.plusSeconds(3600)), name, key.getPublic())
                .addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false,
                        new org.bouncycastle.asn1.x509.SubjectKeyIdentifier(identifier))
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded());
    }

    private static byte[] signed(PKIBody body, String algorithm) throws Exception {
        return builder(body).setSenderKID(CmpProtectedMessage.certificateKeyId(client)).addCMPCertificate(new X509CertificateHolder(client.getEncoded()))
                .build(new JcaContentSignerBuilder(algorithm).build(clientKey.getPrivate())).toASN1Structure().getEncoded();
    }
    private static ProtectedPKIMessageBuilder builder(PKIBody body) {
        return new ProtectedPKIMessageBuilder(new GeneralName(CLIENT), new GeneralName(SERVER))
                .setTransactionID(TX).setSenderNonce(NONCE).setSenderKID(new byte[] {7}).setMessageTime(Date.from(NOW)).setBody(body);
    }
    private static PKIHeader header(AlgorithmIdentifier algorithm) {
        PKIHeaderBuilder builder = new PKIHeaderBuilder(2, new GeneralName(CLIENT), new GeneralName(SERVER));
        builder.setTransactionID(TX); builder.setSenderNonce(NONCE); builder.setSenderKID(new byte[] {7}); builder.setProtectionAlg(algorithm);
        return builder.build();
    }
    private static PKIMessage verifiedResponse(byte[] response) throws Exception {
        ProtectedPKIMessage protectedMessage = new ProtectedPKIMessage(new GeneralPKIMessage(response));
        assertTrue(protectedMessage.verify(new JcaContentVerifierProviderBuilder().build(server.getPublicKey())));
        return protectedMessage.toASN1Structure();
    }
    @Test void confirmationHashFollowsIssuedCertificateSignatureDigest() throws Exception {
        for (String signature : List.of("SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "SHA256withRSAandMGF1")) {
            byte[] certificate = new JcaX509v3CertificateBuilder(CLIENT, BigInteger.TEN, Date.from(NOW.minusSeconds(60)),
                    Date.from(NOW.plusSeconds(3600)), CLIENT, clientKey.getPublic())
                    .build(new JcaContentSignerBuilder(signature).build(clientKey.getPrivate())).getEncoded();
            String digest = signature.contains("384") ? "SHA-384" : signature.contains("512") ? "SHA-512" : "SHA-256";
            assertArrayEquals(java.security.MessageDigest.getInstance(digest).digest(certificate),
                    CmpProtectedMessage.certificateConfirmationHash(certificate));
            assertArrayEquals(CmpProtectedMessage.certificateConfirmationHash(certificate),
                    CmpProtectedMessage.certificateConfirmationHash(certificate, Optional.of(digest)));
            assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.certificateConfirmationHash(certificate,
                    Optional.of(digest.equals("SHA-256") ? "SHA-384" : "SHA-256")));
        }
        assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.certificateConfirmationHash(new byte[] { 0x30, 0 }));
    }

    @Test void versionThreeExplicitConfirmationHashSupportsExistingEddsaAndMlDsaCertificates() throws Exception {
        java.security.Provider provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256);
        for (String algorithm : List.of("Ed25519", "Ed448", "ML-DSA-44")) {
            KeyPair key = KeyPairGenerator.getInstance(algorithm, provider).generateKeyPair();
            byte[] certificate = new JcaX509v3CertificateBuilder(CLIENT, BigInteger.TEN, Date.from(NOW.minusSeconds(60)),
                    Date.from(NOW.plusSeconds(3600)), CLIENT, key.getPublic())
                    .build(new JcaContentSignerBuilder(algorithm).setProvider(provider).build(key.getPrivate())).getEncoded();
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(certificate);
            CmpProtectedMessage request = CmpProtectedMessage.parse(confirmation(hash, 3,
                    new org.bouncycastle.asn1.DERTaggedObject(true, 0, sha256)));
            request.verifySignature(client);
            assertEquals(Optional.of("SHA-256"), request.confirmationHashAlgorithm());
            assertArrayEquals(request.confirmationHash().orElseThrow(),
                    CmpProtectedMessage.certificateConfirmationHash(certificate, request.confirmationHashAlgorithm()));
            assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.certificateConfirmationHash(certificate));
            assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.parse(confirmation(hash, 2,
                    new org.bouncycastle.asn1.DERTaggedObject(true, 0, sha256))));
        }
    }

    @Test void signedConfirmationHashAlgorithmRejectsMalformedAndUnsupportedFields() throws Exception {
        ASN1Encodable valid = new org.bouncycastle.asn1.DERTaggedObject(true, 0,
                new AlgorithmIdentifier(org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256));
        for (ASN1Encodable invalid : List.of(
                new org.bouncycastle.asn1.DERTaggedObject(true, 1, new AlgorithmIdentifier(org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256)),
                new org.bouncycastle.asn1.DERTaggedObject(true, 0, new AlgorithmIdentifier(org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha384)),
                new org.bouncycastle.asn1.DERTaggedObject(true, 0, new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4"))),
                new org.bouncycastle.asn1.DERTaggedObject(true, 0, new AlgorithmIdentifier(org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256, new ASN1Integer(1))),
                new org.bouncycastle.asn1.DERTaggedObject(true, 0, new DERSequence(new ASN1Encodable[] {
                        org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE, DERNull.INSTANCE })))) {
            assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.parse(confirmation(new byte[32], 3, invalid)));
        }
        assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.parse(confirmation(new byte[32], 3, valid, valid)));
        assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.parse(confirmation(new byte[32], 3,
                valid, new DERSequence(new ASN1Integer(0)))));
    }

    @Test void projectSphincsConfirmationUsesOnlyTheCertificateRoleOid() throws Exception {
        KeyPair key = new zeroecho.core.alg.sphincsplus.SphincsPlusKeyGenBuilder().generateKeyPair(
                zeroecho.core.alg.sphincsplus.SphincsPlusKeyGenSpec.defaultSpec());
        for (String oid : List.of(zeroecho.core.alg.EgothorAlgorithmOids.OID_SPHINCS_PLUS_CERTIFICATE_SIGNATURE,
                zeroecho.core.alg.EgothorAlgorithmOids.OID_SPHINCS_PLUS_CSR_SIGNATURE,
                zeroecho.core.alg.EgothorAlgorithmOids.OID_SPHINCS_PLUS_CRL_SIGNATURE,
                zeroecho.core.alg.EgothorAlgorithmOids.OID_SPHINCS_PLUS_OCSP_REQUEST_SIGNATURE)) {
            java.security.Signature signature = java.security.Signature.getInstance("SLH-DSA", "BC");
            signature.initSign(key.getPrivate());
            ByteArrayOutputStream content = new ByteArrayOutputStream();
            org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.ContentSigner() {
                @Override public AlgorithmIdentifier getAlgorithmIdentifier() { return new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid)); }
                @Override public OutputStream getOutputStream() { return content; }
                @Override public byte[] getSignature() {
                    try { signature.update(content.toByteArray()); return signature.sign(); }
                    catch (java.security.SignatureException failure) { throw new IllegalStateException(failure); }
                }
            };
            byte[] certificate = new JcaX509v3CertificateBuilder(CLIENT, BigInteger.TEN, Date.from(NOW.minusSeconds(60)),
                    Date.from(NOW.plusSeconds(3600)), CLIENT, clientKey.getPublic()).build(signer).getEncoded();
            signature.initVerify(key.getPublic()); signature.update(new X509CertificateHolder(certificate).toASN1Structure().getTBSCertificate().getEncoded());
            assertTrue(signature.verify(new X509CertificateHolder(certificate).getSignature()));
            if (oid.equals(zeroecho.core.alg.EgothorAlgorithmOids.OID_SPHINCS_PLUS_CERTIFICATE_SIGNATURE)) {
                assertArrayEquals(java.security.MessageDigest.getInstance("SHA-256").digest(certificate),
                        CmpProtectedMessage.certificateConfirmationHash(certificate, Optional.of("SHA-256")));
                assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.certificateConfirmationHash(certificate));
            } else assertThrows(IllegalArgumentException.class, () -> CmpProtectedMessage.certificateConfirmationHash(certificate, Optional.of("SHA-256")));
        }
    }

    private static byte[] confirmation(byte[] hash, int version, ASN1Encodable... optional) throws Exception {
        java.util.List<ASN1Encodable> fields = new java.util.ArrayList<>();
        fields.add(new DEROctetString(hash)); fields.add(new ASN1Integer(7)); fields.addAll(List.of(optional));
        ASN1Encodable body = new org.bouncycastle.asn1.DERTaggedObject(true, 24,
                new DERSequence(new DERSequence(fields.toArray(ASN1Encodable[]::new))));
        PKIHeader header = new PKIHeaderBuilder(version, new GeneralName(CLIENT), new GeneralName(SERVER))
                .setTransactionID(TX).setSenderNonce(NONCE).setSenderKID(CmpProtectedMessage.certificateKeyId(client))
                .setProtectionAlg(new AlgorithmIdentifier(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE)).build();
        java.security.Signature signer = java.security.Signature.getInstance("SHA256withRSA"); signer.initSign(clientKey.getPrivate());
        signer.update(new DERSequence(new ASN1Encodable[] {header, body}).getEncoded());
        return new DERSequence(new ASN1Encodable[] {header, body,
                new org.bouncycastle.asn1.DERTaggedObject(true, 0, new DERBitString(signer.sign()))}).getEncoded();
    }

    private static X509Certificate certificate(KeyPair key, X500Name name, int serial) throws Exception {
        return Pkix.parseCertificate(new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(serial),
                Date.from(NOW.minusSeconds(60)), Date.from(NOW.plusSeconds(3600)), name, key.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded());
    }
    private static byte[] filled(int size, int value) { byte[] bytes = new byte[size]; Arrays.fill(bytes, (byte) value); return bytes; }
    private static MacCalculator calculator(PBMParameter parameters, byte[] secret) throws Exception {
        JcePKMACValuesCalculator calculator = new JcePKMACValuesCalculator();
        calculator.setup(parameters.getOwf(), parameters.getMac());
        byte[] salt = parameters.getSalt().getOctets();
        byte[] key = Arrays.copyOf(secret, secret.length + salt.length);
        System.arraycopy(salt, 0, key, secret.length, salt.length);
        for (int i = 0; i < parameters.getIterationCount().intValueExact(); i++) key = calculator.calculateDigest(key);
        byte[] derived = key;
        return new MacCalculator() {
            private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            @Override public AlgorithmIdentifier getAlgorithmIdentifier() { return new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac, parameters); }
            @Override public GenericKey getKey() { throw new UnsupportedOperationException("Secret is not exposed"); }
            @Override public OutputStream getOutputStream() { return bytes; }
            @Override public byte[] getMac() {
                try { return calculator.calculateMac(derived, bytes.toByteArray()); }
                catch (org.bouncycastle.cert.crmf.CRMFException failure) { throw new AssertionError(failure); }
            }
        };
    }
}
