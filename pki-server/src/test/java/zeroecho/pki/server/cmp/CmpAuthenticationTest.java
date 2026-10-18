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
package zeroecho.pki.server.cmp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.enrollment.EnrollmentRuntime;
import zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.cmp.CmpProtectedMessage;

class CmpAuthenticationTest {
    static final Instant NOW = Instant.parse("2026-10-11T12:00:00Z");
    static final RealmId REALM = new RealmId("cmp-test");
    static final X500Name CA_NAME = new X500Name("CN=CMP root");
    static final X500Name CLIENT_NAME = new X500Name("CN=CMP requester");
    static final X500Name SERVER_NAME = new X500Name("CN=CMP responder");
    static KeyPair caKey;
    static KeyPair clientKey;
    static KeyPair serverKey;
    static X509Certificate ca;
    static X509Certificate client;
    static X509Certificate server;

    @BeforeAll static void certificates() throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN"); random.setSeed(new byte[] { 3, 8, 14, 92, 6 });
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048, random);
        caKey = generator.generateKeyPair(); clientKey = generator.generateKeyPair(); serverKey = generator.generateKeyPair();
        ca = certificate(caKey, CA_NAME, true, KeyUsage.keyCertSign | KeyUsage.cRLSign, 1, NOW.plusSeconds(3600));
        client = certificate(clientKey, CLIENT_NAME, false, KeyUsage.digitalSignature, 2, NOW.plusSeconds(3600));
        server = certificate(serverKey, SERVER_NAME, false, KeyUsage.digitalSignature, 3, NOW.plusSeconds(3600));
    }

    @Test void signatureRequiresConfiguredTrustAndPreservesRealCertificateIdentity() throws Exception {
        EnrollmentRuntime.CredentialLease lease = signatureLease();
        CmpProtectedMessage request = signed(client, CLIENT_NAME, SERVER_NAME);
        try (CmpAuthentication authenticated = CmpAuthentication.verify(request, false, lease, REALM,
                server.getSubjectX500Principal(), NOW, CancellationSignal.NONE)) {
            assertEquals(IssuanceExecutionEvidence.ActorType.CMP_SIGNER, authenticated.requester().type());
            assertEquals(Optional.of(client), authenticated.certificate());
            assertEquals(List.of(client, ca), authenticated.trustedChain());
            assertTrue(authenticated.requester().aliases().principalIds().isEmpty());
            byte[] result = authenticated.protect(authenticated.verified().caCertificates(List.of(ca.getEncoded())),
                    lease, server.getSubjectX500Principal(), new byte[16], filled(16, 7), NOW, CancellationSignal.NONE);
            ProtectedPKIMessage response = new ProtectedPKIMessage(new GeneralPKIMessage(result));
            assertTrue(response.verify(new JcaContentVerifierProviderBuilder().build(server.getPublicKey())));
            assertArrayEquals(request.senderNonce(), response.toASN1Structure().getHeader().getRecipNonce().getOctets());
        }
        when(lease.requestTrustAnchors()).thenReturn(List.of());
        assertThrows(IllegalArgumentException.class, () -> CmpAuthentication.verify(request, false, lease, REALM,
                server.getSubjectX500Principal(), NOW, CancellationSignal.NONE));
    }

    @Test void signatureRejectsWrongUsageExpiryNamesKeyIdentifiersAndMode() throws Exception {
        EnrollmentRuntime.CredentialLease lease = signatureLease();
        for (X509Certificate invalid : List.of(
                certificate(clientKey, CLIENT_NAME, false, KeyUsage.keyEncipherment, 4, NOW.plusSeconds(3600)),
                certificate(clientKey, CLIENT_NAME, false, KeyUsage.digitalSignature, 5, NOW.minusSeconds(1)))) {
            assertThrows(IllegalArgumentException.class, () -> CmpAuthentication.verify(signed(invalid, CLIENT_NAME, SERVER_NAME),
                    false, lease, REALM, server.getSubjectX500Principal(), NOW, CancellationSignal.NONE));
        }
        assertThrows(IllegalArgumentException.class, () -> CmpAuthentication.verify(signed(client, CA_NAME, SERVER_NAME),
                false, lease, REALM, server.getSubjectX500Principal(), NOW, CancellationSignal.NONE));
        assertThrows(IllegalArgumentException.class, () -> CmpAuthentication.verify(signed(client, CLIENT_NAME, CA_NAME),
                false, lease, REALM, server.getSubjectX500Principal(), NOW, CancellationSignal.NONE));
        CmpProtectedMessage valid = signed(client, CLIENT_NAME, SERVER_NAME);
        assertThrows(IllegalArgumentException.class, () -> CmpAuthentication.verify(valid, true, lease, REALM,
                server.getSubjectX500Principal(), NOW, CancellationSignal.NONE));
        byte[] wrongKid = builder(CLIENT_NAME, SERVER_NAME).setSenderKID(CmpProtectedMessage.certificateKeyId(client))
                .setRecipKID(new byte[] { 4 }).addCMPCertificate(new X509CertificateHolder(client.getEncoded()))
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(clientKey.getPrivate())).toASN1Structure().getEncoded();
        assertThrows(IllegalArgumentException.class, () -> CmpAuthentication.verify(CmpProtectedMessage.parse(wrongKid),
                false, lease, REALM, server.getSubjectX500Principal(), NOW, CancellationSignal.NONE));
    }

    @Test void binaryPbmMapsExplicitIdentityAndErasesOwnedSecretOnCloseAndFailure() throws Exception {
        byte[] secret = filled(32, 0x80); secret[0] = 0;
        PBMParameter parameters = new PBMParameter(filled(16, 3), new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"), DERNull.INSTANCE),
                1000, new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.2.9"), DERNull.INSTANCE));
        CmpProtectedMessage request = CmpProtectedMessage.parse(builder(CLIENT_NAME, SERVER_NAME).setSenderKID(new byte[] { 1, 2 })
                .build(calculator(parameters, secret)).toASN1Structure().getEncoded());
        EnrollmentRuntime.CredentialLease lease = mock(EnrollmentRuntime.CredentialLease.class);
        EnrollmentRuntimeConfiguration.CredentialSet set = mock(EnrollmentRuntimeConfiguration.CredentialSet.class);
        EnrollmentRuntimeConfiguration.PbmIdentity identity = new EnrollmentRuntimeConfiguration.PbmIdentity("0102", "device",
                new EnrollmentRuntimeConfiguration.KeyReference("ring", "secret"), List.of("owner"));
        when(set.pbm()).thenReturn(Optional.of(new EnrollmentRuntimeConfiguration.Pbm(1000, 2000, 16, 32,
                Set.of(EnrollmentRuntimeConfiguration.PbmDigest.SHA256), Set.of(EnrollmentRuntimeConfiguration.PbmMac.HMAC_SHA256), List.of(identity))));
        when(lease.configuration()).thenReturn(set);
        SecretKey key = mock(SecretKey.class); byte[] borrowedCopy = secret.clone();
        when(key.getEncoded()).thenReturn(borrowedCopy); when(lease.pbmSecret("0102")).thenReturn(key);
        try (CmpAuthentication authenticated = CmpAuthentication.verify(request, true, lease, REALM,
                server.getSubjectX500Principal(), NOW, CancellationSignal.NONE)) {
            assertEquals(IssuanceExecutionEvidence.ActorType.CMP_PBM, authenticated.requester().type());
            assertEquals("device", authenticated.requester().actorId());
            assertEquals(Set.of("owner"), authenticated.requester().aliases().principalIds());
            assertFalse(authenticated.certificate().isPresent());
            byte[] bytes = authenticated.protect(authenticated.verified().caCertificates(List.of(ca.getEncoded())), lease,
                    server.getSubjectX500Principal(), filled(16, 4), filled(16, 8), NOW, CancellationSignal.NONE);
            org.bouncycastle.asn1.cmp.PKIMessage response = new GeneralPKIMessage(bytes).toASN1Structure();
            MacCalculator independent = calculator(PBMParameter.getInstance(response.getHeader().getProtectionAlg().getParameters()), secret);
            independent.getOutputStream().write(new DERSequence(new ASN1Encodable[] { response.getHeader(), response.getBody() }).getEncoded());
            assertArrayEquals(independent.getMac(), response.getProtection().getOctets());
        }
        assertArrayEquals(new byte[32], borrowedCopy);
        byte[] wrong = filled(32, 0x22); when(key.getEncoded()).thenReturn(wrong);
        assertThrows(IllegalArgumentException.class, () -> CmpAuthentication.verify(request, true, lease, REALM,
                server.getSubjectX500Principal(), NOW, CancellationSignal.NONE));
        assertArrayEquals(new byte[32], wrong);
        assertThrows(IllegalArgumentException.class, () -> CmpAuthentication.verify(request, false, signatureLease(), REALM,
                server.getSubjectX500Principal(), NOW, CancellationSignal.NONE));
    }

    static EnrollmentRuntime.CredentialLease signatureLease() {
        EnrollmentRuntime.CredentialLease lease = mock(EnrollmentRuntime.CredentialLease.class);
        when(lease.responseChain()).thenReturn(List.of(server, ca)); when(lease.requestTrustAnchors()).thenReturn(List.of(ca));
        when(lease.privateKey()).thenReturn(serverKey.getPrivate());
        return lease;
    }

    static CmpProtectedMessage signed(X509Certificate signer, X500Name sender, X500Name recipient) throws Exception {
        return CmpProtectedMessage.parse(builder(sender, recipient).setSenderKID(CmpProtectedMessage.certificateKeyId(signer))
                .addCMPCertificate(new X509CertificateHolder(signer.getEncoded()))
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(clientKey.getPrivate())).toASN1Structure().getEncoded());
    }

    static ProtectedPKIMessageBuilder builder(X500Name sender, X500Name recipient) {
        return new ProtectedPKIMessageBuilder(new GeneralName(sender), new GeneralName(recipient))
                .setTransactionID(filled(16, 1)).setSenderNonce(filled(16, 2)).setMessageTime(Date.from(NOW))
                .setBody(new PKIBody(21, new org.bouncycastle.asn1.cmp.GenMsgContent(new InfoTypeAndValue(
                        new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.17")))));
    }

    static X509Certificate certificate(KeyPair pair, X500Name subject, boolean isCa, int usage, int serial, Instant expires) throws Exception {
        return Pkix.parseCertificate(new JcaX509v3CertificateBuilder(CA_NAME, BigInteger.valueOf(serial), Date.from(NOW.minusSeconds(3600)),
                Date.from(expires), subject, pair.getPublic()).addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa))
                .addExtension(Extension.keyUsage, true, new KeyUsage(usage))
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(caKey.getPrivate())).getEncoded());
    }

    static byte[] filled(int size, int value) { byte[] bytes = new byte[size]; Arrays.fill(bytes, (byte) value); return bytes; }

    static MacCalculator calculator(PBMParameter parameters, byte[] secret) throws Exception {
        JcePKMACValuesCalculator calculator = new JcePKMACValuesCalculator();
        calculator.setup(parameters.getOwf(), parameters.getMac());
        byte[] salt = parameters.getSalt().getOctets();
        byte[] key = Arrays.copyOf(secret, secret.length + salt.length); System.arraycopy(salt, 0, key, secret.length, salt.length);
        for (int index = 0; index < parameters.getIterationCount().intValueExact(); index++) key = calculator.calculateDigest(key);
        byte[] derived = key;
        return new MacCalculator() {
            private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            @Override public AlgorithmIdentifier getAlgorithmIdentifier() { return new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac, parameters); }
            @Override public GenericKey getKey() { throw new UnsupportedOperationException(); }
            @Override public OutputStream getOutputStream() { return bytes; }
            @Override public byte[] getMac() {
                try { return calculator.calculateMac(derived, bytes.toByteArray()); }
                catch (Exception failure) { throw new IllegalStateException(failure); }
            }
        };
    }
}
