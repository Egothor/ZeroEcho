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

package zeroecho.pkix;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.pkix.crl.CrlReason;
import zeroecho.pkix.ocsp.CertId;
import zeroecho.pkix.ocsp.CertStatus;
import zeroecho.pkix.ocsp.OcspResponse;
import zeroecho.pkix.ocsp.OcspResponseBuilder;
import zeroecho.pkix.ocsp.ResponderId;
import zeroecho.pkix.sign.ContentSigner;

final class OcspUnsignedEncodingTest {
    private static final Instant NOW = Instant.parse("2026-09-22T12:00:00Z");
    private static final AlgorithmIdentifier ED25519 = AlgorithmIdentifier.absent("1.3.101.112");
    private static final byte[] NONCE = {1, 3, 5, 7};

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void unsignedRoundTripMatchesLegacyBuilderAndPreservesOrderedChain(boolean byKey) throws Exception {
        Fixture fixture = new Fixture();
        ResponderId responder = byKey ? ResponderId.byKey(new byte[20]) : ResponderId.byName(fixture.name);
        byte[] tbs = fixture.builder(responder).buildTbs();
        byte[] signature = fixture.sign(tbs);
        byte[] response = Pkix.assembleOcspResponse(tbs, Pkix.encodeAlgorithmIdentifier(ED25519), signature, fixture.chain());
        BasicOCSPResponse basic = basic(response);
        assertArrayEquals(tbs, basic.getTbsResponseData().getEncoded(ASN1Encoding.DER));
        assertArrayEquals(response, ASN1Primitive.fromByteArray(response).getEncoded(ASN1Encoding.DER));
        assertArrayEquals(fixture.legacy(responder), response, "Unsigned assembly preserves the original BC builder's exact DER");
        assertArrayEquals(response, fixture.builder(responder).build(Pkix.signer(fixture.key.getPrivate(), ED25519), fixture.chain()));
        OcspResponse parsed = Pkix.parseOcspResponse(response);
        assertTrue(parsed.verifySignature(fixture.key.getPublic()));
        assertEquals(responder, parsed.responderId());
        assertEquals(NOW, parsed.producedAt());
        assertArrayEquals(NONCE, parsed.nonce().orElseThrow());
        assertEquals(4, parsed.responses().size());
        assertEquals(List.of(BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(3), BigInteger.valueOf(4)),
                parsed.responses().stream().map(value -> value.certId().serialNumber()).toList());
        assertEquals(CertStatus.good(), parsed.responses().get(0).status());
        assertEquals(CertStatus.unknown(), parsed.responses().get(1).status());
        assertEquals(CertStatus.revoked(NOW.minusSeconds(200), CrlReason.KEY_COMPROMISE), parsed.responses().get(2).status());
        assertEquals(CertStatus.revoked(NOW.minusSeconds(300), CrlReason.UNSPECIFIED), parsed.responses().get(3).status());
        assertEquals(NOW.minusSeconds(10), parsed.responses().get(0).thisUpdate());
        assertEquals(Optional.of(NOW.plusSeconds(600)), parsed.responses().get(0).nextUpdate());
        assertTrue(parsed.responses().get(1).nextUpdate().isEmpty());
        assertEquals(2, parsed.certificates().size());
        for (int index = 0; index < fixture.chain().size(); index++) {
            assertArrayEquals(fixture.chain().get(index).getEncoded(), parsed.certificates().get(index).getEncoded());
        }
        // Certificates are not part of ResponseData: embedding order must not change the signed bytes.
        byte[] reversed = Pkix.assembleOcspResponse(tbs, Pkix.encodeAlgorithmIdentifier(ED25519), signature,
                List.of(fixture.root, fixture.certificate));
        assertArrayEquals(tbs, basic(reversed).getTbsResponseData().getEncoded(ASN1Encoding.DER));
        assertArrayEquals(fixture.root.getEncoded(), Pkix.parseOcspResponse(reversed).certificates().getFirst().getEncoded());
    }

    @Test void emptyChainAndNonceRetainExistingOmissionSemanticsWithoutAnAggregateCap() throws Exception {
        Fixture fixture = new Fixture();
        byte[] emptyNonce = {};
        byte[] tbs = fixture.builder(ResponderId.byName(fixture.name)).nonce(emptyNonce).buildTbs();
        byte[] algorithm = Pkix.encodeAlgorithmIdentifier(ED25519);
        byte[] signature = fixture.sign(tbs);
        byte[] old = Pkix.assembleOcspResponse(tbs, algorithm, signature);
        assertArrayEquals(old, Pkix.assembleOcspResponse(tbs, algorithm, signature, List.of()));
        assertNull(basic(old).getCerts(), "Empty chain omits certs rather than adding an empty tagged sequence");
        assertTrue(Pkix.parseOcspResponse(old).nonce().isPresent());
        assertEquals(0, Pkix.parseOcspResponse(old).nonce().orElseThrow().length);
        byte[] absent = fixture.builder(ResponderId.byName(fixture.name)).nonce(null).buildTbs();
        assertTrue(Pkix.parseOcspResponse(Pkix.assembleOcspResponse(absent, algorithm, fixture.sign(absent))).nonce().isEmpty());
        byte[] nonce = new byte[1_048_577];
        byte[] large = fixture.builder(ResponderId.byName(fixture.name)).nonce(nonce).buildTbs();
        nonce[0] = 42;
        assertTrue(large.length > 1_048_576);
        byte[] encoded = Pkix.assembleOcspResponse(large, algorithm, fixture.sign(large), List.of());
        assertArrayEquals(new byte[1_048_577], Pkix.parseOcspResponse(encoded).nonce().orElseThrow());
    }

    @Test void signedBuildConsumesExactlyTheUnsignedBytesAndOneSignature() throws Exception {
        Fixture fixture = new Fixture();
        byte[] expected = fixture.builder(ResponderId.byName(fixture.name)).buildTbs();
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        AtomicInteger streams = new AtomicInteger();
        AtomicInteger signatures = new AtomicInteger();
        ContentSigner signer = new ContentSigner() {
            @Override public AlgorithmIdentifier algorithm() { return ED25519; }
            @Override public OutputStream contentStream() { streams.incrementAndGet(); return content; }
            @Override public byte[] signature() {
                signatures.incrementAndGet();
                assertArrayEquals(expected, content.toByteArray());
                try { return fixture.sign(content.toByteArray()); }
                catch (Exception failure) { throw new AssertionError(failure); }
            }
        };
        byte[] response = fixture.builder(ResponderId.byName(fixture.name)).build(signer, List.of());
        assertEquals(1, streams.get());
        assertEquals(1, signatures.get());
        assertTrue(Pkix.parseOcspResponse(response).verifySignature(fixture.key.getPublic()));
    }

    @Test void rejectsMalformedEncodingAndNullInputsWithoutClaimingSignatureVerification() throws Exception {
        Fixture fixture = new Fixture();
        byte[] tbs = fixture.builder(ResponderId.byName(fixture.name)).buildTbs();
        byte[] algorithm = Pkix.encodeAlgorithmIdentifier(ED25519);
        byte[] signature = fixture.sign(tbs);
        byte[] malformed = {(byte) 0xff};
        assertThrows(IllegalArgumentException.class, () -> Pkix.assembleOcspResponse(malformed, algorithm, signature, List.of()));
        assertThrows(IllegalArgumentException.class, () -> Pkix.assembleOcspResponse(tbs, malformed, signature, List.of()));
        assertThrows(IllegalArgumentException.class, () -> Pkix.assembleOcspResponse(Arrays.copyOf(tbs, tbs.length + 1), algorithm, signature, List.of()));
        assertThrows(NullPointerException.class, () -> Pkix.assembleOcspResponse(null, algorithm, signature, List.of()));
        assertThrows(NullPointerException.class, () -> Pkix.assembleOcspResponse(tbs, null, signature, List.of()));
        assertThrows(NullPointerException.class, () -> Pkix.assembleOcspResponse(tbs, algorithm, null, List.of()));
        assertThrows(NullPointerException.class, () -> Pkix.assembleOcspResponse(tbs, algorithm, signature, null));
        assertThrows(NullPointerException.class, () -> Pkix.assembleOcspResponse(tbs, algorithm, signature, Arrays.asList((X509Certificate) null)));
        assertThrows(NullPointerException.class, () -> Pkix.ocspResponseBuilder().producedAt(NOW).buildTbs());
        assertThrows(NullPointerException.class, () -> Pkix.ocspResponseBuilder().responderId(ResponderId.byName(fixture.name)).buildTbs());
        X509Certificate broken = mock(X509Certificate.class);
        when(broken.getEncoded()).thenThrow(new CertificateEncodingException("test encoding failure"));
        assertThrows(IllegalArgumentException.class, () -> Pkix.assembleOcspResponse(tbs, algorithm, signature, List.of(broken)));
        assertThrows(IllegalStateException.class, () -> fixture.builder(ResponderId.byName(fixture.name))
                .build(Pkix.signer(fixture.key.getPrivate(), ED25519), List.of(broken)));
        byte[] badSignature = signature.clone();
        badSignature[0] ^= 1;
        assertFalse(Pkix.parseOcspResponse(Pkix.assembleOcspResponse(tbs, algorithm, badSignature, fixture.chain()))
                .verifySignature(fixture.key.getPublic()));
    }

    @Test void signerIoFailureIsReportedWithoutRequestingSignature() throws Exception {
        Fixture fixture = new Fixture();
        AtomicInteger signatures = new AtomicInteger();
        ContentSigner signer = new ContentSigner() {
            @Override public AlgorithmIdentifier algorithm() { return ED25519; }
            @Override public OutputStream contentStream() {
                return new OutputStream() {
                    @Override public void write(int value) throws IOException { throw new IOException("test write failure"); }
                };
            }
            @Override public byte[] signature() { signatures.incrementAndGet(); return new byte[64]; }
        };
        assertThrows(IllegalStateException.class, () -> fixture.builder(ResponderId.byName(fixture.name)).build(signer, List.of()));
        assertEquals(0, signatures.get());
    }

    private static BasicOCSPResponse basic(byte[] encoded) throws IOException {
        return BasicOCSPResponse.getInstance(ASN1Primitive.fromByteArray(OCSPResponse.getInstance(encoded).getResponseBytes().getResponse().getOctets()));
    }

    private static final class Fixture {
        private final KeyPair key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        private final KeyPair rootKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        private final X500Principal name = new X500Principal("CN=OCSP Responder,O=Example");
        private final X509Certificate root;
        private final X509Certificate certificate;
        private final List<CertId> ids;

        private Fixture() throws Exception {
            X500Principal issuer = new X500Principal("CN=OCSP Root");
            root = Pkix.certificateBuilder().serialNumber(BigInteger.ONE).issuer(issuer).subject(issuer)
                    .publicKey(rootKey.getPublic()).validity(NOW.minusSeconds(3600), NOW.plusSeconds(86400))
                    .basicConstraints(BasicConstraints.ca(), true).build(Pkix.signer(rootKey.getPrivate(), ED25519));
            certificate = Pkix.certificateBuilder().serialNumber(BigInteger.TWO).issuer(issuer).subject(name)
                    .publicKey(key.getPublic()).validity(NOW.minusSeconds(3600), NOW.plusSeconds(3600))
                    .build(Pkix.signer(rootKey.getPrivate(), ED25519));
            ids = List.of(Pkix.computeCertId(root, BigInteger.ONE, "1.3.14.3.2.26"),
                    Pkix.computeCertId(root, BigInteger.TWO, "1.3.14.3.2.26"),
                    Pkix.computeCertId(root, BigInteger.valueOf(3), "1.3.14.3.2.26"),
                    Pkix.computeCertId(root, BigInteger.valueOf(4), "1.3.14.3.2.26"));
        }
        private List<X509Certificate> chain() { return List.of(certificate, root); }
        private OcspResponseBuilder builder(ResponderId responder) {
            return Pkix.ocspResponseBuilder().responderId(responder).producedAt(NOW).nonce(NONCE)
                    .addResponse(ids.get(0), CertStatus.good(), NOW.minusSeconds(10), NOW.plusSeconds(600))
                    .addResponse(ids.get(1), CertStatus.unknown(), NOW.minusSeconds(20), null)
                    .addResponse(ids.get(2), CertStatus.revoked(NOW.minusSeconds(200), CrlReason.KEY_COMPROMISE), NOW, NOW.plusSeconds(300))
                    .addResponse(ids.get(3), new CertStatus.Revoked(NOW.minusSeconds(300), Optional.empty()), NOW, null);
        }
        private byte[] sign(byte[] bytes) throws Exception {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(key.getPrivate());
            signer.update(bytes);
            return signer.sign();
        }
        private byte[] legacy(ResponderId responder) throws Exception {
            RespID id = switch (responder) {
                case ResponderId.ByName byName -> new RespID(X500Name.getInstance(byName.name().getEncoded()));
                case ResponderId.ByKey byKey -> new RespID(new ResponderID(new DEROctetString(byKey.keyHash())));
            };
            BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(id);
            CertificateStatus[] states = {CertificateStatus.GOOD, new UnknownStatus(),
                    new RevokedStatus(Date.from(NOW.minusSeconds(200)), CrlReason.KEY_COMPROMISE.code()),
                    new RevokedStatus(Date.from(NOW.minusSeconds(300)), 0)};
            Instant[] updates = {NOW.minusSeconds(10), NOW.minusSeconds(20), NOW, NOW};
            Instant[] next = {NOW.plusSeconds(600), null, NOW.plusSeconds(300), null};
            for (int index = 0; index < ids.size(); index++) {
                CertId cert = ids.get(index);
                CertificateID certId = new CertificateID(new org.bouncycastle.asn1.ocsp.CertID(
                        org.bouncycastle.asn1.x509.AlgorithmIdentifier.getInstance(Pkix.encodeAlgorithmIdentifier(cert.hashAlgorithm())),
                        new DEROctetString(cert.issuerNameHash()), new DEROctetString(cert.issuerKeyHash()), new org.bouncycastle.asn1.ASN1Integer(cert.serialNumber())));
                builder.addResponse(certId, states[index], Date.from(updates[index]), next[index] == null ? null : Date.from(next[index]), (Extensions) null);
            }
            ExtensionsGenerator extensions = new ExtensionsGenerator();
            extensions.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(NONCE));
            builder.setResponseExtensions(extensions.generate());
            BasicOCSPResp basic = builder.build(new JcaContentSignerBuilder("Ed25519").build(key.getPrivate()),
                    new X509CertificateHolder[] {new X509CertificateHolder(certificate.getEncoded()), new X509CertificateHolder(root.getEncoded())}, Date.from(NOW));
            return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
        }
    }
}
