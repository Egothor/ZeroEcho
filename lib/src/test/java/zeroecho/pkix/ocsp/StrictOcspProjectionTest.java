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
package zeroecho.pkix.ocsp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.junit.jupiter.api.Test;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.crl.CrlReason;
import zeroecho.sdk.util.BouncyCastleActivator;

/** Regression coverage for bounded native OCSP projections and CertID syntax. */
final class StrictOcspProjectionTest {
    private static final Instant NOW = Instant.parse("2026-11-01T00:00:00Z");
    private static final String SHA256 = "2.16.840.1.101.3.4.2.1";
    private static final AlgorithmIdentifier PRIMARY = AlgorithmIdentifier.absent("1.2.840.10045.4.3.3");
    private static final byte[] NONCE = {1, 2, 3};

    @Test
    void parsesOrderedNativeStatesAndDefensivelyOwnsMutableValues() throws Exception {
        Fixture fixture = new Fixture();
        byte[] response = fixture.response(fixture.ids, NONCE, NOW, NOW.plusSeconds(60));
        var projection = StrictOcspProjection.parse(fixture.request, response, Pkix.encodeAlgorithmIdentifier(PRIMARY));
        assertEquals(List.of("GOOD", "REVOKED", "UNKNOWN"), projection.statuses().stream().map(StrictOcspProjection.Status::status).toList());
        assertEquals(NOW, projection.producedAt());
        assertEquals(NOW, projection.thisUpdate());
        assertEquals(NOW.plusSeconds(60), projection.nextUpdate());
        assertEquals(NOW.minusSeconds(1).toString(), projection.statuses().get(1).revocationTime());
        assertEquals(1, projection.statuses().get(1).reason());
        assertArrayEquals(NONCE, projection.nonce().orElseThrow());
        projection.nonce().orElseThrow()[0] ^= 1;
        assertArrayEquals(NONCE, projection.nonce().orElseThrow());
        byte[] identity = projection.statuses().getFirst().certIdDer(); byte[] saved = identity.clone(); identity[0] ^= 1;
        assertArrayEquals(saved, projection.statuses().getFirst().certIdDer());
        projection.algorithmIdentifier()[0] ^= 1;
        assertArrayEquals(Pkix.encodeAlgorithmIdentifier(PRIMARY), projection.algorithmIdentifier());
        assertThrows(UnsupportedOperationException.class, () -> projection.statuses().clear());
        assertTrue(projection.certificates().isEmpty());
    }

    @Test
    void rejectsNoncanonicalOrMismatchedNativeInputs() throws Exception {
        Fixture fixture = new Fixture();
        byte[] response = fixture.response(fixture.ids, NONCE, NOW, NOW.plusSeconds(60));
        byte[] algorithm = Pkix.encodeAlgorithmIdentifier(PRIMARY);
        byte[] trailing = Arrays.copyOf(response, response.length + 1);
        assertThrows(IllegalArgumentException.class, () -> StrictOcspProjection.parse(fixture.request, trailing, algorithm));
        assertThrows(IllegalArgumentException.class, () -> StrictOcspProjection.parse(fixture.request, response, new byte[] {5, 0}));
        assertThrows(IllegalArgumentException.class, () -> StrictOcspProjection.parse(fixture.request,
                fixture.response(fixture.ids, new byte[] {4}, NOW, NOW.plusSeconds(60)), algorithm));
        assertThrows(IllegalArgumentException.class, () -> StrictOcspProjection.parse(fixture.request,
                fixture.response(List.of(fixture.ids.get(1), fixture.ids.get(0), fixture.ids.get(2)), NONCE, NOW, NOW.plusSeconds(60)), algorithm));
        assertThrows(IllegalArgumentException.class, () -> StrictOcspProjection.parse(fixture.request,
                fixture.response(fixture.ids, NONCE, NOW.plusSeconds(1), NOW.plusSeconds(60)), algorithm));
        assertThrows(IllegalArgumentException.class, () -> StrictOcspProjection.parse(fixture.request, new byte[StrictOcspProjection.MAXIMUM_RESPONSE_BYTES + 1], algorithm));
        assertThrows(IllegalArgumentException.class, () -> StrictOcspProjection.parse(new byte[1_048_577], response, algorithm));
    }

    @Test
    void certIdIdentityNormalizesDigestNullVersusAbsentAndRejectsInvalidBounds() throws Exception {
        CertID withNull = certId(BigInteger.ONE, true, SHA256, 32);
        CertID absent = certId(BigInteger.ONE, false, SHA256, 32);
        assertEquals(StrictOcspProjection.certIdIdentity(withNull.getEncoded("DER")), StrictOcspProjection.certIdIdentity(absent.getEncoded("DER")));
        assertThrows(IllegalArgumentException.class, () -> StrictOcspProjection.certIdIdentity(certId(BigInteger.ZERO, true, SHA256, 32).getEncoded("DER")));
        assertThrows(IllegalArgumentException.class, () -> StrictOcspProjection.certIdIdentity(certId(BigInteger.ONE.shiftLeft(160), true, SHA256, 32).getEncoded("DER")));
        assertThrows(IllegalArgumentException.class, () -> StrictOcspProjection.certIdIdentity(certId(BigInteger.ONE, true, SHA256, 31).getEncoded("DER")));
        assertThrows(IllegalArgumentException.class, () -> StrictOcspProjection.certIdIdentity(certId(BigInteger.ONE, true, "1.2.3", 32).getEncoded("DER")));
        assertThrows(IllegalArgumentException.class, () -> StrictOcspProjection.certIdIdentity(new byte[109]));
        assertThrows(IllegalArgumentException.class, () -> StrictOcspProjection.certIdIdentity(null));
    }

    @Test
    void directProjectionConstructionSnapshotsArraysAndCollections() {
        byte[] nonce = {1}; byte[] algorithm = {2}; byte[] certificate = {3}; byte[] id = {4};
        var status = new StrictOcspProjection.Status(id, "GOOD", "", -1);
        var projection = new StrictOcspProjection.Projection(NOW, NOW, NOW, Optional.of(nonce), List.of(status), algorithm, List.of(certificate));
        nonce[0] = 5; algorithm[0] = 5; certificate[0] = 5; id[0] = 5;
        assertArrayEquals(new byte[] {1}, projection.nonce().orElseThrow());
        assertArrayEquals(new byte[] {2}, projection.algorithmIdentifier());
        assertArrayEquals(new byte[] {3}, projection.certificates().getFirst());
        assertArrayEquals(new byte[] {4}, projection.statuses().getFirst().certIdDer());
        projection.certificates().getFirst()[0] = 8;
        assertArrayEquals(new byte[] {3}, projection.certificates().getFirst());
    }

    private static CertID certId(BigInteger serial, boolean nullParameters, String oid, int hashBytes) {
        var digest = nullParameters ? new org.bouncycastle.asn1.x509.AlgorithmIdentifier(new ASN1ObjectIdentifier(oid), DERNull.INSTANCE)
                : new org.bouncycastle.asn1.x509.AlgorithmIdentifier(new ASN1ObjectIdentifier(oid));
        return new CertID(digest, new DEROctetString(new byte[hashBytes]), new DEROctetString(new byte[hashBytes]), new org.bouncycastle.asn1.ASN1Integer(serial));
    }

    private static final class Fixture {
        private final KeyPair key;
        private final byte[] request;
        private final List<CertId> ids;
        private Fixture() throws Exception {
            BouncyCastleActivator.init();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
            generator.initialize(new ECGenParameterSpec("secp384r1")); key = generator.generateKeyPair();
            var builder = new OCSPReqBuilder();
            for (int index = 1; index <= 3; index++) { builder.addRequest(new CertificateID(certId(BigInteger.valueOf(index), true, SHA256, 32))); }
            builder.setRequestExtensions(new Extensions(new Extension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2"), false,
                    new DEROctetString(new DEROctetString(NONCE).getEncoded("DER")))));
            request = builder.build().getEncoded(); ids = Pkix.parseOcspRequest(request).requestedCertificates();
        }
        private byte[] response(List<CertId> values, byte[] nonce, Instant update, Instant next) {
            var builder = Pkix.ocspResponseBuilder().responderId(ResponderId.byName(new X500Principal("CN=Projection"))).producedAt(NOW).nonce(nonce);
            builder.addResponse(values.get(0), CertStatus.good(), update, next);
            builder.addResponse(values.get(1), CertStatus.revoked(NOW.minusSeconds(1), CrlReason.KEY_COMPROMISE), update, next);
            builder.addResponse(values.get(2), CertStatus.unknown(), update, next);
            return builder.build(Pkix.signer(key.getPrivate(), PRIMARY), List.of());
        }
    }
}
