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
package zeroecho.pki.api.hybrid.sdk;

import static org.junit.jupiter.api.Assertions.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerCryptographicBinding.HybridSignatureBaseline;
import zeroecho.pki.application.SdkOcspProjection;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.CertificateExtension;
import zeroecho.pkix.ocsp.CertStatus;
import zeroecho.pkix.ocsp.ResponderId;

/** Real independent native/delegation and dual-evidence signatures; no live PKI claim. */
class SdkOcspEvidenceVerifierTest {
    private static final Instant NOW = Instant.parse("2026-11-15T12:00:00Z");
    private static final zeroecho.pkix.AlgorithmIdentifier PRIMARY = zeroecho.pkix.AlgorithmIdentifier.absent("1.2.840.10045.4.3.3");
    private static final zeroecho.pkix.AlgorithmIdentifier ALT = zeroecho.pkix.AlgorithmIdentifier.absent("2.16.840.1.101.3.4.3.19");

    @Test void verifiesNativeDelegationBothEvidenceRolesAndPreservesGoodRevokedUnknown() throws Exception {
        var fixture = new Fixture(); var evidence = fixture.bundle(fixture.fields);
        var result = SdkOcspEvidenceVerifier.verify(evidence, fixture.context(NOW, fixture.nonce));
        var statuses = result.statuses().listValues();
        assertEquals(List.of("GOOD", "REVOKED", "UNKNOWN"), statuses.stream().map(value -> value.objectFields().get("status").textValue()).toList());
        assertEquals("2026-11-15T11:59:00Z", statuses.get(1).objectFields().get("revocationTime").textValue());
        assertEquals(1, statuses.get(1).objectFields().get("reason").integerValue());
        assertArrayEquals(new byte[]{1,2,3}, java.util.Arrays.copyOfRange(result.nonce().objectFields().get("value").encode(),5,8));
        // Independent framing code writes the public wire specification, not HybridSdkFrame.encode.
        for (int kind : new int[]{4,5}) {
            byte[] independent = independentFrame(kind, fixture.fields);
            var frame = kind == 4 ? evidence.primaryFrame() : evidence.alternativeFrame();
            assertArrayEquals(independent, frame.encode());
            assertArrayEquals(independent, HybridSdkFrame.decode(independent).encode());
        }
        byte[] borrowed = evidence.primaryResponseDer(); borrowed[0] ^= 1;
        assertArrayEquals(fixture.response, evidence.primaryResponseDer());
    }

    @Test void rejectsTamperWrongRolesNonceStaleStatusAndUntrustedCoordinates() throws Exception {
        var fixture = new Fixture(); var valid = fixture.bundle(fixture.fields);
        byte[] alternative = valid.alternativeSignature(); alternative[0] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> SdkOcspEvidenceVerifier.verify(new SdkOcspEvidence(valid.primaryResponseDer(), valid.responderChain(),valid.primaryFrame(),valid.alternativeFrame(),valid.primarySignature(),alternative),fixture.context(NOW,fixture.nonce)));
        assertThrows(IllegalArgumentException.class, () -> new SdkOcspEvidence(valid.primaryResponseDer(),valid.responderChain(),valid.primaryFrame(),valid.alternativeFrame(),valid.alternativeSignature(),valid.primarySignature()));
        byte[] wrongNonce = fixture.nonce.clone(); wrongNonce[0] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> SdkOcspEvidenceVerifier.verify(valid,fixture.context(NOW,wrongNonce)));
        assertThrows(IllegalArgumentException.class, () -> SdkOcspEvidenceVerifier.verify(valid,fixture.context(NOW.plusSeconds(301),fixture.nonce)));
        var changed = new TreeMap<>(fixture.fields); changed.put(10, text("issuer:other"));
        var wrongIssuer = fixture.bundle(changed);
        assertThrows(IllegalArgumentException.class, () -> SdkOcspEvidenceVerifier.verify(wrongIssuer,fixture.context(NOW,fixture.nonce)));
        changed = new TreeMap<>(fixture.fields);
        var statuses = new java.util.ArrayList<>(HybridSdkValue.decode(changed.get(21)).listValues());
        var first = new TreeMap<>(statuses.getFirst().objectFields()); first.put("status",HybridSdkValue.text("UNKNOWN")); statuses.set(0,HybridSdkValue.object(first));
        changed.put(21,HybridSdkValue.list(statuses).encode()); var wrongStatus = fixture.bundle(changed);
        assertThrows(IllegalArgumentException.class, () -> SdkOcspEvidenceVerifier.verify(wrongStatus,fixture.context(NOW,fixture.nonce)));
        byte[] trailing = Arrays.copyOf(fixture.response,fixture.response.length+1);
        assertThrows(IllegalArgumentException.class, () -> SdkOcspProjection.parse(fixture.request,trailing));
        assertThrows(IllegalArgumentException.class, () -> SdkOcspProjection.parse(new byte[1048577],fixture.response));
        var oversized = new TreeMap<>(fixture.fields); oversized.put(21,new byte[262145]);
        assertThrows(IllegalArgumentException.class, () -> new HybridSdkFrame(4,oversized));
        assertThrows(IllegalArgumentException.class, () -> new SdkOcspEvidence(new byte[SdkOcspProjection.MAXIMUM_RESPONSE_BYTES+1],valid.responderChain(),valid.primaryFrame(),valid.alternativeFrame(),valid.primarySignature(),valid.alternativeSignature()));
    }

    @Test void parsesComponentBoundedNativeResponseLargerThanRequestLimitAndRejectsDerivedOverflow() throws Exception {
        var fixture = new Fixture();
        // This tests native parsing/allocation, not authorization of this artificial chain.
        var name = new X500Principal("CN=" + "x".repeat(230000));
        var certificate = Pkix.certificateBuilder().serialNumber(BigInteger.valueOf(90)).subject(name).issuer(new X500Principal("CN=Large native parser fixture"))
                .publicKey(fixture.primary.getPublic()).validity(NOW.minusSeconds(60),NOW.plusSeconds(600))
                .build(Pkix.signer(fixture.primary.getPrivate(),PRIMARY));
        byte[] certificateDer = certificate.getEncoded(); assertTrue(certificateDer.length <= 262144);
        HybridSdkValue.list(List.of(certificate,certificate,certificate,certificate).stream().map(value -> {
            try { return HybridSdkValue.bytes(value.getEncoded()); } catch (java.security.cert.CertificateEncodingException failure) { throw new IllegalStateException(failure); }
        }).toList());
        var id = Pkix.parseOcspRequest(fixture.request).requestedCertificates();
        var builder = Pkix.ocspResponseBuilder().responderId(ResponderId.byName(name)).producedAt(NOW).nonce(new byte[]{1,2,3});
        for (var entry : id) builder.addResponse(entry,CertStatus.good(),NOW,NOW.plusSeconds(300));
        byte[] response = builder.build(Pkix.signer(fixture.primary.getPrivate(),PRIMARY),List.of(certificate,certificate,certificate,certificate));
        assertTrue(response.length > 1048576); assertTrue(response.length <= 1455101);
        assertTrue(Pkix.parseOcspResponse(response).verifySignature(fixture.primary.getPublic()));
        assertEquals(3,SdkOcspProjection.parse(fixture.request,response).statuses().listValues().size());
        assertThrows(IllegalArgumentException.class, () -> SdkOcspProjection.parse(fixture.request,new byte[1455102]));
    }

    @Test void rejectsDuplicateCertIdDespiteAcceptedNullVersusAbsentDigestParameters() throws Exception {
        var fixture = new Fixture();
        var first = new org.bouncycastle.cert.ocsp.OCSPReq(fixture.request).getRequestList()[0].getCertID().toASN1Primitive();
        var absent = new org.bouncycastle.asn1.ocsp.CertID(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(first.getHashAlgorithm().getAlgorithm()),
                first.getIssuerNameHash(), first.getIssuerKeyHash(), first.getSerialNumber());
        assertFalse(Arrays.equals(first.getEncoded("DER"), absent.getEncoded("DER")));
        var request = new OCSPReqBuilder().addRequest(new CertificateID(first)).addRequest(new CertificateID(absent)).build().getEncoded();
        var ids = Pkix.parseOcspRequest(request).requestedCertificates();
        var response = Pkix.ocspResponseBuilder().responderId(ResponderId.byName(fixture.responder.getSubjectX500Principal())).producedAt(NOW)
                .addResponse(ids.get(0), CertStatus.good(), NOW, NOW.plusSeconds(300))
                .addResponse(ids.get(1), CertStatus.good(), NOW, NOW.plusSeconds(300))
                .build(Pkix.signer(fixture.primary.getPrivate(), PRIMARY), List.of(fixture.responder));
        assertThrows(IllegalArgumentException.class, () -> SdkOcspProjection.parse(request,response));
    }

    private static byte[] independentFrame(int kind, Map<Integer,byte[]> fields) throws Exception {
        var buffer = new java.io.ByteArrayOutputStream(); var out = new java.io.DataOutputStream(buffer);
        out.write("ZeroEcho-Hybrid-SDK".getBytes(StandardCharsets.US_ASCII)); out.writeByte(0); out.writeShort(1); out.writeShort(kind); out.writeShort(21);
        for (int tag=1;tag<=21;tag++) { out.writeShort(tag); out.writeInt(fields.get(tag).length); out.write(fields.get(tag)); }
        return buffer.toByteArray();
    }
    private static byte[] text(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static byte[] time(Instant value) { return ByteBuffer.allocate(8).putLong(value.getEpochSecond()).array(); }
    private static KeyPair primary() throws Exception { var generator=KeyPairGenerator.getInstance("EC"); generator.initialize(new ECGenParameterSpec("secp384r1")); return generator.generateKeyPair(); }
    private static KeyPair alternative() throws Exception { return KeyPairGenerator.getInstance("ML-DSA-87","BC").generateKeyPair(); }
    private static byte[] signature(KeyPair key, String algorithm, byte[] bytes) throws Exception {
        var signer=Signature.getInstance(algorithm,"BC"); if (algorithm.equals("ML-DSA-87")) signer.setParameter(new org.bouncycastle.jcajce.spec.ContextParameterSpec(new byte[0]));
        signer.initSign(key.getPrivate()); signer.update(bytes); return signer.sign();
    }
    private static java.security.cert.X509Certificate certificate(KeyPair subjectPrimary,KeyPair subjectAlternative,KeyPair issuerPrimary,KeyPair issuerAlternative,boolean ca) throws Exception {
        var builder=Pkix.certificateBuilder().serialNumber(ca?BigInteger.ONE:BigInteger.TWO).subject(new X500Principal(ca?"CN=Evidence root":"CN=Evidence responder"))
                .issuer(new X500Principal("CN=Evidence root")).publicKey(subjectPrimary.getPublic()).validity(NOW.minusSeconds(3600),NOW.plusSeconds(3600))
                .basicConstraints(ca?zeroecho.pkix.BasicConstraints.ca():zeroecho.pkix.BasicConstraints.endEntity(),true)
                .keyUsage(ca?java.util.Set.of(zeroecho.pkix.KeyUsage.KEY_CERT_SIGN):java.util.Set.of(zeroecho.pkix.KeyUsage.DIGITAL_SIGNATURE),true)
                .addExtension(new CertificateExtension("2.5.29.72",false,subjectAlternative.getPublic().getEncoded()))
                .addExtension(new CertificateExtension("2.5.29.73",false,Pkix.encodeAlgorithmIdentifier(ALT)));
        if (!ca) builder.addExtension(new CertificateExtension("2.5.29.37",false,new org.bouncycastle.asn1.x509.ExtendedKeyUsage(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_OCSPSigning).getEncoded("DER")));
        byte[] alternative=signature(issuerAlternative,"ML-DSA-87",builder.buildAlternativeSignatureTbs(PRIMARY));
        return builder.addExtension(new CertificateExtension("2.5.29.74",false,new DERBitString(alternative).getEncoded("DER"))).build(Pkix.signer(issuerPrimary.getPrivate(),PRIMARY));
    }
    private static HybridSdkValue role(KeyPair key,boolean alternative) {
        return HybridSdkValue.object(Map.of("spki",HybridSdkValue.bytes(key.getPublic().getEncoded()),
                "publicKeyAlgorithm",HybridSdkValue.text((alternative?BootstrapAlgorithmIdentities.ML_DSA_87_PUBLIC_KEY:BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY).canonicalForm()),
                "signatureAlgorithm",HybridSdkValue.text((alternative?BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE:BootstrapAlgorithmIdentities.ECDSA_SHA384).canonicalForm()),
                "algorithmIdentifier",HybridSdkValue.bytes(alternative?HybridSdkFrame.alternativeAlgorithm():HybridSdkFrame.primaryAlgorithm())));
    }
    private static final class Fixture {
        final KeyPair primary,alternative; final java.security.cert.X509Certificate root,responder;
        final byte[] request,response,nonce=new byte[32]; final HybridSdkValue roles; final TreeMap<Integer,byte[]> fields=new TreeMap<>();
        Fixture() throws Exception {
            zeroecho.sdk.util.BouncyCastleActivator.init(); var rootPrimary=primary(); var rootAlternative=alternative(); primary=primary(); alternative=alternative();
            root=certificate(rootPrimary,rootAlternative,rootPrimary,rootAlternative,true); responder=certificate(primary,alternative,rootPrimary,rootAlternative,false);
            roles=HybridSdkValue.object(Map.of("primary",role(primary,false),"alternative",role(alternative,true)));
            var digest=new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"), org.bouncycastle.asn1.DERNull.INSTANCE));
            var builder=new OCSPReqBuilder();
            for(int index=0;index<3;index++) builder.addRequest(new CertificateID(digest,new X509CertificateHolder(root.getEncoded()),BigInteger.TEN.add(BigInteger.valueOf(index))));
            builder.setRequestExtensions(new Extensions(new Extension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2"),false,new DEROctetString(new DEROctetString(new byte[]{1,2,3}).getEncoded("DER")))));
            request=builder.build().getEncoded(); var requested=Pkix.parseOcspRequest(request).requestedCertificates();
            var responseBuilder=Pkix.ocspResponseBuilder().responderId(ResponderId.byName(responder.getSubjectX500Principal())).producedAt(NOW).nonce(new byte[]{1,2,3});
            // Native service recomputes CertIDs; NULL versus absent digest parameters
            // must not change accepted SHA256 hash/serial identity.
            var normalized = requested.stream().map(id -> Pkix.computeCertId(root,id.serialNumber(),id.hashAlgorithm().oid())).toList();
            responseBuilder.addResponse(normalized.get(0),CertStatus.good(),NOW,NOW.plusSeconds(300));
            responseBuilder.addResponse(normalized.get(1),CertStatus.revoked(NOW.minusSeconds(60),zeroecho.pkix.crl.CrlReason.KEY_COMPROMISE),NOW,NOW.plusSeconds(300));
            responseBuilder.addResponse(normalized.get(2),CertStatus.unknown(),NOW,NOW.plusSeconds(300));
            response=responseBuilder.build(Pkix.signer(primary.getPrivate(),PRIMARY),List.of(responder,root));
            var requestId = new org.bouncycastle.cert.ocsp.OCSPReq(request).getRequestList()[0].getCertID().toASN1Primitive();
            var responseId = ((org.bouncycastle.cert.ocsp.BasicOCSPResp)new org.bouncycastle.cert.ocsp.OCSPResp(response).getResponseObject()).getResponses()[0].getCertID().toASN1Primitive();
            assertFalse(Arrays.equals(requestId.getEncoded("DER"),responseId.getEncoded("DER")));
            var projection=SdkOcspProjection.parse(request,response);
            fields.put(1,text("zeroecho-hybrid-sdk-v1")); fields.put(2,text("test-realm")); fields.put(3,text("https://127.0.0.1:8443")); fields.put(4,nonce);
            fields.put(5,HybridSdkFrame.hash(request)); fields.put(6,HybridSdkFrame.hash(response)); fields.put(7,HybridSdkFrame.hash(responder.getEncoded()));
            fields.put(8,HybridSdkFrame.hash(HybridSdkValue.list(List.of(HybridSdkValue.bytes(responder.getEncoded()),HybridSdkValue.bytes(root.getEncoded()))).encode()));
            fields.put(9,text("ca:test"));fields.put(10,text("issuer:test"));fields.put(11,text("path:test"));fields.put(12,text("a".repeat(64)));fields.put(13,text("b".repeat(64)));fields.put(14,roles.encode());
            fields.put(15,time(NOW));fields.put(16,time(NOW));fields.put(17,time(NOW.plusSeconds(300)));fields.put(18,time(NOW));fields.put(19,time(NOW.plusSeconds(120)));fields.put(20,projection.nonce().encode());fields.put(21,projection.statuses().encode());
        }
        SdkOcspEvidence bundle(Map<Integer,byte[]> values) throws Exception {
            var f4=new HybridSdkFrame(4,values);var f5=new HybridSdkFrame(5,values);
            return new SdkOcspEvidence(response,List.of(responder.getEncoded(),root.getEncoded()),f4,f5,signature(primary,"SHA384withECDSA",f4.encode()),signature(alternative,"ML-DSA-87",f5.encode()));
        }
        SdkOcspEvidenceVerifier.TrustedContext context(Instant now,byte[] clientNonce) throws Exception {
            return new SdkOcspEvidenceVerifier.TrustedContext("test-realm","https://127.0.0.1:8443",new PkiId("ca:test"),new PkiId("issuer:test"),new PkiId("path:test"),"a".repeat(64),"b".repeat(64),request,clientNonce,List.of(root.getEncoded()),List.of(HybridSignatureBaseline.COR3_SIGNED_WRAPPER),responder.getEncoded(),roles,now);
        }
    }
}
