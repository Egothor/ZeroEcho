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
package zeroecho.pki.impl.framework.x509.bc;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;

/** Fixed-suite v1 verifier of two SUBJECT-key proofs; it grants no issuance authority. */
public final class BcHybridSdkProofVerifier {
    /** Creates a stateless, thread-safe verifier. */
    public BcHybridSdkProofVerifier() { }

    /**
     * Verifies the original signed CSR and both domain-separated fresh proofs.
     * Authenticated actor, issuer context and one-shot consumption remain the server gate's responsibility.
     * @param request exact SDK request view
     * @param primaryFrame retained F1 challenge; F2 uses identical fields with kind 2
     * @param primaryProof canonical DER ECDSA/SHA-384 signature
     * @param alternativeProof pure ML-DSA-87 signature with empty context
     * @param now authoritative acceptance time
     * @return immutable sha512-prefixed F3 proof commitment
     * @throws PkiException for mismatched request, expired context or invalid proofs
     */
    public String verify(ParsedHybridSdkRequest request, HybridSdkFrame primaryFrame,
            byte[] primaryProof, byte[] alternativeProof, Instant now) {
        Objects.requireNonNull(request, "request"); Objects.requireNonNull(primaryFrame, "primaryFrame");
        Objects.requireNonNull(primaryProof, "primaryProof"); Objects.requireNonNull(alternativeProof, "alternativeProof");
        Objects.requireNonNull(now, "now");
        if (primaryProof.length > 104 || alternativeProof.length != 4627) throw invalid();
        primaryProof = primaryProof.clone(); alternativeProof = alternativeProof.clone();
        try {
            byte[] original = original(request);
            ParsedHybridSdkRequest reparsed = new BcX509CertificationRequestParser().parseHybridSdk(
                    new CertificationRequest(BcX509CredentialFramework.FORMAT_ID, new EncodedObject(Encoding.DER, original)));
            if (!request.primary().subjectRef().equals(reparsed.primary().subjectRef())
                    || !request.primary().subjectRdns().equals(reparsed.primary().subjectRdns())
                    || !request.primary().subjectAlternativeNames().equals(reparsed.primary().subjectAlternativeNames())
                    || !Arrays.equals(request.primary().publicKeyInfo().bytes(), reparsed.primary().publicKeyInfo().bytes())
                    || !Arrays.equals(request.alternativeSubjectPublicKeyInfo().bytes(), reparsed.alternativeSubjectPublicKeyInfo().bytes())) throw invalid();
            if (primaryFrame.kind() != 1) throw invalid();
            long issued = ByteBuffer.wrap(primaryFrame.field(7)).getLong();
            long expires = ByteBuffer.wrap(primaryFrame.field(8)).getLong();
            if (now.isBefore(Instant.ofEpochSecond(issued)) || !now.isBefore(Instant.ofEpochSecond(expires))) throw invalid();
            if (!MessageDigest.isEqual(HybridSdkFrame.hash(original), primaryFrame.field(11))
                    || !MessageDigest.isEqual(HybridSdkFrame.hash(request.primary().publicKeyInfo().bytes()), primaryFrame.field(13))
                    || !MessageDigest.isEqual(HybridSdkFrame.hash(request.alternativeSubjectPublicKeyInfo().bytes()), primaryFrame.field(14))) throw invalid();
            Keys keys = keys(request); requireEcdsaSignature(primaryProof);
            if (alternativeProof.length != 4627) throw invalid();
            HybridSdkFrame alternativeFrame = new HybridSdkFrame(2, primaryFrame.fields());
            if (!verifyEcdsa(keys.primary(), primaryFrame.encode(), primaryProof)
                    || !verifyMldsa(keys.alternative(), alternativeFrame.encode(), alternativeProof)) throw invalid();
            var proof = new HybridSdkFrame(3, Map.of(1, HybridSdkFrame.hash(primaryFrame.encode()),
                    2, HybridSdkFrame.hash(alternativeFrame.encode()), 3, primaryProof.clone(), 4, alternativeProof.clone(), 5, primaryFrame.field(17)));
            return "sha512:" + HexFormat.of().formatHex(HybridSdkFrame.hash(proof.encode()));
        } catch (java.io.IOException | GeneralSecurityException | IllegalArgumentException invalid) {
            throw invalid();
        }
    }

    static void requireRequest(ParsedHybridSdkRequest request) {
        try {
            Keys keys = keys(request); byte[] der = original(request);
            var csr = org.bouncycastle.asn1.pkcs.CertificationRequest.getInstance(ASN1Primitive.fromByteArray(der));
            if (!Arrays.equals(csr.getSignatureAlgorithm().getEncoded("DER"), HybridSdkFrame.primaryAlgorithm())
                    || csr.getSignature().getPadBits() != 0
                    || !Arrays.equals(csr.getCertificationRequestInfo().getSubjectPublicKeyInfo().getEncoded("DER"), request.primary().publicKeyInfo().bytes())) throw invalid();
            requireEcdsaSignature(csr.getSignature().getBytes());
            if (!verifyEcdsa(keys.primary(), csr.getCertificationRequestInfo().getEncoded("DER"), csr.getSignature().getBytes())) throw invalid();
        } catch (java.io.IOException | GeneralSecurityException | IllegalArgumentException invalid) { throw invalid(); }
    }

    private static Keys keys(ParsedHybridSdkRequest request) throws java.io.IOException, GeneralSecurityException {
        byte[] primary = request.primary().publicKeyInfo().bytes();
        byte[] alternative = request.alternativeSubjectPublicKeyInfo().bytes();
        SubjectPublicKeyInfo primaryInfo = spki(primary), alternativeInfo = spki(alternative);
        if (!primaryInfo.getAlgorithm().getAlgorithm().getId().equals("1.2.840.10045.2.1")
                || !ASN1ObjectIdentifier.getInstance(primaryInfo.getAlgorithm().getParameters()).getId().equals("1.3.132.0.34")) throw invalid();
        byte[] point = primaryInfo.getPublicKeyData().getBytes();
        if (point.length != 97 || point[0] != 4) throw invalid();
        var curve = SECNamedCurves.getByName("secp384r1"); var decoded = curve.getCurve().decodePoint(point);
        if (decoded.isInfinity() || !decoded.isValid()) throw invalid();
        if (!alternativeInfo.getAlgorithm().getAlgorithm().getId().equals("2.16.840.1.101.3.4.3.19")
                || alternativeInfo.getAlgorithm().getParameters() != null || alternativeInfo.getPublicKeyData().getBytes().length != 2592) throw invalid();
        zeroecho.sdk.util.BouncyCastleActivator.init();
        PublicKey primaryKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(primary));
        PublicKey alternativeKey = KeyFactory.getInstance("ML-DSA", "BC").generatePublic(new X509EncodedKeySpec(alternative));
        if (!Arrays.equals(primary, primaryKey.getEncoded()) || !Arrays.equals(alternative, alternativeKey.getEncoded())) throw invalid();
        return new Keys(primaryKey, alternativeKey);
    }
    private static SubjectPublicKeyInfo spki(byte[] der) throws java.io.IOException {
        new StreamingDerReader().validate(der, 8192);
        SubjectPublicKeyInfo result = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(der));
        if (!Arrays.equals(der, result.getEncoded("DER")) || result.getPublicKeyData().getPadBits() != 0) throw invalid(); return result;
    }
    private static byte[] original(ParsedHybridSdkRequest request) {
        X509EnrollmentPayload payload = BcX509RequestPayloads.extract(request.primary());
        if (payload.kind() != X509EnrollmentPayload.Kind.PKCS10) throw invalid(); return payload.der();
    }
    private static boolean verifyEcdsa(PublicKey key, byte[] bytes, byte[] signature) throws GeneralSecurityException {
        Signature verifier = Signature.getInstance("SHA384withECDSA"); verifier.initVerify(key); verifier.update(bytes); return verifier.verify(signature);
    }
    private static boolean verifyMldsa(PublicKey key, byte[] bytes, byte[] signature) throws GeneralSecurityException {
        Signature verifier = Signature.getInstance("ML-DSA-87", "BC");
        verifier.setParameter(new org.bouncycastle.jcajce.spec.ContextParameterSpec(new byte[0]));
        verifier.initVerify(key); verifier.update(bytes); return verifier.verify(signature);
    }
    private static void requireEcdsaSignature(byte[] der) throws java.io.IOException {
        if (der.length < 8 || der.length > 104) throw invalid();
        new StreamingDerReader().validate(der, 104); ASN1Sequence value = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der));
        if (value.size() != 2 || !Arrays.equals(der, value.getEncoded("DER"))) throw invalid();
        var order = SECNamedCurves.getByName("secp384r1").getN();
        for (int i = 0; i < 2; i++) {
            var integer = ASN1Integer.getInstance(value.getObjectAt(i)).getValue();
            if (integer.signum() <= 0 || integer.compareTo(order) >= 0) throw invalid();
        }
    }
    private static PkiException invalid() { return new PkiException("SDK_PROOF_INVALID"); }
    private record Keys(PublicKey primary, PublicKey alternative) { }
}
