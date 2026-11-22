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

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Strict DER and fixed-suite signature checks with no provider types in the public contract.
 * Inputs are borrowed only for each call; returned byte arrays are independently owned.
 */
public final class PkixEncoding {
    private static final String DER = "DER";
    private PkixEncoding() { }

    /**
     * Re-encodes exactly one ASN.1 value as canonical DER.
     * @param encoded one complete ASN.1 value, not null
     * @return canonical DER in a new array
     * @throws IOException if the encoding is malformed or contains trailing data
     * @throws NullPointerException if encoded is null
     */
    public static byte[] canonicalDer(byte[] encoded) throws IOException {
        return ASN1Primitive.fromByteArray(Objects.requireNonNull(encoded, "encoded")).getEncoded(DER);
    }

    /**
     * Unwraps one ASN.1 OCTET STRING, as returned by X509Certificate extension accessors.
     * @param encoded complete encoded OCTET STRING, not null
     * @return independently owned payload bytes
     * @throws IllegalArgumentException if the value is malformed or has a different ASN.1 type
     * @throws NullPointerException if encoded is null
     */
    public static byte[] octetStringContents(byte[] encoded) {
        return ASN1OctetString.getInstance(Objects.requireNonNull(encoded, "encoded")).getOctets().clone();
    }

    /**
     * Requires a canonical SPKI with a zero-padding subject public-key BIT STRING.
     * @param encoded complete subject public-key info DER, not null
     * @throws IOException if the value cannot be encoded
     * @throws IllegalArgumentException if malformed, noncanonical, or padded
     * @throws NullPointerException if encoded is null
     */
    public static void requireCanonicalSubjectPublicKeyInfo(byte[] encoded) throws IOException {
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(Objects.requireNonNull(encoded, "encoded"));
        if (!Arrays.equals(encoded, info.getEncoded(DER)) || info.getPublicKeyData().getPadBits() != 0) {
            throw new IllegalArgumentException("Noncanonical subject public key");
        }
    }

    /**
     * Requires a canonical PKCS#10 encoding with an unpadded signature BIT STRING.
     * @param encoded complete PKCS#10 DER, not null
     * @throws IOException if ASN.1 decoding or encoding fails
     * @throws IllegalArgumentException if malformed, noncanonical, or signature bits are padded
     * @throws NullPointerException if encoded is null
     */
    public static void requireCanonicalCertificationRequest(byte[] encoded) throws IOException {
        CertificationRequest request = CertificationRequest.getInstance(
                ASN1Primitive.fromByteArray(Objects.requireNonNull(encoded, "encoded")));
        if (!Arrays.equals(encoded, request.getEncoded(DER)) || request.getSignature().getPadBits() != 0) {
            throw new IllegalArgumentException("Noncanonical certification request");
        }
    }

    /**
     * Validates the canonical, uncompressed, finite P-384 point and exact named-curve identity.
     * @param encoded complete subject public-key info DER, not null
     * @throws IOException if the value cannot be encoded
     * @throws IllegalArgumentException if the key is malformed, noncanonical or outside P-384
     * @throws NullPointerException if encoded is null
     */
    public static void requireP384SubjectPublicKeyInfo(byte[] encoded) throws IOException {
        requireCanonicalSubjectPublicKeyInfo(encoded);
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(encoded);
        byte[] bits = info.getPublicKeyData().getBytes();
        if (!"1.2.840.10045.2.1".equals(info.getAlgorithm().getAlgorithm().getId())
                || info.getAlgorithm().getParameters() == null
                || !Arrays.equals(info.getAlgorithm().getParameters().toASN1Primitive().getEncoded(DER),
                        new byte[] {6, 5, 43, (byte) 129, 4, 0, 34})
                || bits.length != 97 || bits[0] != 4) {
            throw new IllegalArgumentException("Expected uncompressed named P-384 key");
        }
        ECPoint point = SECNamedCurves.getByName("secp384r1").getCurve().decodePoint(bits);
        if (point.isInfinity() || !point.isValid()) {
            throw new IllegalArgumentException("Invalid P-384 point");
        }
    }

    /**
     * Requires canonical DER ECDSA scalars in the open interval (0, P-384 order).
     * @param encoded complete signature DER, not null, 8 through 104 bytes
     * @throws IOException if ASN.1 decoding fails
     * @throws IllegalArgumentException if noncanonical, wrong-shaped or a scalar is out of range
     * @throws NullPointerException if encoded is null
     */
    public static void requireP384Signature(byte[] encoded) throws IOException {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length < 8 || encoded.length > 104) {
            throw new IllegalArgumentException("Invalid P-384 signature length");
        }
        ASN1Sequence sequence = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoded));
        if (sequence.size() != 2 || !Arrays.equals(encoded, sequence.getEncoded(DER))) {
            throw new IllegalArgumentException("Invalid P-384 signature encoding");
        }
        BigInteger order = SECNamedCurves.getByName("secp384r1").getN();
        for (int index = 0; index < 2; index++) {
            BigInteger value = ASN1Integer.getInstance(sequence.getObjectAt(index)).getValue();
            if (value.signum() <= 0 || value.compareTo(order) >= 0) {
                throw new IllegalArgumentException("P-384 scalar out of range");
            }
        }
    }

    /**
     * Encodes an ECDSA scalar pair without asserting an algorithm or scalar range.
     * @param first first non-null scalar
     * @param second second non-null scalar
     * @return canonical DER SEQUENCE of the two INTEGERs
     * @throws IOException if DER encoding fails
     * @throws NullPointerException if either scalar is null
     */
    public static byte[] ecdsaSignature(BigInteger first, BigInteger second) throws IOException {
        return new DERSequence(new ASN1Integer[] {new ASN1Integer(Objects.requireNonNull(first, "first")),
                new ASN1Integer(Objects.requireNonNull(second, "second"))}).getEncoded(DER);
    }

    /**
     * Verifies pure ML-DSA-87 with the explicitly empty FIPS 204 context.
     * @param key non-null ML-DSA public key
     * @param message non-null message bytes
     * @param signature non-null signature bytes
     * @return true only if the signature verifies with an empty context
     * @throws GeneralSecurityException if the required engine, parameters or key are invalid
     * @throws NullPointerException if an argument is null
     */
    public static boolean verifyEmptyContextMldsa87(PublicKey key, byte[] message, byte[] signature)
            throws GeneralSecurityException {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        Signature verifier = Signature.getInstance("ML-DSA-87", "BC");
        verifier.setParameter(new org.bouncycastle.jcajce.spec.ContextParameterSpec(new byte[0]));
        verifier.initVerify(Objects.requireNonNull(key, "key"));
        verifier.update(Objects.requireNonNull(message, "message"));
        return verifier.verify(Objects.requireNonNull(signature, "signature"));
    }
}
