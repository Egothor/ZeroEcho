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
 * Validates the encodings and signature primitives used by the fixed PKIX proof suites.
 *
 * <p>The encoding checks distinguish canonical representation from cryptographic
 * verification. A structurally valid subject key or certification request is not
 * thereby trusted, and an encoded ECDSA scalar pair is not thereby a valid
 * signature. Callers must perform the applicable proof and trust checks separately.
 *
 * <p>Methods do not retain or modify input arrays. Callers must not modify an input
 * array while a call is in progress; returned arrays belong to the caller. Signature
 * verification initializes the library's cryptographic provider when necessary.
 * Provider-specific types do not form part of this API.
 */
public final class PkixEncoding {
    private static final String DER = "DER";
    private PkixEncoding() { }

    /**
     * Re-encodes exactly one ASN.1 value as canonical DER.
     *
     * <p>This operation normalizes an accepted ASN.1 representation; it does not
     * require the input already to be DER and does not validate a PKIX schema.
     * Compare the result with the input when canonical input is a precondition.
     * The input must contain one complete value with no trailing bytes.
     *
     * @param encoded the complete ASN.1 representation; must not be {@code null}
     * @return a newly allocated canonical DER representation of the value
     * @throws IOException if decoding or encoding fails, including trailing input
     * @throws NullPointerException if {@code encoded} is {@code null}
     */
    public static byte[] canonicalDer(byte[] encoded) throws IOException {
        return ASN1Primitive.fromByteArray(Objects.requireNonNull(encoded, "encoded")).getEncoded(DER);
    }

    /**
     * Extracts the contents of an encoded ASN.1 OCTET STRING.
     *
     * <p>Use this operation for the outer wrapper returned by
     * {@link java.security.cert.X509Certificate#getExtensionValue(String)}. The
     * extracted bytes are not interpreted or validated as an extension value,
     * and this operation does not require canonical DER input.
     *
     * @param encoded one complete encoded OCTET STRING; must not be {@code null}
     * @return a new array containing the OCTET STRING payload without its wrapper
     * @throws IllegalArgumentException if the representation cannot be decoded as
     *     an OCTET STRING
     * @throws NullPointerException if {@code encoded} is {@code null}
     */
    public static byte[] octetStringContents(byte[] encoded) {
        return ASN1OctetString.getInstance(Objects.requireNonNull(encoded, "encoded")).getOctets().clone();
    }

    /**
     * Requires canonical DER SubjectPublicKeyInfo with an octet-aligned public key.
     *
     * <p>The complete representation must equal its DER re-encoding and the
     * subject-public-key BIT STRING must have zero unused bits. This check does
     * not select an algorithm, validate algorithm parameters or establish that
     * the key is mathematically valid for a particular algorithm.
     *
     * @param encoded the complete SubjectPublicKeyInfo representation; must not
     *     be {@code null}
     * @throws IOException if DER re-encoding fails
     * @throws IllegalArgumentException if the structure is malformed, differs
     *     from its canonical DER encoding or contains unused public-key bits
     * @throws NullPointerException if {@code encoded} is {@code null}
     */
    public static void requireCanonicalSubjectPublicKeyInfo(byte[] encoded) throws IOException {
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(Objects.requireNonNull(encoded, "encoded"));
        if (!Arrays.equals(encoded, info.getEncoded(DER)) || info.getPublicKeyData().getPadBits() != 0) {
            throw new IllegalArgumentException("Noncanonical subject public key");
        }
    }

    /**
     * Requires a canonical PKCS#10 certification request with an octet-aligned signature.
     *
     * <p>The input must contain exactly one complete request, equal its DER
     * re-encoding and have zero unused signature bits. This is an encoding check:
     * it does not verify proof of possession, select a signature algorithm or
     * authorize any requested subject name or extension.
     *
     * @param encoded the complete PKCS#10 request; must not be {@code null}
     * @throws IOException if ASN.1 decoding or DER re-encoding fails
     * @throws IllegalArgumentException if the request structure is malformed,
     *     noncanonical or contains unused signature bits
     * @throws NullPointerException if {@code encoded} is {@code null}
     */
    public static void requireCanonicalCertificationRequest(byte[] encoded) throws IOException {
        CertificationRequest request = CertificationRequest.getInstance(
                ASN1Primitive.fromByteArray(Objects.requireNonNull(encoded, "encoded")));
        if (!Arrays.equals(encoded, request.getEncoded(DER)) || request.getSignature().getPadBits() != 0) {
            throw new IllegalArgumentException("Noncanonical certification request");
        }
    }

    /**
     * Validates a canonical SubjectPublicKeyInfo containing a finite P-384 public point.
     *
     * <p>The algorithm must be {@code id-ecPublicKey} with the exact named-curve
     * identifier {@code secp384r1}. Explicit curve parameters and other curves are
     * rejected. The public key must be an uncompressed 97-byte point with zero
     * unused bits, and the decoded point must be valid and not the point at infinity.
     * This does not establish possession of the corresponding private key.
     *
     * @param encoded the complete SubjectPublicKeyInfo DER; must not be {@code null}
     * @throws IOException if DER re-encoding fails
     * @throws IllegalArgumentException if the encoding, algorithm parameters or
     *     public point do not satisfy the fixed P-384 profile
     * @throws NullPointerException if {@code encoded} is {@code null}
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
     * Validates the representation and scalar bounds of an ECDSA P-384 signature.
     *
     * <p>The input must be an 8-through-104-byte canonical DER SEQUENCE containing
     * exactly two INTEGERs. Each scalar must be greater than zero and less than
     * the P-384 group order. This method does not check a message signature or
     * require a particular representative of the equivalent ECDSA signatures.
     *
     * @param encoded the complete DER signature; must not be {@code null}
     * @throws IOException if ASN.1 decoding or DER re-encoding fails
     * @throws IllegalArgumentException if the length, structure, canonical
     *     representation or scalar bounds are invalid
     * @throws NullPointerException if {@code encoded} is {@code null}
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
     * Encodes two integers in the DER representation used for an ECDSA signature.
     *
     * <p>The result contains {@code first} followed by {@code second}. No curve,
     * positivity or scalar-range checks are performed, so encoding succeeds for
     * values that are not valid ECDSA signature scalars.
     *
     * @param first the first INTEGER value; must not be {@code null}
     * @param second the second INTEGER value; must not be {@code null}
     * @return a new array containing the canonical DER SEQUENCE of the two INTEGERs
     * @throws IOException if DER encoding fails
     * @throws NullPointerException if either scalar is {@code null}
     */
    public static byte[] ecdsaSignature(BigInteger first, BigInteger second) throws IOException {
        return new DERSequence(new ASN1Integer[] {new ASN1Integer(Objects.requireNonNull(first, "first")),
                new ASN1Integer(Objects.requireNonNull(second, "second"))}).getEncoded(DER);
    }

    /**
     * Verifies a pure ML-DSA-87 signature using an explicitly empty FIPS 204 context.
     *
     * <p>The supplied message is passed directly to ML-DSA-87; this is not a
     * HashML-DSA operation. A fresh verification engine is configured with an
     * empty context for each call. The library's cryptographic providers are
     * initialized if necessary. Successful verification establishes only the
     * signature relationship, not the origin or trustworthiness of the key.
     *
     * @param key the verification public key accepted by the ML-DSA-87 engine;
     *     must not be {@code null}
     * @param message the message bytes; must not be {@code null}
     * @param signature the signature representation; must not be {@code null}
     * @return {@code true} if the engine accepts the signature for this message
     *     and empty context; {@code false} if verification completes negatively
     * @throws GeneralSecurityException if the engine or context cannot be
     *     configured, the key is unsuitable or signature processing fails
     * @throws NullPointerException if any argument is {@code null}
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
