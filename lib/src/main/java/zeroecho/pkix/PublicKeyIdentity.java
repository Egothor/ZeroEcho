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

package zeroecho.pkix;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Immutable mathematical public-key identity for enrollment separation checks.
 * Supports rsaEncryption keys with absent or NULL parameters and named P-256,
 * P-384 and P-521 keys with standard compressed or uncompressed SEC1 points.
 * PSS-restricted RSA, explicit/implicit EC domains and other algorithms are
 * rejected. This identity does not authorize a key, enforce a security strength,
 * or replace verification of its original encoding and algorithm restrictions.
 *
 * <p>The canonical commitment hashes a canonical SPKI: RSA uses DER NULL
 * parameters; EC uses its named-curve OID and uncompressed point. The finite
 * equivalent-encoding commitments are solely for exclusion against existing
 * hash-only mappings. They must never broaden authentication matching.</p>
 *
 * <p>Instances are thread-safe. Input is bounded at 16 KiB. Parsing and retained
 * storage are linear in the input size, plus bounded curve-point validation.</p>
 */
public final class PublicKeyIdentity {
    /** Maximum accepted encoded SPKI size. */
    public static final int MAXIMUM_SPKI_BYTES = 16 * 1024;
    private final byte[] canonical;
    private final String commitment;
    private final Set<String> equivalentCommitments;

    private PublicKeyIdentity(byte[] canonical, byte[] alternative) {
        this.canonical = canonical;
        commitment = digest(canonical);
        SortedSet<String> hashes = new TreeSet<>();
        hashes.add(commitment);
        hashes.add(digest(alternative));
        equivalentCommitments = java.util.Collections.unmodifiableSortedSet(hashes);
    }

    /**
     * Parses and validates one supported mathematical key without retaining input.
     * @param encoded exact DER SubjectPublicKeyInfo, defensively copied
     * @return normalized immutable key identity
     * @throws IllegalArgumentException if input is null, oversized, malformed or unsupported
     */
    public static PublicKeyIdentity fromSubjectPublicKeyInfo(byte[] encoded) {
        if (encoded == null || encoded.length == 0 || encoded.length > MAXIMUM_SPKI_BYTES) {
            throw invalid();
        }
        byte[] snapshot = encoded.clone();
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(snapshot));
            if (!Arrays.equals(snapshot, spki.getEncoded(ASN1Encoding.DER)) || spki.getPublicKeyData().getPadBits() != 0) {
                throw invalid();
            }
            ASN1ObjectIdentifier algorithm = spki.getAlgorithm().getAlgorithm();
            if (PKCSObjectIdentifiers.rsaEncryption.equals(algorithm)) {
                return rsa(spki);
            }
            if (X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm)) {
                return ec(spki);
            }
            throw invalid();
        } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Invalid input is rejected here and normalized at the protocol boundary; exceptions do not represent successful control flow.
            throw invalid(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    private static PublicKeyIdentity rsa(SubjectPublicKeyInfo spki) throws IOException {
        if (spki.getAlgorithm().getParameters() != null
                && !(spki.getAlgorithm().getParameters().toASN1Primitive() instanceof ASN1Null)) {
            throw invalid();
        }
        RSAPublicKey key = RSAPublicKey.getInstance(spki.parsePublicKey());
        byte[] keyDer = key.getEncoded(ASN1Encoding.DER);
        if (!Arrays.equals(keyDer, spki.getPublicKeyData().getOctets())) {
            throw invalid();
        }
        BigInteger modulus = key.getModulus();
        BigInteger exponent = key.getPublicExponent();
        if (modulus.compareTo(BigInteger.ONE) <= 0 || !modulus.testBit(0) || modulus.bitLength() > 16_384
                || exponent.compareTo(BigInteger.valueOf(3)) < 0 || !exponent.testBit(0)
                || exponent.compareTo(modulus) >= 0) {
            throw invalid();
        }
        byte[] canonical = new SubjectPublicKeyInfo(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), key).getEncoded(ASN1Encoding.DER);
        byte[] absent = new SubjectPublicKeyInfo(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                PKCSObjectIdentifiers.rsaEncryption), key).getEncoded(ASN1Encoding.DER);
        return new PublicKeyIdentity(canonical, absent);
    }

    private static PublicKeyIdentity ec(SubjectPublicKeyInfo spki) throws IOException {
        if (!(spki.getAlgorithm().getParameters() instanceof ASN1ObjectIdentifier curve)) {
            throw invalid();
        }
        if (!SECObjectIdentifiers.secp256r1.equals(curve) && !SECObjectIdentifiers.secp384r1.equals(curve)
                && !SECObjectIdentifiers.secp521r1.equals(curve)) {
            throw invalid();
        }
        X9ECParameters parameters = SECNamedCurves.getByOID(curve);
        byte[] encodedPoint = spki.getPublicKeyData().getOctets();
        int width = (parameters.getCurve().getFieldSize() + 7) / 8;
        if (encodedPoint.length == 0 || !((encodedPoint[0] == 2 || encodedPoint[0] == 3)
                && encodedPoint.length == width + 1 || encodedPoint[0] == 4 && encodedPoint.length == 2 * width + 1)) {
            throw invalid();
        }
        ECPoint point = parameters.getCurve().decodePoint(encodedPoint).normalize();
        if (point.isInfinity() || !point.isValid()) {
            throw invalid();
        }
        org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithm =
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curve);
        return new PublicKeyIdentity(new SubjectPublicKeyInfo(algorithm, point.getEncoded(false)).getEncoded(ASN1Encoding.DER),
                new SubjectPublicKeyInfo(algorithm, point.getEncoded(true)).getEncoded(ASN1Encoding.DER));
    }

    /**
     * Returns the canonical encoding used solely for identity comparison.
     * @return a defensive copy of the canonical identity-only SPKI
     */
    public byte[] canonicalSubjectPublicKeyInfo() { return canonical.clone(); }

    /**
     * Returns the stable mathematical key commitment.
     * @return lowercase SHA-256 of the canonical SPKI, never an authentication grant
     */
    public String canonicalSha256() { return commitment; }

    /**
     * Returns immutable, sorted legacy SPKI hashes of both supported encodings.
     * These hashes are exclusively for conservative alias exclusion. Certificate
     * hashes and issuer/serial hashes occupy separate commitment domains.
     * @return finite equivalent-encoding hashes
     */
    public Set<String> equivalentSubjectPublicKeyInfoSha256() { return equivalentCommitments; }

    /** @return redacted diagnostic description */
    @Override public String toString() { return "PublicKeyIdentity[redacted]"; }

    private static String digest(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Public key identity is malformed or unsupported");
    }
}
