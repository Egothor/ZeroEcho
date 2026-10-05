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
package zeroecho.pki.impl.hybrid;

import java.util.Map;

import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.CertificateExtension;
import zeroecho.pkix.Pkix;

/**
 * DER encoding helpers for X.509 2019 Amendment 2 alternative-signature extensions.
 *
 * <p>
 * Three extensions are defined by the specification:
 * </p>
 * <ul>
 * <li>SubjectAltPublicKeyInfo (OID 2.5.29.72) — carries the alternative public key</li>
 * <li>AltSignatureAlgorithm (OID 2.5.29.73) — identifies the alternative signature algorithm</li>
 * <li>AltSignatureValue (OID 2.5.29.74) — carries the alternative signature bits</li>
 * </ul>
 *
 * <p>
 * All three extensions are non-critical per the draft specification.
 * </p>
 *
 * <p>
 * The {@code derValue} produced by each factory method is the raw content of the
 * {@code extnValue} OCTET STRING (not the OCTET STRING wrapper itself), matching
 * the contract of {@link CertificateExtension}.
 * </p>
 */
public final class AltSignatureExtensions {
    private static final int OCTET_STRING_TAG = 4;
    private static final int LONG_FORM_THRESHOLD = 0x80;
    private static final int UNSIGNED_BYTE_MAX = 0xff;
    private static final int UNSIGNED_SHORT_MAX = 0xffff;

    /** OID for SubjectAltPublicKeyInfo (id-ce-subjectAltPublicKeyInfo). */
    public static final String OID_SUBJECT_ALT_PUBLIC_KEY_INFO = "2.5.29.72"; // NOPMD LongVariable, AvoidUsingHardCodedIP - Exported descriptive OID identifier preserves consumer API. Standardized X.509 extension OID, not a network address.

    /** OID for AltSignatureAlgorithm (id-ce-altSignatureAlgorithm). */
    public static final String OID_ALT_SIGNATURE_ALGORITHM = "2.5.29.73"; // NOPMD AvoidUsingHardCodedIP - Standardized X.509 extension OID, not a network address.

    /** OID for AltSignatureValue (id-ce-altSignatureValue). */
    public static final String OID_ALT_SIGNATURE_VALUE = "2.5.29.74"; // NOPMD AvoidUsingHardCodedIP - Standardized X.509 extension OID, not a network address.

    /** Fixed raw signature length for ML-DSA-44 (FIPS 204). */
    public static final int ML_DSA_44_SIGNATURE_LENGTH = 2420;

    /** Fixed raw signature length for ML-DSA-65 (FIPS 204). */
    public static final int ML_DSA_65_SIGNATURE_LENGTH = 3309;

    /** Fixed raw signature length for ML-DSA-87 (FIPS 204). */
    public static final int ML_DSA_87_SIGNATURE_LENGTH = 4627;

    private static final Map<String, Integer> FIXED_SIGNATURE_LENGTHS = Map.of(
            "ml-dsa-44", ML_DSA_44_SIGNATURE_LENGTH,
            "ml-dsa-65", ML_DSA_65_SIGNATURE_LENGTH,
            "ml-dsa-87", ML_DSA_87_SIGNATURE_LENGTH);

    private AltSignatureExtensions() {
    }

    /**
     * Creates a SubjectAltPublicKeyInfo extension from DER-encoded SPKI bytes.
     *
     * <p>
     * The SPKI bytes are already a {@code SubjectPublicKeyInfo SEQUENCE} and are
     * placed verbatim as the extension value.
     * </p>
     *
     * @param spkiDer DER-encoded {@code SubjectPublicKeyInfo} bytes
     * @return non-critical extension with the alt public key
     */
    public static CertificateExtension subjectAltPublicKeyInfo(byte[] spkiDer) {
        return new CertificateExtension(OID_SUBJECT_ALT_PUBLIC_KEY_INFO, false, spkiDer);
    }

    /**
     * Creates an AltSignatureAlgorithm extension from a ZeroEcho {@link AlgorithmIdentifier}.
     *
     * <p>
     * The extension value is the DER encoding of the {@code AlgorithmIdentifier SEQUENCE}.
     * {@link Pkix#encodeAlgorithmIdentifier(AlgorithmIdentifier)} is used for the encoding.
     * </p>
     *
     * @param algorithmIdentifier the alternative signature algorithm identifier
     * @return non-critical extension with the alt signature algorithm
     */
    public static CertificateExtension altSignatureAlgorithm(AlgorithmIdentifier algorithmIdentifier) {
        byte[] der = Pkix.encodeAlgorithmIdentifier(algorithmIdentifier);
        return new CertificateExtension(OID_ALT_SIGNATURE_ALGORITHM, false, der);
    }

    /**
     * Creates an AltSignatureValue extension from raw signature bytes.
     *
     * <p>
     * The extension value is a {@code BIT STRING} wrapping the raw signature bytes.
     * A leading zero byte is prepended to indicate zero unused bits per the DER
     * BIT STRING encoding rules.
     * </p>
     *
     * @param rawSignature raw signature bytes produced by the alt signing operation
     * @return non-critical extension with the alt signature value
     */
    public static CertificateExtension altSignatureValue(byte[] rawSignature) {
        byte[] bitString = encodeBitString(rawSignature);
        return new CertificateExtension(OID_ALT_SIGNATURE_VALUE, false, bitString);
    }

    /**
     * Creates a zero-valued extension for legacy callers and diagnostic fixtures.
     *
     * <p>
     * This value must never be included in alternative-signature input. The
     * standardized pre-TBS omits the complete AltSignatureValue extension and
     * the TBSCertificate signature field; it requires no advance signature size.
     * </p>
     *
     * @param signatureLength expected raw signature length in bytes
     * @return non-critical placeholder extension
     */
    public static CertificateExtension altSignatureValuePlaceholder(int signatureLength) {
        return altSignatureValue(new byte[signatureLength]);
    }

    /**
     * Extracts the canonical DER value of a required certificate extension.
     * @param certificate parsed certificate
     * @param oid required extension OID
     * @return newly allocated inner DER value
     * @throws java.io.IOException if the extension is absent or malformed
     */
    public static byte[] requiredValue(java.security.cert.X509Certificate certificate, String oid)
            throws java.io.IOException {
        byte[] wrapped = certificate.getExtensionValue(oid);
        if (wrapped == null) { throw new java.io.IOException("Required alternative extension is absent"); }
        new zeroecho.pki.impl.framework.x509.StreamingDerReader().validate(wrapped,
                1_048_576);
        if (wrapped[0] != OCTET_STRING_TAG) { throw new java.io.IOException("Alternative extension wrapper is invalid"); }
        int offset = 2;
        if ((wrapped[1] & 0x80) != 0) { offset += wrapped[1] & 0x7f; }
        return java.util.Arrays.copyOfRange(wrapped, offset, wrapped.length);
    }

    /**
     * Returns the fixed raw signature length for a known PQC algorithm by searching the
     * canonical algorithm identifier string for known family name substrings.
     *
     * @param canonicalAlgorithmId canonical algorithm identity string
     * @return fixed signature length in bytes, or {@code -1} if the algorithm is unknown
     */
    public static int fixedSignatureLength(String canonicalAlgorithmId) {
        if (canonicalAlgorithmId == null) {
            return -1;
        }
        for (Map.Entry<String, Integer> entry : FIXED_SIGNATURE_LENGTHS.entrySet()) {
            if (canonicalAlgorithmId.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        return -1;
    }

    // ---- DER BIT STRING encoding (no BC dependency) --------------------------

    /* default */ static byte[] encodeBitString(byte[] content) {
        // BIT STRING: tag 0x03, length(1 + content.length), 0x00 unused bits, content
        byte[] payload = new byte[content.length + 1];
        payload[0] = 0x00; // zero unused bits
        System.arraycopy(content, 0, payload, 1, content.length);
        return encodeTlv(0x03, payload);
    }

    /* default */ static byte[] encodeTlv(int tag, byte[] value) {
        byte[] length = encodeLength(value.length);
        byte[] result = new byte[1 + length.length + value.length];
        result[0] = (byte) tag;
        System.arraycopy(length, 0, result, 1, length.length);
        System.arraycopy(value, 0, result, 1 + length.length, value.length);
        return result;
    }

    /* default */ static byte[] encodeLength(int length) {
        if (length < LONG_FORM_THRESHOLD) {
            return new byte[] { (byte) length };
        }
        if (length <= UNSIGNED_BYTE_MAX) {
            return new byte[] { (byte) 0x81, (byte) length };
        }
        if (length <= UNSIGNED_SHORT_MAX) {
            return new byte[] { (byte) 0x82, (byte) (length >> 8), (byte) length };
        }
        return new byte[] { (byte) 0x83, (byte) (length >> 16), (byte) (length >> 8), (byte) length };
    }
}
