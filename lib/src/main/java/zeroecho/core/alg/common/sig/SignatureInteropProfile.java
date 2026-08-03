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
package zeroecho.core.alg.common.sig;

import java.io.IOException;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

import zeroecho.core.spec.ContextSpec;

/**
 * Describes how a standard signature algorithm identifier maps to a concrete
 * ZeroEcho signature context.
 *
 * <p>
 * Standard external ecosystems such as X.509, PKCS#10, JCA, OpenSSL, or remote
 * APIs often identify signature algorithms with canonical names such as
 * {@code SHA256withRSA}, {@code SHA384withECDSA}, or {@code Ed25519}. ZeroEcho,
 * by contrast, separates the key algorithm from the per-operation
 * {@link ContextSpec}. This immutable helper bridges the two worlds by carrying
 * all information needed to:
 * </p>
 * <ul>
 * <li>import or compare the correct public-key algorithm,</li>
 * <li>create a ZeroEcho signature context with an explicit, deterministic
 * {@link ContextSpec}, and</li>
 * <li>translate signature bytes between an external representation and the
 * internal ZeroEcho representation when the two differ.</li>
 * </ul>
 *
 * <h2>Representation model</h2>
 * <p>
 * For RSA PKCS#1 v1.5, RSA-PSS, Ed25519, and Ed448, the external and internal
 * signature bytes are identical. ECDSA is different: X.509/JCA normally use
 * ASN.1 DER encoded {@code SEQUENCE { r, s }}, while ZeroEcho ECDSA contexts
 * use fixed-length IEEE P1363 bytes ({@code r || s}). The
 * {@link SignatureRepresentation} enum models this distinction explicitly.
 * </p>
 *
 * <h2>Security notes</h2>
 * <ul>
 * <li>This class never stores key material, plaintext, or signatures beyond the
 * arguments passed to conversion methods.</li>
 * <li>Conversion methods validate structure and length to prevent silent format
 * confusion.</li>
 * <li>The carried {@link ContextSpec} must be treated as part of algorithm
 * semantics, not as an optional hint.</li>
 * </ul>
 */
public final class SignatureInteropProfile {
    private static final int DER_SEQUENCE_TAG = 0x30;
    private static final int DER_INTEGER_TAG = 0x02;
    private static final int DER_LONG_FORM_BIT = 0x80;

    /**
     * Signature byte representation bridging policy.
     */
    public enum SignatureRepresentation {
        /**
         * External and internal signature bytes are identical.
         */
        IDENTITY,
        /**
         * External bytes use ASN.1 DER ECDSA encoding while ZeroEcho uses fixed-size
         * IEEE P1363 bytes internally.
         */
        ECDSA_DER_EXTERNAL_P1363_INTERNAL
    }

    private final String requestedAlgorithmId;
    private final String keyAlgorithmId;
    private final String contextAlgorithmId;
    private final ContextSpec contextSpec;
    private final SignatureRepresentation signatureRepresentation;
    private final int internalSignatureLength;

    /**
     * Creates a profile.
     *
     * @param requestedAlgorithmId    caller-visible algorithm identifier such as
     *                                {@code SHA256withRSA}
     * @param keyAlgorithmId          ZeroEcho key algorithm identifier used for key
     *                                import and matching, such as {@code RSA}
     * @param contextAlgorithmId      ZeroEcho context algorithm identifier used
     *                                with
     *                                {@code ZeroEchoSession.createContext(...)}
     * @param contextSpec             explicit ZeroEcho context specification
     * @param signatureRepresentation signature representation bridge between
     *                                external bytes and internal ZeroEcho bytes
     * @param internalSignatureLength fixed internal signature length in bytes when
     *                                representation conversion requires it; set to
     *                                {@code 0} for identity representations
     */
    public SignatureInteropProfile(String requestedAlgorithmId, String keyAlgorithmId, String contextAlgorithmId,
            ContextSpec contextSpec, SignatureRepresentation signatureRepresentation, int internalSignatureLength) {
        this.requestedAlgorithmId = requireNonBlank(requestedAlgorithmId, "requestedAlgorithmId");
        this.keyAlgorithmId = requireNonBlank(keyAlgorithmId, "keyAlgorithmId");
        this.contextAlgorithmId = requireNonBlank(contextAlgorithmId, "contextAlgorithmId");
        this.contextSpec = Objects.requireNonNull(contextSpec, "contextSpec");
        this.signatureRepresentation = Objects.requireNonNull(signatureRepresentation, "signatureRepresentation");
        if (signatureRepresentation == SignatureRepresentation.IDENTITY && internalSignatureLength != 0) {
            throw new IllegalArgumentException("Identity representation must not declare internal signature length");
        }
        if (signatureRepresentation != SignatureRepresentation.IDENTITY && internalSignatureLength <= 0) {
            throw new IllegalArgumentException(
                    "Converted signature representation requires positive internal signature length");
        }
        this.internalSignatureLength = internalSignatureLength;
    }

    /**
     * Returns the caller-visible signature algorithm identifier.
     *
     * @return canonical requested algorithm id
     */
    public String requestedAlgorithmId() {
        return requestedAlgorithmId;
    }

    /**
     * Returns the ZeroEcho key algorithm identifier.
     *
     * @return key algorithm id used for key import and key-class matching
     */
    public String keyAlgorithmId() {
        return keyAlgorithmId;
    }

    /**
     * Returns the ZeroEcho context algorithm identifier.
     *
     * @return context algorithm id used to create signature contexts
     */
    public String contextAlgorithmId() {
        return contextAlgorithmId;
    }

    /**
     * Returns the explicit ZeroEcho context specification.
     *
     * @return non-null signature context spec
     */
    public ContextSpec contextSpec() {
        return contextSpec;
    }

    /**
     * Returns the representation bridge used for signature bytes.
     *
     * @return representation policy
     */
    public SignatureRepresentation signatureRepresentation() {
        return signatureRepresentation;
    }

    /**
     * Converts external signature bytes into the internal ZeroEcho representation.
     *
     * @param signature external signature bytes
     * @return internal signature bytes suitable for ZeroEcho verification contexts
     * @throws IllegalArgumentException if the supplied bytes do not match the
     *                                  expected external representation
     */
    public byte[] externalToInternalSignature(byte[] signature) {
        Objects.requireNonNull(signature, "signature");
        if (signatureRepresentation == SignatureRepresentation.IDENTITY) {
            return signature.clone();
        }
        return ecdsaDerToP1363(signature, internalSignatureLength);
    }

    /**
     * Converts internal ZeroEcho signature bytes into the external representation.
     *
     * @param signature internal ZeroEcho signature bytes
     * @return external signature bytes suitable for X.509, PKCS#10, or JCA callers
     * @throws IOException              if DER encoding fails
     * @throws IllegalArgumentException if the supplied bytes do not match the
     *                                  expected internal representation
     */
    public byte[] internalToExternalSignature(byte[] signature) throws IOException {
        Objects.requireNonNull(signature, "signature");
        if (signatureRepresentation == SignatureRepresentation.IDENTITY) {
            return signature.clone();
        }
        return ecdsaP1363ToDer(signature, internalSignatureLength);
    }

    private static byte[] ecdsaDerToP1363(byte[] der, int fixedLength) {
        if ((fixedLength & 1) != 0 || der.length > fixedLength + 8 || der.length < 8) {
            throw new IllegalArgumentException("Invalid ECDSA DER signature length");
        }
        int coordinateLength = fixedLength / 2;
        int offset = 0;
        if (Byte.toUnsignedInt(der[offset++]) != DER_SEQUENCE_TAG) {
            throw new IllegalArgumentException("ECDSA DER signature must be a sequence");
        }
        long sequenceLength = readDerLength(der, offset);
        offset = (int) sequenceLength;
        int sequenceEnd = Math.addExact(offset, (int) (sequenceLength >>> Integer.SIZE));
        if (sequenceEnd != der.length) {
            throw new IllegalArgumentException("ECDSA DER signature contains trailing or truncated data");
        }
        byte[] out = new byte[fixedLength];
        offset = readPositiveInteger(der, offset, sequenceEnd, out, 0, coordinateLength);
        offset = readPositiveInteger(der, offset, sequenceEnd, out, coordinateLength, coordinateLength);
        if (offset != sequenceEnd) {
            throw new IllegalArgumentException("ECDSA DER signature must contain exactly two integers");
        }
        return out;
    }

    /* High 32 bits carry the decoded length; low 32 bits carry the next offset. */
    private static long readDerLength(byte[] der, int offset) {
        int cursor = offset;
        if (cursor >= der.length) {
            throw new IllegalArgumentException("Truncated ECDSA DER length");
        }
        int first = Byte.toUnsignedInt(der[cursor++]);
        int length;
        if (first < DER_LONG_FORM_BIT) {
            length = first;
        } else {
            int octets = first & 0x7f;
            if (octets == 0 || octets > 2 || cursor + octets > der.length
                    || Byte.toUnsignedInt(der[cursor]) == 0) {
                throw new IllegalArgumentException("Non-canonical ECDSA DER length");
            }
            length = 0;
            for (int index = 0; index < octets; index++) {
                length = (length << Byte.SIZE) | Byte.toUnsignedInt(der[cursor++]);
            }
            if (length < DER_LONG_FORM_BIT) {
                throw new IllegalArgumentException("Non-canonical ECDSA DER length");
            }
        }
        return ((long) length << Integer.SIZE) | Integer.toUnsignedLong(cursor);
    }

    private static int readPositiveInteger(byte[] der, int offset, int limit, byte[] target, int targetOffset,
            int width) {
        int cursor = offset;
        if (cursor >= limit || Byte.toUnsignedInt(der[cursor++]) != DER_INTEGER_TAG) {
            throw new IllegalArgumentException("ECDSA DER signature must contain INTEGER values");
        }
        long encodedLength = readDerLength(der, cursor);
        cursor = (int) encodedLength;
        int length = (int) (encodedLength >>> Integer.SIZE);
        if (length == 0 || length > width + 1 || cursor > limit - length) {
            throw new IllegalArgumentException("Invalid ECDSA DER integer length");
        }
        int first = Byte.toUnsignedInt(der[cursor]);
        if (first == 0) {
            if (length == 1 || (der[cursor + 1] & DER_LONG_FORM_BIT) == 0) {
                throw new IllegalArgumentException("ECDSA DER integer must be positive, nonzero, and minimal");
            }
            cursor++;
            length--;
        } else if ((first & DER_LONG_FORM_BIT) != 0) {
            throw new IllegalArgumentException("ECDSA DER integer must be positive");
        }
        if (length > width) {
            throw new IllegalArgumentException("ECDSA integer does not fit into fixed P1363 width");
        }
        System.arraycopy(der, cursor, target, targetOffset + width - length, length);
        return cursor + length;
    }

    private static byte[] ecdsaP1363ToDer(byte[] p1363, int fixedLength) throws IOException {
        if (p1363.length != fixedLength) {
            throw new IllegalArgumentException("Unexpected P1363 signature length: " + p1363.length);
        }
        int coordinateLength = fixedLength / 2;
        byte[] r = new byte[coordinateLength];
        byte[] s = new byte[coordinateLength];
        System.arraycopy(p1363, 0, r, 0, coordinateLength);
        System.arraycopy(p1363, coordinateLength, s, 0, coordinateLength);

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(new java.math.BigInteger(1, r)));
        vector.add(new ASN1Integer(new java.math.BigInteger(1, s)));
        return new DERSequence(vector).getEncoded(ASN1Encoding.DER);
    }

    private static String requireNonBlank(String value, String label) {
        Objects.requireNonNull(value, label);
        if (value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
        return value;
    }
}
