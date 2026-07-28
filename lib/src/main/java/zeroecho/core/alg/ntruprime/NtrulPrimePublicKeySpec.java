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
package zeroecho.core.alg.ntruprime;

import java.util.Base64;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Specification wrapper for an encoded NTRU LPRime public key in X.509 format.
 *
 * <p>
 * {@code NtrulPrimePublicKeySpec} provides a type-safe holder for X.509
 * SubjectPublicKeyInfo bytes belonging to the NTRU LPRime KEM. It is immutable
 * and defensive copies are made on construction and retrieval.
 * </p>
 *
 * <h2>Usage</h2> Instances are typically created after parsing or receiving
 * encoded key data, and passed to an algorithm’s key builder to import a usable
 * {@link java.security.PublicKey}.
 *
 * <pre>{@code
 * // Wrap existing encoded public key
 * byte[] der = Files.readAllBytes(Paths.get("ntru-public.spki"));
 * NtrulPrimePublicKeySpec spec = new NtrulPrimePublicKeySpec(der);
 *
 * // Import via CryptoAlgorithms
 * PublicKey pub = session.keyBuilders().asymmetric().importPublic("NTRULPRime", spec);
 * }</pre>
 *
 * <h2>Serialization</h2> A lightweight marshaling format is supported via
 * {@link PairSeq}:
 * <ul>
 * <li>{@link #marshal(NtrulPrimePublicKeySpec)} produces a base64 string under
 * the key {@code "x509.b64"}.</li>
 * <li>{@link #unmarshal(PairSeq)} reconstructs a new spec instance from such a
 * sequence.</li>
 * </ul>
 *
 * @since 1.0
 */
public final class NtrulPrimePublicKeySpec implements AlgorithmKeySpec {

    private static final String X509_B64 = "x509.b64";
    private final byte[] x509;

    /**
     * Constructs a new public key specification from an X.509-encoded byte array.
     *
     * <p>
     * A defensive copy is made; the input array may be reused or modified without
     * affecting this instance.
     * </p>
     *
     * @param x509Der X.509 SubjectPublicKeyInfo bytes
     * @throws NullPointerException if {@code x509Der} is null
     */
    public NtrulPrimePublicKeySpec(byte[] x509Der) {
        this.x509 = Objects.requireNonNull(x509Der).clone();
    }

    /**
     * Returns a clone of the X.509-encoded public key bytes.
     *
     * @return copy of the encoded public key
     */
    public byte[] x509() {
        return x509.clone();
    }

    /**
     * Serializes this specification into a {@link PairSeq}.
     *
     * <p>
     * The result contains:
     * <ul>
     * <li>{@code type = "NtrulPrimePublicKeySpec"}</li>
     * <li>{@code x509.b64 = ...} base64-encoded key</li>
     * </ul>
     *
     * @param spec specification to marshal
     * @return serialized representation containing the base64-encoded key
     */
    public static PairSeq marshal(NtrulPrimePublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.x509);
        return PairSeq.of("type", "NtrulPrimePublicKeySpec", X509_B64, b64);
    }

    /**
     * Reconstructs a public key specification from a {@link PairSeq}.
     *
     * <p>
     * The sequence must contain an {@code x509.b64} entry; otherwise an
     * {@link IllegalArgumentException} is thrown.
     * </p>
     *
     * @param p serialized pair sequence produced by
     *          {@link #marshal(NtrulPrimePublicKeySpec)}
     * @return a new specification with the decoded X.509 bytes
     * @throws IllegalArgumentException if the required field is missing
     */
    public static NtrulPrimePublicKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (X509_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("NtrulPrimePublicKeySpec: missing x509.b64");
        }
        return new NtrulPrimePublicKeySpec(Base64.getDecoder().decode(b64));
    }

    /**
     * Returns a diagnostic string identifying this specification.
     *
     * <p>
     * The string includes the encoded key length but never the key material.
     * </p>
     *
     * @return a string such as {@code "NtrulPrimePublicKeySpec[len=1234]"}
     */
    @Override
    public String toString() {
        return "NtrulPrimePublicKeySpec[len=" + x509.length + "]";
    }
}
