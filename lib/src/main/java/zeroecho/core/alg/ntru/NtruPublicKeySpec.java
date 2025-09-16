/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core.alg.ntru;

import java.util.Base64;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * NtruPublicKeySpec holds an X.509 SubjectPublicKeyInfo encoded NTRU public key
 * and supports a simple marshal/unmarshal form.
 *
 * <p>
 * Instances are immutable. The byte array provided to the constructor is
 * defensively copied and {@link #x509()} returns a fresh clone on each call.
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Construct from existing X.509 bytes
 * byte[] x509Der = Files.readAllBytes(Path.of("ntru-public.der"));
 * NtruPublicKeySpec spec = new NtruPublicKeySpec(x509Der);
 *
 * // Import into JCA (example provider alias shown)
 * KeyFactory kf = KeyFactory.getInstance("NTRU", "BCPQC");
 * PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(spec.x509()));
 *
 * // Marshal to a compact name-value form (Base64 without padding)
 * PairSeq serialized = NtruPublicKeySpec.marshal(spec);
 *
 * // Later or elsewhere, reconstruct the spec
 * NtruPublicKeySpec restored = NtruPublicKeySpec.unmarshal(serialized);
 * }</pre>
 *
 * @since 1.0
 */
public final class NtruPublicKeySpec implements AlgorithmKeySpec {

    private static final String X509_B64 = "x509.b64";
    private final byte[] x509;

    /**
     * Creates a new specification from X.509 SubjectPublicKeyInfo encoded bytes.
     *
     * <p>
     * The input array is not retained. A defensive copy is made and stored.
     * </p>
     *
     * @param x509Der X.509 DER bytes of the NTRU public key, must not be null
     * @throws NullPointerException if {@code x509Der} is null
     */
    public NtruPublicKeySpec(byte[] x509Der) {
        this.x509 = Objects.requireNonNull(x509Der, "x509Der").clone();
    }

    /**
     * Returns a copy of the X.509-encoded public key.
     *
     * <p>
     * The returned array is a fresh clone. Callers may modify it without affecting
     * the spec.
     * </p>
     *
     * @return a new byte array containing the X.509 DER encoding
     */
    public byte[] x509() {
        return x509.clone();
    }

    /**
     * Serializes this specification into a simple name-value sequence.
     *
     * <p>
     * The output contains:
     * <ul>
     * <li>{@code "type"} set to {@code "NtruPublicKey"} for identification,
     * and</li>
     * <li>{@code "x509.b64"} containing the X.509 bytes encoded with Base64 without
     * padding.</li>
     * </ul>
     * This format is suitable for lightweight persistence or interchange where a
     * compact textual representation is preferred.
     *
     * @param spec the specification to serialize, must not be null
     * @return a {@code PairSeq} carrying the serialized fields
     * @throws NullPointerException if {@code spec} is null
     */
    public static PairSeq marshal(NtruPublicKeySpec spec) {
        String b64 = Base64.getEncoder().withoutPadding().encodeToString(spec.x509);
        return PairSeq.of("type", "NtruPublicKey", X509_B64, b64);
    }

    /**
     * Deserializes a specification from a name-value sequence produced by
     * {@link #marshal(NtruPublicKeySpec)}.
     *
     * <p>
     * Fields not recognized by this implementation are ignored to allow forward
     * compatibility. The field {@code "x509.b64"} is required and must contain
     * Base64 (no padding) of the X.509 bytes.
     * </p>
     *
     * @param p the sequence to read
     * @return a new specification carrying the decoded X.509 bytes
     * @throws IllegalArgumentException if the required {@code "x509.b64"} field is
     *                                  absent
     * @throws NullPointerException     if {@code p} is null
     */
    public static NtruPublicKeySpec unmarshal(PairSeq p) {
        String x509b64 = null;
        PairSeq.Cursor cur = p.cursor();
        while (cur.next()) {
            String k = cur.key();
            String v = cur.value();
            if (X509_B64.equals(k)) {
                x509b64 = v;
            }
        }
        if (x509b64 == null) {
            throw new IllegalArgumentException("NtruPublicKeySpec: missing 'x509.b64'");
        }
        return new NtruPublicKeySpec(Base64.getDecoder().decode(x509b64));
    }

    /**
     * Returns a short diagnostic string including the encoded length.
     *
     * @return a human-readable form such as {@code NtruPublicKeySpec[len=...]}
     */
    @Override
    public String toString() {
        return "NtruPublicKeySpec[len=" + x509.length + "]";
    }
}
