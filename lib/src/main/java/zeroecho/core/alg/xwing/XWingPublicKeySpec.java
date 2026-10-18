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
package zeroecho.core.alg.xwing;

import java.util.Base64;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Encoded representation of an X-Wing public key in raw format.
 *
 * <p>
 * X-Wing uses a raw (non-DER) encoding for both public and private keys, as
 * BouncyCastle 1.86 has no JCA/JCE provider binding for X-Wing. The raw
 * encoding is the 1184-byte ML-KEM-768 public key followed by the 32-byte
 * X25519 public key (1216 bytes total).
 * </p>
 *
 * @since 1.0
 */
public final class XWingPublicKeySpec implements AlgorithmKeySpec {

    private static final String RAW_B64 = "raw.b64";
    /* default */ static final int RAW_LENGTH = 1216;
    private final byte[] raw;

    /**
     * Constructs a new spec from raw X-Wing public key bytes.
     *
     * @param raw raw-encoded public key bytes
     * @throws NullPointerException if {@code raw} is null
     * @throws IllegalArgumentException if the encoding is not exactly 1216 bytes
     */
    public XWingPublicKeySpec(byte[] raw) {
        Objects.requireNonNull(raw, "raw");
        if (raw.length != RAW_LENGTH) {
            throw new IllegalArgumentException("X-Wing public key must contain exactly 1216 bytes");
        }
        this.raw = Objects.requireNonNull(raw).clone();
    }

    /**
     * Returns a defensive copy of the raw public key bytes.
     *
     * @return raw public key bytes
     */
    public byte[] raw() {
        return raw.clone();
    }

    /**
     * Serializes this spec to a {@link PairSeq}.
     *
     * @param spec the spec to serialize
     * @return serialized representation
     */
    public static PairSeq marshal(XWingPublicKeySpec spec) {
        return PairSeq.of("type", "XWingPublicKeySpec", RAW_B64,
                Base64.getEncoder().withoutPadding().encodeToString(spec.raw));
    }

    /**
     * Deserializes a spec from a {@link PairSeq}.
     *
     * @param p serialized representation
     * @return reconstructed spec
     * @throws IllegalArgumentException if required field is missing
     */
    public static XWingPublicKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (RAW_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("XWingPublicKeySpec: missing raw.b64");
        }
        if (b64.length() != 1622 && b64.length() != 1624) {
            throw new IllegalArgumentException("XWingPublicKeySpec: invalid encoded length");
        }
        return new XWingPublicKeySpec(Base64.getDecoder().decode(b64));
    }

    @Override
    public String toString() {
        return "XWingPublicKeySpec[len=" + raw.length + "]";
    }
}
