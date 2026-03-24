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
package zeroecho.sdk.hybrid.kex;

import java.nio.charset.StandardCharsets;

/**
 * Profile for a hybrid key exchange (KEX) composition.
 *
 * <p>
 * A hybrid KEX combines two independently derived secrets:
 * </p>
 * <ul>
 * <li>a classic (pre-quantum) agreement secret produced by an
 * {@code AgreementContext} (e.g. X25519, ECDH, DH), and</li>
 * <li>a post-quantum agreement secret produced by a
 * {@code MessageAgreementContext} (typically a KEM-style agreement such as
 * ML-KEM).</li>
 * </ul>
 *
 * <p>
 * The two secrets are combined using HKDF-SHA256 (RFC 5869) to produce a final
 * keying material byte array of a caller-selected length. The default label is
 * intended to make cross-protocol misuse harder by providing an explicit domain
 * separator.
 * </p>
 *
 * <h2>Notes</h2>
 * <ul>
 * <li>This profile does not store algorithm identifiers on purpose; it focuses
 * on KDF binding and output size. Algorithm selection happens in higher layers
 * when constructing the two underlying contexts.</li>
 * <li>{@code salt} is optional; if null/empty, HKDF uses a zero-filled salt as
 * per RFC 5869 and {@link zeroecho.sdk.util.Kdf}.</li>
 * </ul>
 *
 * @param hkdfSalt    optional HKDF salt (defensively copied), may be
 *                    {@code null}
 * @param hkdfInfo    optional HKDF info/label (defensively copied), may be
 *                    {@code null}
 * @param outLenBytes length of derived keying material in bytes (1..8160)
 *
 * @since 1.0
 */
public record HybridKexProfile(byte[] hkdfSalt, byte[] hkdfInfo, int outLenBytes) {

    /**
     * Default HKDF label used when the caller does not provide an explicit one.
     */
    public static final byte[] DEFAULT_INFO = "ZeroEcho-HybridKEX".getBytes(StandardCharsets.US_ASCII);

    /**
     * Constructs a profile with a default HKDF info label.
     *
     * @param outLenBytes output length in bytes
     * @return profile with default HKDF info label and no explicit salt
     */
    public static HybridKexProfile defaultProfile(int outLenBytes) {
        return new HybridKexProfile(null, DEFAULT_INFO, outLenBytes);
    }

    /**
     * Canonical constructor with validation and defensive copies.
     *
     * @param hkdfSalt    optional HKDF salt
     * @param hkdfInfo    optional HKDF info/label
     * @param outLenBytes output length in bytes
     */
    public HybridKexProfile {
        if (outLenBytes < 1 || outLenBytes > 255 * 32) {
            throw new IllegalArgumentException("outLenBytes must be in range 1.." + (255 * 32));
        }
        hkdfSalt = (hkdfSalt == null) ? null : hkdfSalt.clone();
        hkdfInfo = (hkdfInfo == null) ? null : hkdfInfo.clone();
    }
}
