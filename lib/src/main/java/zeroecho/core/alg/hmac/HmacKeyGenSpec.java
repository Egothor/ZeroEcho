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
package zeroecho.core.alg.hmac;

import java.util.Objects;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>Specification for HMAC key generation</h2>
 *
 * {@code HmacKeyGenSpec} describes the parameters required to generate a secret
 * key for a Hash-based Message Authentication Code (HMAC) algorithm. It defines
 * the target MAC algorithm name and the key size in bits.
 *
 * <h2>Constraints</h2>
 * <ul>
 * <li>The {@code macName} must correspond to a supported HMAC variant such as
 * {@code "HmacSHA256"}, {@code "HmacSHA384"}, or {@code "HmacSHA512"}.</li>
 * <li>The key size must be a positive multiple of 8 (i.e., full-byte
 * lengths).</li>
 * </ul>
 *
 * <h2>Usage</h2> Typical usage is to construct a spec with a given digest
 * family and key size, and then pass it to a registered
 * {@link zeroecho.core.spi.SymmetricKeyGenerator}:
 *
 * <pre>{@code
 * // Generate a 256-bit key for HMAC-SHA256
 * HmacKeyGenSpec spec = HmacKeyGenSpec.sha256(256);
 * SecretKey key = session.keyBuilders().symmetric().generate("HMAC", spec);
 * }</pre>
 *
 * <h2>Defaults</h2> Convenience static factories are provided for the most
 * common variants:
 * <ul>
 * <li>{@link #sha256(int)} - HMAC-SHA256 with a caller-specified bit
 * length</li>
 * <li>{@link #sha384(int)} - HMAC-SHA384 with a caller-specified bit
 * length</li>
 * <li>{@link #sha512(int)} - HMAC-SHA512 with a caller-specified bit
 * length</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Recommended key size is at least equal to the output size of the
 * underlying hash function (e.g., 256 bits for SHA-256).</li>
 * <li>Keys should always be generated with a strong randomness source.</li>
 * <li>Do not reuse HMAC keys across different digest families.</li>
 * </ul>
 *
 * @since 1.0
 */
public final class HmacKeyGenSpec implements AlgorithmKeySpec, Describable {
    private final String macName;
    private final int keySizeBits;

    /**
     * Constructs a new specification for HMAC key generation.
     *
     * @param macName     canonical name of the target HMAC algorithm (e.g.,
     *                    {@code "HmacSHA256"})
     * @param keySizeBits desired key size in bits; must be a positive multiple of 8
     * @throws NullPointerException     if {@code macName} is {@code null}
     * @throws IllegalArgumentException if {@code keySizeBits} is non-positive or
     *                                  not divisible by 8
     */
    public HmacKeyGenSpec(String macName, int keySizeBits) {
        this.macName = Objects.requireNonNull(macName, "macName must not be null");
        if (keySizeBits <= 0 || (keySizeBits % 8) != 0) {
            throw new IllegalArgumentException("keySizeBits must be a positive multiple of 8");
        }
        this.keySizeBits = keySizeBits;
    }

    /**
     * Returns the JCA algorithm name of the HMAC variant.
     *
     * @return the algorithm name (e.g., {@code "HmacSHA256"})
     */
    public String macName() {
        return macName;
    }

    /**
     * Returns the key size requested for generation.
     *
     * @return key size in bits (always a positive multiple of 8)
     */
    public int keySizeBits() {
        return keySizeBits;
    }

    /**
     * Convenience factory for HMAC-SHA256 key generation specs.
     *
     * @param bits desired key size in bits
     * @return a new spec targeting {@code HmacSHA256} with the given key size
     */
    public static HmacKeyGenSpec sha256(int bits) {
        return new HmacKeyGenSpec("HmacSHA256", bits);
    }

    /**
     * Convenience factory for HMAC-SHA384 key generation specs.
     *
     * @param bits desired key size in bits
     * @return a new spec targeting {@code HmacSHA384} with the given key size
     */
    public static HmacKeyGenSpec sha384(int bits) {
        return new HmacKeyGenSpec("HmacSHA384", bits);
    }

    /**
     * Convenience factory for HMAC-SHA512 key generation specs.
     *
     * @param bits desired key size in bits
     * @return a new spec targeting {@code HmacSHA512} with the given key size
     */
    public static HmacKeyGenSpec sha512(int bits) {
        return new HmacKeyGenSpec("HmacSHA512", bits);
    }

    /**
     * Returns a short description of this key spec.
     *
     * <p>
     * The description is formed as {@code "<macName>/<keySizeBits>"}. Example:
     * {@code "HmacSHA256/256"}.
     * </p>
     *
     * @return human-readable description string
     */
    @Override
    public String description() {
        return macName + "/" + keySizeBits;
    }
}
