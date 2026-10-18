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
package zeroecho.core.alg.chacha;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>ChaCha20 key generation specification</h2>
 *
 * Immutable record describing the key size for ChaCha20 key generation. Only
 * 256-bit keys are permitted by the ChaCha20 design.
 *
 * <h3>Validation</h3>
 * <ul>
 * <li>The constructor enforces {@code keySizeBits == 256}.</li>
 * <li>Any other size results in an {@link IllegalArgumentException}.</li>
 * </ul>
 *
 * <h3>Factory method</h3>
 * <ul>
 * <li>{@link #chacha256()} provides a convenient way to obtain a standard
 * 256-bit spec.</li>
 * </ul>
 *
 * <h3>Usage example</h3> <pre>{@code
 * ChaChaKeyGenSpec spec = ChaChaKeyGenSpec.chacha256();
 * SecretKey key = cryptoAlgorithm.generateSecret(spec);
 * }</pre>
 *
 * @param keySizeBits key size in bits (must be 256)
 * @since 1.0
 */
public record ChaChaKeyGenSpec(int keySizeBits) implements AlgorithmKeySpec, Describable {
    /**
     * Constructs a new ChaCha20 key generation spec.
     *
     * @param keySizeBits must be 256; otherwise an exception is thrown
     * @throws IllegalArgumentException if {@code keySizeBits != 256}
     */
    public ChaChaKeyGenSpec {
        if (keySizeBits != 256) { // NOPMD
            throw new IllegalArgumentException("ChaCha20 keySizeBits must be 256");
        }
    }

    /**
     * Returns the standard 256-bit key generation spec.
     *
     * @return a new {@code ChaChaKeyGenSpec} with size 256
     */
    public static ChaChaKeyGenSpec chacha256() {
        return new ChaChaKeyGenSpec(256);
    }

    /**
     * Returns a short human-readable description of this spec.
     *
     * @return the string {@code "256bits"}
     */
    @Override
    public String description() {
        return "256bits";
    }
}
