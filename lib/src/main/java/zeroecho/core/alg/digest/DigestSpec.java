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
package zeroecho.core.alg.digest;

import java.util.Objects;

import zeroecho.core.annotation.Describable;
import zeroecho.core.annotation.DisplayName;
import zeroecho.core.spec.ContextSpec;

/**
 * <h2>Digest parameters for SHA-2, SHA-3, and SHAKE</h2>
 *
 * {@code DigestSpec} is a context specification for the
 * {@link Sha2Sha3Algorithm}, selecting which digest algorithm variant to use
 * and, for extendable-output functions (XOFs), the desired output length.
 *
 * <h2>Algorithm selection</h2> The nested {@link Algorithm} enum defines the
 * supported digest families:
 * <ul>
 * <li>{@link Algorithm#SHA_256}, {@link Algorithm#SHA_384},
 * {@link Algorithm#SHA_512} - fixed-length SHA-2 digests.</li>
 * <li>{@link Algorithm#SHA3_256}, {@link Algorithm#SHA3_512} - fixed-length
 * SHA-3 digests.</li>
 * <li>{@link Algorithm#SHAKE128}, {@link Algorithm#SHAKE256} -
 * extendable-output functions (XOFs).</li>
 * </ul>
 *
 * <p>
 * For fixed-length digests, the {@link #outputLenBytes()} is always {@code 0}
 * (the digest length is implicit). For XOFs, a positive output length must be
 * supplied at construction time.
 * </p>
 *
 * <h2>Construction</h2> Factory methods are provided for common cases:
 * <ul>
 * <li>{@link #sha256()}, {@link #sha384()}, {@link #sha512()}</li>
 * <li>{@link #sha3_256()}, {@link #sha3_512()}</li>
 * <li>{@link #shake128(int)}, {@link #shake256(int)} (require explicit output
 * length)</li>
 * </ul>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Create a spec for SHAKE256 with 64-byte output
 * DigestSpec spec = DigestSpec.shake256(64);
 *
 * // Use in context creation
 * DigestContext ctx = session.createContext(
 *         "DIGEST", KeyUsage.DIGEST, NullKey.INSTANCE, spec);
 *
 * byte[] digest = ctx.doFinal(data);
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances are immutable and can be safely reused
 * across threads.
 *
 * @see Sha2Sha3Algorithm
 * @see zeroecho.core.context.DigestContext
 * @since 1.0
 */
@DisplayName("Digest parameters")
public final class DigestSpec implements ContextSpec, Describable {

    /**
     * Enumeration of supported digest algorithms.
     *
     * <p>
     * Each constant defines the JCA algorithm name and whether the variant is an
     * extendable-output function (XOF).
     * </p>
     */
    public enum Algorithm {
        /** SHA-256 digest from the SHA-2 family. */
        SHA_256("SHA-256", false),
        /** SHA-384 digest from the SHA-2 family. */
        SHA_384("SHA-384", false),
        /** SHA-512 digest from the SHA-2 family. */
        SHA_512("SHA-512", false),
        /** SHA3-256 digest from the SHA-3 family. */
        SHA3_256("SHA3-256", false),
        /** SHA3-512 digest from the SHA-3 family. */
        SHA3_512("SHA3-512", false),
        /** SHAKE128 extendable-output function (XOF). */
        SHAKE128("SHAKE128", true),
        /** SHAKE256 extendable-output function (XOF). */
        SHAKE256("SHAKE256", true);

        private final String jca;
        private final boolean xof;

        Algorithm(String jca, boolean xof) {
            this.jca = jca;
            this.xof = xof;
        }

        /**
         * Returns the canonical JCA algorithm name.
         *
         * @return JCA name string (e.g., {@code "SHA-256"} or {@code "SHAKE256"})
         */
        public String jca() {
            return jca;
        }

        /**
         * Indicates whether this algorithm is an XOF (extendable-output function).
         *
         * @return {@code true} if this algorithm is an XOF, {@code false} otherwise
         */
        public boolean isXof() {
            return xof;
        }
    }

    private final Algorithm algorithm;
    private final int outputLenBytes; // for XOFs; 0 for fixed-length digests

    private DigestSpec(Algorithm algorithm, int outputLenBytes) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
        if (algorithm.isXof() && outputLenBytes <= 0) {
            throw new IllegalArgumentException("XOF output length must be > 0");
        }
        this.outputLenBytes = algorithm.isXof() ? outputLenBytes : 0;
    }

    /**
     * Returns a {@code DigestSpec} for SHA-256.
     *
     * @return spec for SHA-256
     */
    public static DigestSpec sha256() {
        return new DigestSpec(Algorithm.SHA_256, 0);
    }

    /**
     * Returns a {@code DigestSpec} for SHA-384.
     *
     * @return spec for SHA-384
     */
    public static DigestSpec sha384() {
        return new DigestSpec(Algorithm.SHA_384, 0);
    }

    /**
     * Returns a {@code DigestSpec} for SHA-512.
     *
     * @return spec for SHA-512
     */
    public static DigestSpec sha512() {
        return new DigestSpec(Algorithm.SHA_512, 0);
    }

    /**
     * Returns a {@code DigestSpec} for SHA3-256.
     *
     * @return spec for SHA3-256
     */
    public static DigestSpec sha3_256() {
        return new DigestSpec(Algorithm.SHA3_256, 0);
    }

    /**
     * Returns a {@code DigestSpec} for SHA3-512.
     *
     * @return spec for SHA3-512
     */
    public static DigestSpec sha3_512() {
        return new DigestSpec(Algorithm.SHA3_512, 0);
    }

    /**
     * Returns a {@code DigestSpec} for SHAKE128 with the given output length.
     *
     * @param outLen desired output length in bytes (must be > 0)
     * @return spec for SHAKE128 with the specified output length
     * @throws IllegalArgumentException if {@code outLen <= 0}
     */
    public static DigestSpec shake128(int outLen) {
        return new DigestSpec(Algorithm.SHAKE128, outLen);
    }

    /**
     * Returns a {@code DigestSpec} for SHAKE256 with the given output length.
     *
     * @param outLen desired output length in bytes (must be > 0)
     * @return spec for SHAKE256 with the specified output length
     * @throws IllegalArgumentException if {@code outLen <= 0}
     */
    public static DigestSpec shake256(int outLen) {
        return new DigestSpec(Algorithm.SHAKE256, outLen);
    }

    /**
     * Returns the digest algorithm.
     *
     * @return algorithm enum constant
     */
    public Algorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the requested output length in bytes.
     *
     * <p>
     * For fixed-length digests, this value is {@code 0}. For XOFs, this is the
     * explicit length requested at construction.
     * </p>
     *
     * @return output length in bytes (0 if not applicable)
     */
    public int outputLenBytes() {
        return outputLenBytes;
    }

    /**
     * Returns a human-readable description of this specification.
     *
     * <p>
     * For XOFs, the description includes the chosen output length, e.g.,
     * {@code "SHAKE128(64B)"}.
     * </p>
     *
     * @return description string
     */
    @Override
    public String description() {
        return algorithm.isXof() ? algorithm.jca() + "(" + outputLenBytes + "B)" : algorithm.jca();
    }
}
