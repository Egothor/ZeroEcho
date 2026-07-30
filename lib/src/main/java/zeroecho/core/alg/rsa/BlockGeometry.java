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
package zeroecho.core.alg.rsa;

import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.RSAKey;
import java.util.Objects;

/**
 * Describes block sizing rules for RSA encryption and decryption.
 *
 * <p>
 * A {@code BlockGeometry} defines how many plaintext or ciphertext bytes can be
 * processed per block and how many bytes are emitted, given an RSA modulus,
 * padding scheme, and direction (encryption or decryption). This information is
 * required by {@link RsaCipherContext} to configure the
 * {@code CipherTransformInputStreamBuilder} for streaming operation.
 * </p>
 *
 * <h2>RSA rules</h2>
 * <ul>
 * <li><b>Encryption</b>:
 * <ul>
 * <li>Input block size is the modulus length minus padding overhead.</li>
 * <li>Output block size is exactly the modulus length in bytes.</li>
 * </ul>
 * </li>
 * <li><b>Decryption</b>:
 * <ul>
 * <li>Input block size is exactly the modulus length in bytes.</li>
 * <li>Output block size is bounded by the encryption input maximum, but
 * {@code modulus length} is used as a safe upper bound.</li>
 * </ul>
 * </li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * Key pub = ...; // RSA public key
 * RsaEncSpec spec = RsaEncSpec.ofPkcs1v15();
 * BlockGeometry g = BlockGeometry.forRsa(spec, pub, true);
 * System.out.printf("Plaintext block: %d, Ciphertext block: %d%n",
 *                   g.inChunkSize(), g.outChunkSize());
 * }</pre>
 *
 * @since 1.0
 */
public record BlockGeometry(int inChunkSize, int outChunkSize, int finalizationOutputChunks) {
    private static final int MINIMUM_INPUT_CHUNK_SIZE = 2;

    /**
     * Constructs a new block geometry descriptor.
     *
     * @param inChunkSize              maximum input bytes per block
     * @param outChunkSize             output bytes per block
     * @param finalizationOutputChunks number of additional chunks during
     *                                 finalization
     * @throws IllegalArgumentException if input size is not greater than one,
     *                                  output size is not positive, input exceeds
     *                                  output, or finalization chunks is not zero
     */
    public BlockGeometry {
        if (inChunkSize < MINIMUM_INPUT_CHUNK_SIZE) {
            throw new IllegalArgumentException("inChunkSize must be greater than 1: " + inChunkSize);
        }
        if (outChunkSize <= 0) {
            throw new IllegalArgumentException("outChunkSize must be positive: " + outChunkSize);
        }
        if (inChunkSize > outChunkSize) {
            throw new IllegalArgumentException(
                    "inChunkSize must not exceed outChunkSize: " + inChunkSize + " > " + outChunkSize);
        }
        if (finalizationOutputChunks != 0) {
            throw new IllegalArgumentException("finalizationOutputChunks must be zero: " + finalizationOutputChunks);
        }
    }

    /**
     * Computes RSA block geometry for the given specification and key.
     *
     * @param spec    RSA encryption specification with padding and hash parameters
     * @param key     RSA key; must implement
     *                {@link java.security.interfaces.RSAKey}
     * @param encrypt {@code true} for encryption, {@code false} for decryption
     * @return block geometry with input and output block sizes
     * @throws IllegalArgumentException if {@code key} is not RSA or modulus is too
     *                                  small
     */
    public static BlockGeometry forRsa(RsaEncSpec spec, Key key, boolean encrypt) {
        if (!(key instanceof RSAKey rsa)) {
            throw new IllegalArgumentException("RSA key required");
        }
        int k = byteLen(rsa.getModulus()); // modulus size in bytes

        int inBlock = 0;
        int outBlock = k;
        if (encrypt) {
            switch (spec.padding()) {
                case PKCS1V15 -> {
                    inBlock = k - 11;
                }
                case OAEP -> {
                    int hLen = oaepHashLen(spec.hash());
                    inBlock = k - 2 * hLen - 2;
                }
            }
            if (inBlock <= 0) {
                throw new IllegalArgumentException("RSA modulus too small for chosen padding/hash");
            }
        } else {
            // Decryption: input blocks are exactly k bytes; output ≤ encrypt max. Use k as
            // safe bound.
            inBlock = k;
        }

        return new BlockGeometry(inBlock, outBlock, 0);
    }

    private static int byteLen(BigInteger n) {
        int bits = n.bitLength();
        return (bits + 7) >>> 3;
    }

    private static int oaepHashLen(RsaEncSpec.Hash h) {
        return switch (h) {
            case SHA1 -> 20;
            case SHA256 -> 32;
            case SHA384 -> 48;
            case SHA512 -> 64;
        };
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof BlockGeometry geometry)) {
            return false;
        }
        return inChunkSize == geometry.inChunkSize && outChunkSize == geometry.outChunkSize
                && finalizationOutputChunks == geometry.finalizationOutputChunks;
    }

    @Override
    public int hashCode() {
        return Objects.hash(inChunkSize, outChunkSize, finalizationOutputChunks);
    }

    @Override
    public String toString() {
        return "BlockGeometry[inChunkSize=" + inChunkSize + ", outChunkSize=" + outChunkSize
                + ", finalizationOutputChunks=" + finalizationOutputChunks + "]";
    }
}
