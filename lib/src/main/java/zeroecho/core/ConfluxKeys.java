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
package zeroecho.core;

import conflux.Key;

/**
 * Shared typed keys for ephemeral cryptographic parameters.
 *
 * <p>
 * {@code ConfluxKeys} provides strongly typed, namespaced keys for common
 * transient values such as IVs, nonces, AAD, and authentication tags. These
 * keys are typically used with a key–value parameter store (e.g., a
 * {@code Map<Key<?>,Object>} or a dedicated context object) to exchange
 * per-operation metadata between algorithms and higher layers.
 * </p>
 *
 * <h2>Design goals</h2>
 * <ul>
 * <li><b>Type safety</b>: each key carries its value type (e.g.,
 * {@code Key<byte[]>} vs {@code Key<Integer>}).</li>
 * <li><b>Namespacing</b>: all keys include the algorithm identifier in their
 * name, preventing collisions when multiple algorithms share a context.</li>
 * <li><b>Consistency</b>: avoids ad-hoc string constants; discoverable via
 * {@link CryptoAlgorithm#listCapabilities()} and related APIs.</li>
 * </ul>
 *
 * <p>
 * Instances are created via static factories; this class cannot be
 * instantiated.
 * </p>
 *
 * @since 1.0
 */
public final class ConfluxKeys {
    final private static String PREFIX = "crypto.";

    private ConfluxKeys() {
    }

    /**
     * Returns a typed key for the initialization vector (IV) of a given algorithm.
     *
     * <p>
     * IVs are required by block cipher modes such as CBC or GCM. Each call produces
     * a key namespaced as {@code "crypto.<algoId>.iv"}.
     * </p>
     *
     * @param algoId canonical algorithm identifier
     * @return key for IV values, of type {@code byte[]}
     */
    public static Key<byte[]> iv(String algoId) {
        return Key.of(PREFIX + algoId + ".iv", byte[].class);
    }

    /**
     * Returns a typed key for additional authenticated data (AAD).
     *
     * <p>
     * Used in AEAD schemes such as AES-GCM to bind unencrypted headers into the
     * authentication tag. Namespaced as {@code "crypto.<algoId>.aad"}.
     * </p>
     *
     * @param algoId canonical algorithm identifier
     * @return key for AAD values, of type {@code byte[]}
     */
    public static Key<byte[]> aad(String algoId) {
        return Key.of(PREFIX + algoId + ".aad", byte[].class);
    }

    /**
     * Returns a typed key for a nonce value of a given algorithm.
     *
     * <p>
     * Nonces are required by stream ciphers and AEAD modes to ensure uniqueness per
     * key. Namespaced as {@code "crypto.<algoId>.nonce"}.
     * </p>
     *
     * @param algoId canonical algorithm identifier
     * @return key for nonce values, of type {@code byte[]}
     */
    public static Key<byte[]> nonce(String algoId) {
        return Key.of(PREFIX + algoId + ".nonce", byte[].class);
    }

    /**
     * Returns a typed key for the authentication tag of a given algorithm.
     *
     * <p>
     * AEAD modes output a tag that must be preserved for decryption/verification.
     * Namespaced as {@code "crypto.<algoId>.tag"}.
     * </p>
     *
     * @param algoId canonical algorithm identifier
     * @return key for authentication tag values, of type {@code byte[]}
     */
    public static Key<byte[]> tag(String algoId) {
        return Key.of(PREFIX + algoId + ".tag", byte[].class);
    }

    /**
     * Returns a typed key for the number of authentication tag bits.
     *
     * <p>
     * Some AEAD constructions allow truncated tags (e.g., 96-bit or 64-bit). This
     * key represents the chosen bit-length. Namespaced as
     * {@code "crypto.<algoId>.tagBits"}.
     * </p>
     *
     * @param algoId canonical algorithm identifier
     * @return key for tag length values, of type {@code Integer}
     */
    public static Key<Integer> tagBits(String algoId) {
        return Key.of(PREFIX + algoId + ".tagBits", Integer.class);
    }
}
