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
package zeroecho.core.context;

import java.io.IOException;

/**
 * Context for performing key encapsulation and decapsulation (KEM) operations.
 *
 * <p>
 * A {@code KemContext} encapsulates the state for algorithms that exchange
 * shared secrets using asymmetric primitives. KEMs are widely used in
 * post-quantum cryptography and hybrid key exchange protocols.
 * </p>
 *
 * <h2>Lifecycle</h2>
 * <ul>
 * <li>Create a context via {@code ZeroEchoSession#createContext(...)} for the
 * {@link zeroecho.core.KeyUsage#ENCAPSULATE} or
 * {@link zeroecho.core.KeyUsage#DECAPSULATE} role.</li>
 * <li>Call {@link #encapsulate()} when acting as an initiator. The result
 * includes both the ciphertext to send and the derived shared secret.</li>
 * <li>Call {@link #decapsulate(byte[])} when acting as a responder, supplying
 * the received ciphertext to recover the same shared secret.</li>
 * <li>Dispose of the context with {@link #close()} to release resources.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>The shared secret must be immediately fed into a key-derivation function
 * (KDF). Applications should zeroize the byte array after use.</li>
 * <li>Implementations must validate ciphertexts carefully; malformed inputs
 * should fail decapsulation without leaking side-channel information.</li>
 * <li>Contexts are not guaranteed to be thread-safe; use one instance per
 * flow.</li>
 * </ul>
 *
 * @since 1.0
 */
public non-sealed interface KemContext extends CryptoContext {
    /**
     * Performs encapsulation, generating both the encapsulated ciphertext and the
     * derived shared secret.
     *
     * @return a {@link KemResult} containing the ciphertext to transmit and the raw
     *         shared secret
     * @throws IOException if encapsulation fails or the provider encounters an
     *                     error
     */
    KemResult encapsulate() throws IOException;

    /**
     * Performs decapsulation of the given ciphertext to recover the shared secret.
     *
     * @param ciphertext the peer’s encapsulation ciphertext
     * @return a new byte array containing the raw shared secret
     * @throws IOException if decapsulation fails or the input is invalid
     */
    byte[] decapsulate(byte[] ciphertext) throws IOException;

    /**
     * Encapsulation result holding both ciphertext and shared secret.
     *
     * <p>
     * Instances of this class are immutable. The caller is responsible for handling
     * and clearing the secret bytes after use.
     * </p>
     */
    final class KemResult {
        private final byte[] ciphertext;
        private final byte[] sharedSecret;

        /**
         * Creates a new result object with the provided values.
         *
         * @param ciphertext   the encapsulation ciphertext to be transmitted
         * @param sharedSecret the derived shared secret (sensitive material)
         */
        public KemResult(byte[] ciphertext, byte[] sharedSecret) {
            this.ciphertext = ciphertext;
            this.sharedSecret = sharedSecret;
        }

        /**
         * Returns the encapsulation ciphertext.
         *
         * @return ciphertext to send to the peer
         */
        public byte[] ciphertext() {
            return ciphertext; // NOPMD
        }

        /**
         * Returns the derived shared secret.
         *
         * <p>
         * This material is sensitive and should be passed into a KDF and then cleared
         * as soon as possible.
         * </p>
         *
         * @return the raw shared secret
         */
        public byte[] sharedSecret() {
            return sharedSecret; // NOPMD
        }
    }
}
