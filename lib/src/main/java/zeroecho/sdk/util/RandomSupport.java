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
package zeroecho.sdk.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Utility class providing support for secure random number generation.
 * <p>
 * This class provides cryptographically secure random data through one
 * process-wide, thread-safe {@link SecureRandom}. It selects the platform's
 * strong implementation when available and otherwise uses the platform default.
 * </p>
 *
 * @author Leo Galambos
 */
public final class RandomSupport {
    private static final Logger LOG = Logger.getLogger(RandomSupport.class.getName());

    /** Shared {@link SecureRandom} instance. */
    private static final SecureRandom RANDOM = createRandom();

    private RandomSupport() {
        // this is a utility class
    }

    /**
     * Returns the shared {@link SecureRandom} instance.
     *
     * @return the shared random source
     */
    public static SecureRandom getRandom() {
        return RANDOM;
    }

    private static SecureRandom createRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException exception) {
            LOG.log(Level.WARNING, "Strong SecureRandom unavailable; using the platform default");
            return new SecureRandom();
        }
    }

    /**
     * Generates a secure random byte array of the specified size.
     *
     * @param size The size of the byte array to generate.
     * @return A byte array filled with cryptographically secure random bytes.
     */
    public static byte[] generateRandom(final int size) {
        return generateRandom(new byte[size]);
    }

    /**
     * Fills the given byte array with random bytes and returns it.
     * <p>
     * This method uses a thread-safe {@code SecureRandom} instance to generate
     * cryptographically strong random values.
     *
     * @param buffer the byte array to fill with random bytes
     * @return the same byte array, now containing random data
     * @throws NullPointerException if {@code buffer} is {@code null}
     */
    public static byte[] generateRandom(final byte[] buffer) {
        RANDOM.nextBytes(buffer);
        return buffer;
    }

    /**
     * Returns a uniformly distributed value between zero (inclusive) and the
     * specified bound (exclusive).
     *
     * @param bound exclusive upper bound; must be positive
     * @return a uniformly distributed value
     * @throws IllegalArgumentException if {@code bound} is not positive
     */
    public static int nextInt(final int bound) {
        return RANDOM.nextInt(bound);
    }
}
