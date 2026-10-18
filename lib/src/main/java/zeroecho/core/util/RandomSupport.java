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
package zeroecho.core.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Provides the authoritative process-wide cryptographic random source.
 */
public final class RandomSupport {
    private static final Logger LOG = Logger.getLogger(RandomSupport.class.getName());
    private static final SecureRandom RANDOM = createRandom();

    private RandomSupport() {
    }

    /**
     * Returns the shared thread-safe random source.
     *
     * @return shared secure random generator
     */
    public static SecureRandom getRandom() {
        return RANDOM;
    }

    /**
     * Allocates and fills a random byte array.
     *
     * @param size required array length
     * @return random bytes
     */
    public static byte[] generateRandom(int size) {
        return generateRandom(new byte[size]);
    }

    /**
     * Fills the supplied array with random bytes.
     *
     * @param buffer destination array
     * @return {@code buffer}
     */
    public static byte[] generateRandom(byte[] buffer) {
        RANDOM.nextBytes(buffer);
        return buffer;
    }

    /**
     * Returns a uniform value below the bound.
     *
     * @param bound exclusive positive upper bound
     * @return generated value
     */
    public static int nextInt(int bound) {
        return RANDOM.nextInt(bound);
    }

    private static SecureRandom createRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException exception) {
            LOG.log(Level.WARNING, "Strong SecureRandom unavailable; using the platform default");
            return new SecureRandom();
        }
    }
}
