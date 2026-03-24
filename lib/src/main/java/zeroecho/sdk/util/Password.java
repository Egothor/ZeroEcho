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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Utility class for generating random passwords and secure random byte arrays.
 * <p>
 * This class provides methods to:
 * <ul>
 * <li>Generate cryptographically secure random byte arrays of specified
 * length.</li>
 * <li>Generate random passwords composed of characters derived from random
 * bytes.</li>
 * </ul>
 * <p>
 * A single instance of {@link SecureRandom} is used unless
 * {@code UNSAFE_SINGLE_SECURE} is set to {@code false}, in which case a new
 * {@link SecureRandom} instance is created for each operation.
 * <p>
 * This class is thread-safe through use of a {@link ReentrantLock}.
 *
 * @author Leo Galambos
 */
public final class Password {
    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private Password() {
        // this is a utility class
    }

    /**
     * Generates a random password by filling the provided byte array with
     * cryptographically strong random bytes. The randomness is influenced by a
     * combination of a user-supplied seed string and a randomly generated salt,
     * ensuring that the result is both secure and non-deterministic across multiple
     * invocations with the same input.
     * <p>
     * Internally, the method uses the SHA-256 digest of the concatenation of the
     * seed and a 16-byte random salt to derive a seed for a {@link SecureRandom}
     * instance. This seed is mixed into the internal state of the
     * {@code SecureRandom} generator to produce a high-entropy, unpredictable byte
     * sequence. As a result, the output differs each time the method is called,
     * even with the same seed and password buffer.
     * <p>
     * Note: The generated salt is not returned or stored. If you require
     * reproducible output or need to verify the result later, you must persist the
     * salt separately.
     *
     * @param password the byte array to be filled with random password bytes; must
     *                 not be {@code null}
     * @param seed     a user-supplied string used to influence the randomness
     *                 generation; must not be {@code null}
     * @return the same {@code password} byte array, now filled with
     *         cryptographically strong random data
     * @throws NoSuchAlgorithmException if the SHA-256 digest or strong
     *                                  {@code SecureRandom} implementation is not
     *                                  available
     * @throws NullPointerException     if {@code password} or {@code seed} is
     *                                  {@code null}
     */
    public static byte[] generateRandom(final byte[] password, final String seed) throws NoSuchAlgorithmException {
        final byte[] salt = new byte[16];
        RandomSupport.getRandom().nextBytes(salt);

        // Combine input + salt
        final byte[] seedBytes = seed.getBytes(StandardCharsets.UTF_8);
        final byte[] combined = new byte[seedBytes.length + salt.length];
        System.arraycopy(seedBytes, 0, combined, 0, seedBytes.length);
        System.arraycopy(salt, 0, combined, seedBytes.length, salt.length);

        // Derive seed using SHA-256
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final byte[] rndSeed = digest.digest(combined);

        // Seed SecureRandom (deterministic per run, but uses a fresh salt)
        final SecureRandom seededRandom = SecureRandom.getInstanceStrong();
        seededRandom.setSeed(rndSeed); // mixes with internal state

        // Generate random output
        seededRandom.nextBytes(password);

        return password;
    }

    /**
     * Generates a cryptographically secure random password consisting of printable
     * ASCII characters.
     *
     * @param length the desired length of the password; must be positive
     * @return a random password string using printable characters in the ASCII
     *         range 33–126
     * @throws IllegalArgumentException if {@code length} is less than or equal to
     *                                  zero
     */
    public static String generatePrintablePassword(final int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Password length must be greater than zero");
        }

        final StringBuilder password = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            final int ascii = RandomSupport.getRandom().nextInt('~' - '!' + 1) + '!';
            password.append((char) ascii);
        }

        return password.toString();
    }
}
