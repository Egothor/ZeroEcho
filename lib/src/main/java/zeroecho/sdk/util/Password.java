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

import zeroecho.core.util.RandomSupport;

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
 * Randomness is supplied by the shared thread-safe source in
 * {@link RandomSupport}.
 *
 * @since 1.0
 */
public final class Password {
    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private Password() {
        // this is a utility class
    }

    /**
     * Fills the supplied array with cryptographically strong random bytes.
     *
     * @param password array to fill; must not be {@code null}
     * @return {@code password}
     * @throws NullPointerException if {@code password} is {@code null}
     */
    public static byte[] generateRandom(final byte[] password) {
        return RandomSupport.generateRandom(password);
    }

    /**
     * Generates a printable password in a caller-owned character array.
     *
     * @param length desired password length; must be positive
     * @return a newly allocated printable password
     * @throws IllegalArgumentException if {@code length} is not positive
     */
    public static char[] generatePrintablePasswordChars(final int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Password length must be greater than zero");
        }

        final char[] password = new char[length];
        for (int i = 0; i < length; i++) {
            password[i] = (char) (RandomSupport.nextInt('~' - '!' + 1) + '!');
        }
        return password;
    }

}
