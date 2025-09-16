/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.sdk.content.builtin;

import conflux.Ctx;
import conflux.Key;
import zeroecho.sdk.content.api.SecretContent;
import zeroecho.sdk.util.Password;

/**
 * A {@link SecretContent} implementation that encapsulates a passwordKey
 * string. This class extends {@link PlainString} and enforces immutability of
 * the passwordKey after construction.
 * <p>
 * Passwords can be generated randomly or provided explicitly. Once set,
 * attempts to change the passwordKey via parameters will cause an exception.
 * <p>
 * This class supports applying parameters from a map and collecting its state
 * back into a map, using the key {@link #PASSWORD}.
 * 
 * @author Leo Galambos
 */
public class SecretPassword extends PlainString implements SecretContent {
    private final Key<String> PASSWORD = Key.of("secret.password", String.class);

    /**
     * Constructs a {@code SecretPassword} with a randomly generated printable
     * passwordKey of the specified length.
     *
     * @param length the length of the generated passwordKey
     * @throws IllegalArgumentException if {@code length} is less than or equal to
     *                                  zero
     */
    public SecretPassword(final int length) {
        super(Password.generatePrintablePassword(length));
        Ctx.INSTANCE.put(PASSWORD, str);
    }

    /**
     * Constructs a {@code SecretPassword} wrapping the specified passwordKey
     * string. The passwordKey may be {@code null}.
     *
     * @param password the passwordKey string, or {@code null}
     */
    public SecretPassword(final String password) {
        super(password);
        Ctx.INSTANCE.put(PASSWORD, str);
    }
}
