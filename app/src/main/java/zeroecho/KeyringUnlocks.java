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
package zeroecho;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import zeroecho.core.spi.KeyringUnlockProvider;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;

/**
 * Application boundary for acquiring and promptly destroying keyring passwords.
 */
final class KeyringUnlocks {
    private KeyringUnlocks() {
    }

    /**
     * Creates a provider that prompts for a password on each acquisition using the JVM console.
     *
     * <p>The provider reports absent console input or cancellation as an IOException when
     * acquired. Its transient character buffer is cleared after creating the owned password.</p>
     *
     * @return reusable provider; callers must close each acquired password
     */
    /* default */ static KeyringUnlockProvider console() {
        return () -> {
            Console console = System.console();
            if (console == null) {
                throw new IOException("Interactive keyring password input is unavailable");
            }
            char[] input = console.readPassword("Keyring password: ");
            if (input == null) {
                throw new IOException("Keyring password input was cancelled");
            }
            try {
                return new KeyringPassword(input);
            } finally {
                Arrays.fill(input, '\0');
            }
        };
    }

    /**
     * Returns an unlock provider that reads the keyring password from a named environment variable,
     * enabling non-interactive/scripted keyring management (mirrors the PKI session's
     * {@code unlockEnvironmentVariable}). The variable value is copied into a destroyable password and the
     * transient copy is scrubbed after use.
     *
     * @param variable environment variable name; must not be null
     * @return provider that reports an absent or empty value as an IOException on acquisition
     * @throws NullPointerException if variable is null
     */
    /* default */ static KeyringUnlockProvider environment(String variable) {
        String name = java.util.Objects.requireNonNull(variable, "variable");
        return () -> {
            String value = System.getenv(name);
            if (value == null || value.isEmpty()) {
                throw new IOException("Keyring password environment variable is unavailable");
            }
            char[] input = value.toCharArray();
            try {
                return new KeyringPassword(input);
            } finally {
                Arrays.fill(input, '\0');
            }
        };
    }

    /**
     * Opens a keyring using one acquired password, which is destroyed before this call returns.
     *
     * @param path existing keyring location
     * @param provider password acquisition callback; must not be null
     * @return opened store owned by the caller
     * @throws IOException if acquisition, file access, or decoding fails
     * @throws GeneralSecurityException if unlocking or cryptographic validation fails
     * @throws NullPointerException if path or provider is null
     */
    /* default */ static KeyringStore open(Path path, KeyringUnlockProvider provider)
            throws IOException, GeneralSecurityException {
        try (KeyringPassword password = acquire(provider)) {
            return KeyringStore.open(path, password);
        }
    }

    /**
     * Creates a keyring using one acquired password, which is destroyed before this call returns.
     *
     * @param path destination keyring location
     * @param provider password acquisition callback; must not be null
     * @return newly created store owned by the caller
     * @throws IOException if acquisition or file creation fails
     * @throws GeneralSecurityException if cryptographic initialization fails
     * @throws NullPointerException if path or provider is null
     */
    /* default */ static KeyringStore create(Path path, KeyringUnlockProvider provider)
            throws IOException, GeneralSecurityException {
        try (KeyringPassword password = acquire(provider)) {
            return KeyringStore.create(path, password);
        }
    }

    private static KeyringPassword acquire(KeyringUnlockProvider provider) throws IOException {
        KeyringPassword password = provider.acquire();
        if (password == null) {
            throw new IOException("Keyring unlock provider returned no password");
        }
        return password;
    }
}
