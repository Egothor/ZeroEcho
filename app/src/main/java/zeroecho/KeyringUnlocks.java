/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
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

    /* default */ static KeyringStore open(Path path, KeyringUnlockProvider provider)
            throws IOException, GeneralSecurityException {
        try (KeyringPassword password = acquire(provider)) {
            return KeyringStore.open(path, password);
        }
    }

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
