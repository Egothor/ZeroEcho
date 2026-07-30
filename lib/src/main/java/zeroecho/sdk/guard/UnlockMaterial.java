/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the conditions in the project LICENSE are met.
 ******************************************************************************/
package zeroecho.sdk.guard;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.annotation.Describable;

/**
 * Caller-owned session-operation input used to unlock a recipient entry.
 *
 * <p>
 * Components accepting an {@code UnlockMaterial} borrow it and do not destroy
 * it. The caller must keep it usable until the operation completes and destroy
 * password material afterwards.
 * </p>
 */
public sealed interface UnlockMaterial extends Describable {
    /**
     * Private key unlocking material.
     *
     * @param key non-null private key
     */
    record Private(java.security.PrivateKey key) implements UnlockMaterial {
        /** Validates the key. */
        public Private {
            Objects.requireNonNull(key, "key must not be null");
        }

        /** {@inheritDoc} */
        @Override
        public String description() {
            return "Unlock via key of " + key.getAlgorithm();
        }
    }

    /**
     * Destroyable password unlocking material backed by an owned character array.
     *
     * <p>
     * Construction and access use defensive copies. Destruction is idempotent and
     * prevents subsequent access.
     * </p>
     */
    final class Password implements UnlockMaterial, Destroyable {
        private final char[] characters;
        private final ReentrantLock lifecycleLock = new ReentrantLock();
        private boolean destroyed;

        /**
         * Creates password material from a caller-owned array.
         *
         * @param password source characters; retained only as a defensive copy
         * @throws NullPointerException if {@code password} is {@code null}
         */
        @SuppressWarnings("PMD.UseVarargs")
        public Password(char[] password) {
            this.characters = Objects.requireNonNull(password, "password must not be null").clone();
        }

        /**
         * Returns a caller-owned password copy.
         *
         * @return password copy
         * @throws IllegalStateException if destroyed
         */
        public char[] password() {
            lifecycleLock.lock();
            try {
                if (destroyed) {
                    throw new IllegalStateException("Password material has been destroyed");
                }
                return characters.clone();
            } finally {
                lifecycleLock.unlock();
            }
        }

        /** {@inheritDoc} */
        @Override
        public String description() {
            return "Unlock via password";
        }

        /** {@inheritDoc} */
        @Override
        public void destroy() {
            lifecycleLock.lock();
            try {
                if (!destroyed) {
                    Arrays.fill(characters, '\0');
                    destroyed = true;
                }
            } finally {
                lifecycleLock.unlock();
            }
        }

        /** {@inheritDoc} */
        @Override
        public boolean isDestroyed() {
            lifecycleLock.lock();
            try {
                return destroyed;
            } finally {
                lifecycleLock.unlock();
            }
        }

        /**
         * Returns a redacted diagnostic representation.
         *
         * @return redacted text
         */
        @Override
        public String toString() {
            return "UnlockMaterial.Password[REDACTED]";
        }
    }
}
