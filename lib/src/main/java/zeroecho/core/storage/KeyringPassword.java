/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.storage;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

/**
 * Destroyable owner of a keyring password.
 *
 * <p>
 * The constructor and {@link #copy()} use defensive copies. Callers retain
 * ownership of the array supplied to the constructor and must clear it. The
 * returned copy belongs to the receiver and must be cleared immediately after
 * key derivation. This object never creates an immutable password
 * {@link String}.
 * </p>
 *
 * <p>
 * Instances are thread-safe. Destruction is idempotent and makes subsequent
 * access fail deterministically.
 * </p>
 */
public final class KeyringPassword implements Destroyable, AutoCloseable {
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private final char[] password;
    private boolean destroyed;

    /**
     * Creates a password owner.
     *
     * @param password password characters, which are defensively copied
     * @throws NullPointerException     if {@code password} is {@code null}
     * @throws IllegalArgumentException if {@code password} is empty
     */
    @SuppressWarnings("PMD.UseVarargs")
    public KeyringPassword(char[] password) {
        Objects.requireNonNull(password, "password must not be null");
        if (password.length == 0) {
            throw new IllegalArgumentException("password must not be empty");
        }
        this.password = password.clone();
    }

    /**
     * Returns a receiver-owned password copy.
     *
     * @return a new mutable array that the receiver must clear
     * @throws IllegalStateException if this object has been destroyed
     */
    public char[] copy() {
        lifecycleLock.lock();
        try {
            if (destroyed) {
                throw new IllegalStateException("Keyring password is destroyed");
            }
            return password.clone();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Clears the owned password characters.
     *
     * @throws DestroyFailedException never thrown by this implementation
     */
    @Override
    public void destroy() throws DestroyFailedException {
        lifecycleLock.lock();
        try {
            if (!destroyed) {
                Arrays.fill(password, '\0');
                destroyed = true;
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Reports whether the password has been destroyed.
     *
     * @return {@code true} after destruction
     */
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
     * Destroys the password.
     */
    @Override
    @SuppressWarnings("PMD.PreserveStackTrace")
    public void close() {
        try {
            destroy();
        } catch (DestroyFailedException impossible) {
            throw new IllegalStateException("Keyring password destruction failed");
        }
    }

    /**
     * Returns a redacted representation.
     *
     * @return a constant redacted value
     */
    @Override
    public String toString() {
        return "KeyringPassword[REDACTED]";
    }
}
