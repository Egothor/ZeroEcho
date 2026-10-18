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
