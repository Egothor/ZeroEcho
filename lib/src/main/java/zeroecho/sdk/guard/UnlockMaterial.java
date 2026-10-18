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
