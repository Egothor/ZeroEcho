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
package zeroecho.sdk.content.builtin;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.SecretContent;
import zeroecho.sdk.util.Password;

/**
 * Destroyable password content backed exclusively by an owned character array.
 *
 * <p>
 * Textual diagnostics are always redacted. Callers obtain explicit copies
 * through {@link #chars()} or {@link #toBytes()} and remain responsible for
 * wiping those copies.
 * </p>
 *
 * <p>
 * Lifecycle operations are synchronized. Destruction is idempotent, wipes the
 * complete owned character array, and prevents subsequent access to password
 * material. Streams returned by {@link #getStream()} wipe their private UTF-8
 * buffer when closed.
 * </p>
 *
 * @author Leo Galambos
 */
public final class SecretPassword implements SecretContent, Destroyable {
    private static final String REDACTED = "[REDACTED]";
    private final char[] password;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Constructs a password with randomly generated printable characters.
     *
     * @param length the length of the generated passwordKey
     * @throws IllegalArgumentException if {@code length} is less than or equal to
     *                                  zero
     */
    public SecretPassword(final int length) {
        this(Password.generatePrintablePasswordChars(length), true);
    }

    /**
     * Constructs a password from a caller-owned character array. The supplied
     * array is cloned and remains owned by the caller.
     *
     * @param password password characters; must not be {@code null}
     * @throws NullPointerException if {@code password} is {@code null}
     */
    public SecretPassword(final char[] password) { // NOPMD - explicit array ownership is part of the API contract
        this(password, false);
    }

    private SecretPassword(final char[] password, final boolean takeOwnership) {
        Objects.requireNonNull(password, "password must not be null");
        this.password = takeOwnership ? password : password.clone();
    }

    /**
     * Returns an owned copy of the password characters.
     *
     * @return a newly allocated password copy
     * @throws IllegalStateException if this password has been destroyed
     */
    public char[] chars() {
        lifecycleLock.lock();
        try {
            ensureActive();
            return password.clone();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Returns a UTF-8 encoding owned by the caller.
     *
     * @return a newly allocated UTF-8 byte array
     * @throws IllegalStateException if this password has been destroyed
     */
    @Override
    public byte[] toBytes() {
        lifecycleLock.lock();
        try {
            ensureActive();
            ByteBuffer encoded = null;
            try {
                encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(password));
                final byte[] result = new byte[encoded.remaining()];
                encoded.get(result);
                return result;
            } catch (CharacterCodingException exception) {
                throw new IllegalStateException("Password could not be encoded", exception);
            } finally {
                if (encoded != null && encoded.hasArray()) {
                    Arrays.fill(encoded.array(), (byte) 0);
                }
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Returns a stream over a private UTF-8 buffer. Closing the stream wipes that
     * buffer.
     *
     * @return a stream that wipes its buffer when closed
     * @throws IllegalStateException if this password has been destroyed
     */
    @Override
    public InputStream getStream() {
        lifecycleLock.lock();
        try {
            ensureActive();
            return new DestroyingByteArrayInputStream(toBytes());
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Returns a redacted diagnostic representation.
     *
     * @return {@code "[REDACTED]"}
     */
    @Override
    public String toText() {
        return REDACTED;
    }

    /**
     * Returns a redacted diagnostic representation.
     *
     * @return {@code "[REDACTED]"}
     */
    @Override
    public String toString() {
        return REDACTED;
    }

    /**
     * Rejects preceding content because a password is a chain source.
     *
     * @param input preceding content; must be {@code null}
     * @throws IllegalArgumentException if {@code input} is non-null
     */
    @Override
    public void setInput(DataContent input) {
        if (input != null) {
            throw new IllegalArgumentException("SecretPassword must be the first content element");
        }
    }

    /** {@inheritDoc} */
    @Override
    public void destroy() {
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

    private void ensureActive() {
        if (destroyed) {
            throw new IllegalStateException("Password has been destroyed");
        }
    }

    /**
     * Byte-array stream that wipes its owned storage when closed.
     */
    private static final class DestroyingByteArrayInputStream extends ByteArrayInputStream {
        private final byte[] ownedBuffer;
        private boolean closed;

        private DestroyingByteArrayInputStream(final byte[] buffer) {
            super(buffer);
            ownedBuffer = buffer;
        }

        @Override
        public void close() {
            if (!closed) {
                Arrays.fill(ownedBuffer, (byte) 0);
                closed = true;
            }
        }
    }
}
