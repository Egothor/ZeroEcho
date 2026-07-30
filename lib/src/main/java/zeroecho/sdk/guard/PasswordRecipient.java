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
package zeroecho.sdk.guard;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.io.Util;
import zeroecho.core.util.RandomSupport;
import zeroecho.sdk.Pbkdf2Limits;

/**
 * Password recipient that derives a KEK via PBKDF2(HMAC-SHA-256) and wraps the
 * CEK with AES-GCM.
 */
public final class PasswordRecipient implements Recipient, Destroyable, AutoCloseable {
    private final char[] password;
    private final int iterations;
    private final int saltLen;
    private final int kekBytes;
    private final boolean decoy;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Creates a password-based recipient that derives a key-encryption key (KEK)
     * using PBKDF2.
     *
     * <p>
     * The supplied password is expanded with PBKDF2 using the provided iteration
     * count and a randomly generated salt of the specified length. The result is a
     * KEK of the requested size in bytes, which is then used to wrap the
     * content-encryption key (CEK) for this recipient. A recipient may also be
     * marked as a decoy to obscure the actual number of usable recipients.
     * </p>
     *
     * <h4>Security considerations</h4>
     * <ul>
     * <li>The caller should clear the {@code password} array after constructing the
     * recipient to minimize exposure in memory.</li>
     * <li>Choose an iteration count appropriate to the target platform to balance
     * password-guessing resistance against recipient creation and opening
     * latency. Counts below {@value Pbkdf2Limits#MINIMUM} are rejected.</li>
     * <li>Decoy recipients increase confidentiality by hiding the number of real
     * recipients but cannot successfully unwrap the CEK.</li>
     * </ul>
     *
     * @param password   the password used as input to PBKDF2; must not be
     *                   {@code null}
     * @param iterations the PBKDF2 iteration count; must be at least
     *                   {@value Pbkdf2Limits#MINIMUM}
     * @param saltLen    length of the random salt (in bytes)
     * @param kekBytes   derived KEK length; exactly 16 or 32 bytes
     * @param decoy      {@code true} if this is a decoy recipient (fake entry that
     *                   cannot unwrap a CEK); {@code false} if it is a real
     *                   recipient
     * @throws NullPointerException     if {@code password} is {@code null}
     * @throws IllegalArgumentException if {@code iterations} is below
     *                                  {@value Pbkdf2Limits#MINIMUM} or
     *                                  {@code kekBytes} is not exactly 16 or 32
     */
    /* default */ PasswordRecipient(char[] password, int iterations, int saltLen, int kekBytes, boolean decoy,
            Pbkdf2Limits limits) {
        int validatedKekBytes = RecipientKekSizes.requireSupported(kekBytes);
        Objects.requireNonNull(limits, "limits must not be null").validateTrusted(iterations);
        this.password = Objects.requireNonNull(password, "password must not be null").clone();
        this.iterations = iterations;
        this.saltLen = saltLen;
        this.kekBytes = validatedKekBytes;
        this.decoy = decoy;
    }

    /**
     * Returns the recipient entry identifier used in the header.
     *
     * @return {@code "PWD:PBKDF2-SHA256:GCM-WRAP"}
     */
    @Override
    public String id() {
        return "PWD:PBKDF2-SHA256:GCM-WRAP";
    }

    /**
     * Builds the recipient entry blob for this password recipient.
     *
     * @param cek the CEK to wrap
     * @return a blob containing {@code pack7(iter) || salt || wrapIv || wrappedCEK}
     * @throws GeneralSecurityException if PBKDF2 or AES-GCM fails
     * @throws IOException              if blob assembly fails
     */
    @Override
    public byte[] buildRecipientEntry(byte[] cek) throws GeneralSecurityException, IOException {
        lifecycleLock.lock();
        try {
            if (destroyed) {
                throw new IllegalStateException("Password recipient has been destroyed");
            }
            byte[] salt = RandomSupport.generateRandom(saltLen);
            byte[] kek = MultiRecipientDataSourceBuilder.pbkdf2HmacSha256(password, salt, iterations, kekBytes);
            try {
                byte[] wrapIv = RandomSupport.generateRandom(12);
                byte[] wrapped = MultiRecipientDataSourceBuilder.aesGcmWrap(kek, wrapIv, null, cek);

                ByteArrayOutputStream out = new ByteArrayOutputStream(64 + wrapped.length);
                Util.writePack7I(out, iterations);
                Util.write(out, salt);
                Util.write(out, wrapIv);
                Util.write(out, wrapped);
                return out.toByteArray();
            } finally {
                Arrays.fill(kek, (byte) 0);
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Returns whether this recipient entry is marked as a decoy.
     *
     * <p>
     * A decoy recipient is syntactically valid but intentionally unusable for
     * recovering the content-encryption key (CEK). Such entries are included to
     * conceal the number and identity of real recipients within a multi-recipient
     * envelope.
     * </p>
     *
     * @return {@code true} if this recipient is a decoy (fake recipient that cannot
     *         unwrap a CEK); {@code false} if it is a real recipient
     */
    @Override
    public boolean decoy() {
        return decoy;
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

    /**
     * Closes this recipient by destroying its retained password copy.
     */
    @Override
    public void close() {
        destroy();
    }
}
