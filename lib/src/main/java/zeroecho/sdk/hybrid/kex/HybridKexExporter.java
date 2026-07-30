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
package zeroecho.sdk.hybrid.kex;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.sdk.util.Kdf;

/**
 * Deterministic exporter for deriving multiple independent keys from a single
 * hybrid KEX.
 *
 * <p>
 * Many protocols require more than one key from a single handshake (for
 * example, separate traffic keys for each direction, confirmation keys, or
 * application exporters). This class provides a minimal key schedule API over
 * HKDF-SHA256.
 * </p>
 *
 * <h2>Construction</h2>
 * <p>
 * The exporter is seeded by a caller-supplied secret (typically the output of
 * {@link HybridKexContext#deriveSecret()}). The exporter then derives sub-keys
 * by varying HKDF {@code info}.
 * </p>
 *
 * <h2>Security notes</h2>
 * <ul>
 * <li>Use distinct labels per purpose (for example {@code "app/tx"} vs
 * {@code "app/rx"}).</li>
 * <li>Bind transcript/context by including it in the {@code info} bytes.</li>
 * </ul>
 *
 * @since 1.0
 */
public final class HybridKexExporter implements Destroyable, AutoCloseable {

    private final byte[] rootSecret;
    private final byte[] salt;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Creates an exporter seeded from a root secret.
     *
     * @param rootSecret root secret (must not be null)
     * @param salt       optional HKDF salt (may be null)
     */
    public HybridKexExporter(byte[] rootSecret, byte[] salt) {
        Objects.requireNonNull(rootSecret, "rootSecret");
        this.rootSecret = rootSecret.clone();
        this.salt = (salt == null) ? null : salt.clone();
    }

    /**
     * Derives {@code outLenBytes} bytes for a specific purpose.
     *
     * @param label       ASCII/UTF-8 label identifying the purpose (must not be
     *                    null)
     * @param info        optional additional binding info (may be null)
     * @param outLenBytes output length in bytes (1..8160)
     * @return derived bytes
     * @throws IllegalArgumentException if outLenBytes is out of range
     */
    public byte[] export(String label, byte[] info, int outLenBytes) {
        lifecycleLock.lock();
        try {
            requireActive();
            Objects.requireNonNull(label, "label");

            if (outLenBytes < 1 || outLenBytes > 255 * 32) {
                throw new IllegalArgumentException("outLenBytes must be in range 1.." + (255 * 32));
            }

            byte[] labelBytes = label.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] infoUse;
            if (info == null || info.length == 0) {
                infoUse = labelBytes;
            } else {
                infoUse = new byte[labelBytes.length + 1 + info.length];
                System.arraycopy(labelBytes, 0, infoUse, 0, labelBytes.length);
                infoUse[labelBytes.length] = 0;
                System.arraycopy(info, 0, infoUse, labelBytes.length + 1, info.length);
            }

            try {
                return Kdf.hkdfSha256(rootSecret, salt, infoUse, outLenBytes);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("HKDF-SHA256 failed", e);
            } finally {
                Arrays.fill(labelBytes, (byte) 0);
                Arrays.fill(infoUse, (byte) 0);
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Returns a defensive copy of the exporter root secret.
     *
     * <p>
     * This is intended for diagnostics/testing only. Applications should prefer
     * {@link #export(String, byte[], int)}.
     * </p>
     *
     * @return copy of root secret
     */
    public byte[] rootSecretCopy() {
        lifecycleLock.lock();
        try {
            requireActive();
            return rootSecret.clone();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Overwrites the exporter root secret and salt.
     *
     * <p>
     * Destruction is idempotent. All subsequent export or diagnostic access fails
     * with {@link IllegalStateException}.
     * </p>
     */
    @Override
    public void destroy() {
        lifecycleLock.lock();
        try {
            if (!destroyed) {
                Arrays.fill(rootSecret, (byte) 0);
                if (salt != null) {
                    Arrays.fill(salt, (byte) 0);
                }
                destroyed = true;
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Reports whether this exporter has been destroyed.
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
     * Closes this exporter by destroying its retained secret material.
     */
    @Override
    public void close() {
        destroy();
    }

    private void requireActive() {
        if (destroyed) {
            throw new IllegalStateException("Hybrid KEX exporter has been destroyed");
        }
    }
}
