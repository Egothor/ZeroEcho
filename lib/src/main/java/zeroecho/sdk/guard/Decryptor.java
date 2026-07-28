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

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.AEADBadTagException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import zeroecho.core.io.Util;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.alg.ChaChaDataContentBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;

/**
 * Decrypting stage that scans recipient entries to recover the CEK and then
 * delegates to the symmetric builder.
 */
final class Decryptor implements PlainContent, MultiRecipientContent {
    private static final Logger LOG = Logger.getLogger(Decryptor.class.getName());

    private final List<RecipientOpener> openers;
    private final UnlockMaterial material;
    private final AesDataContentBuilder aesBuilder;
    private final ChaChaDataContentBuilder chachaBuilder;
    private final int keyBytes;
    private final int maxRecipients;
    private final int maxEntryLen;
    private DataContent upstream;
    private boolean closed;

    /* package */ Decryptor(List<RecipientOpener> openers, UnlockMaterial material, AesDataContentBuilder aesBuilder,
            ChaChaDataContentBuilder chachaBuilder, int keyBytes, int maxRecipients, int maxEntryLen) {
        this.openers = openers;
        this.material = material;
        this.aesBuilder = aesBuilder;
        this.chachaBuilder = chachaBuilder;
        this.keyBytes = keyBytes;
        this.maxRecipients = maxRecipients;
        this.maxEntryLen = maxEntryLen;
    }

    /**
     * Sets the upstream encrypted input to be decrypted.
     *
     * @param input the upstream encrypted content
     * @throws NullPointerException if {@code input} is null
     */
    @Override
    public void setInput(DataContent input) {
        ensureOpen();
        this.upstream = Objects.requireNonNull(input);
    }

    /**
     * Returns a stream that yields the plaintext by first recovering the CEK from
     * recipient entries and then delegating to the symmetric builder to process its
     * own header and ciphertext.
     *
     * @return an input stream over the plaintext
     * @throws IOException if header parsing fails, if CEK cannot be recovered, or
     *                     if symmetric stage fails
     */
    @Override
    public InputStream getStream() throws IOException { // NOPMD
        ensureOpen();
        InputStream in = null; // NOPMD
        String matchedId = null;
        byte[] cek = null;
        Throwable failure = null;
        boolean transferred = false;
        try {
            Objects.requireNonNull(upstream, "decrypt: missing input");
            in = upstream.getStream();
            // 1) Read recipients
            int count = Util.readPack7I(in);
            if (count < 0 || count > maxRecipients) {
                throw new IOException("invalid recipient count: " + count);
            }

            for (int i = 0; i < count; i++) {
                String id = Util.readUTF8(in, 256); // reasonable max id length
                byte[] blob = Util.read(in, maxEntryLen);

                if (LOG.isLoggable(Level.FINE)) {
                    LOG.log(Level.FINE, "round {0} id {1} material {2}",
                            new Object[] { i, id, material.description() }); // NOPMD
                }

                for (RecipientOpener op : openers) { // NOPMD - owned openers close in closeAfterAttempt
                    if (LOG.isLoggable(Level.FINE)) {
                        LOG.log(Level.FINE, "testing {0}", op.getClass().getName());
                    }
                    try {
                        byte[] maybe = op.tryOpen(id, blob, material);
                        if (maybe != null) {
                            if (maybe.length > keyBytes) {
                                rejectOversizedCek(maybe, i, id, op);
                            } else {
                                cek = maybe;
                                matchedId = id;
                                if (LOG.isLoggable(Level.FINE)) {
                                    LOG.log(Level.FINE, "*** match with {0} ***", op.getClass().getName());
                                }
                                break;
                            }
                        }
                    } catch (AEADBadTagException ex) {
                        // wrong key/password for that entry, continue scanning
                        if (LOG.isLoggable(Level.FINE)) {
                            LOG.log(Level.FINE, "recipient authentication failed: {0}",
                                    ex.getClass().getSimpleName());
                        }
                    } catch (GeneralSecurityException | IOException | IllegalArgumentException ex) {
                        // entry not applicable to this opener/material; ignore and continue
                        if (LOG.isLoggable(Level.FINE)) {
                            LOG.log(Level.FINE, "recipient opener failed: {0}", ex.getClass().getSimpleName());
                        }
                    }
                }
                if (cek != null) {
                    // Skip remaining recipient entries if any
                    for (int j = i + 1; j < count; j++) {
                        Util.readUTF8(in, 256);
                        Util.read(in, maxEntryLen);
                    }
                    break;
                }
            }

            if (cek == null) {
                throw new IOException("unable to unlock CEK with provided material");
            }

            LOG.log(Level.INFO, "found={0}", matchedId);

            close();

            // 2) Build symmetric decrypt stage and feed the remaining stream
            final DataContent symmetric;
            if (aesBuilder != null) {
                symmetric = aesBuilder.withKey(new SecretKeySpec(cek, "AES")).build(false);
            } else {
                symmetric = chachaBuilder.withKey(new SecretKeySpec(cek, "ChaCha20")).build(false);
            }
            symmetric.setInput(new TailDataContent(in));
            InputStream result = symmetric.getStream();
            transferred = true;
            return result;
        } catch (IOException | RuntimeException | Error exception) { // NOPMD - retain primary failure
            failure = exception;
            throw exception;
        } finally {
            if (cek != null) {
                Arrays.fill(cek, (byte) 0);
            }
            closeAfterAttempt(in, transferred, failure);
        }
    }

    private void closeAfterAttempt(InputStream input, boolean transferred, Throwable primary)
            throws IOException {
        IOException cleanupFailure = null;
        if (!transferred) {
            try {
                closeRejectedInput(input, primary);
            } catch (IOException exception) {
                cleanupFailure = exception;
            }
        }
        Throwable effectivePrimary = primary == null ? cleanupFailure : primary;
        try {
            closeWithPrimary(effectivePrimary);
        } catch (IOException exception) {
            cleanupFailure = exception;
        }
        if (primary == null && cleanupFailure != null) {
            throw cleanupFailure;
        }
    }

    private static void closeRejectedInput(InputStream input, Throwable primary) throws IOException {
        if (input == null) {
            return;
        }
        try {
            input.close();
        } catch (IOException cleanupFailure) {
            if (primary != null) {
                primary.addSuppressed(cleanupFailure);
            } else {
                throw cleanupFailure;
            }
        }
    }

    /**
     * Releases opener-owned resources after scanning or abandonment.
     *
     * @throws IOException if opener cleanup fails
     */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        closeOpeners(openers, null);
    }

    /**
     * Destroys opener-owned resources after scanning or abandonment.
     *
     * @throws DestroyFailedException if opener cleanup fails
     */
    @Override
    public void destroy() throws DestroyFailedException {
        try {
            close();
        } catch (IOException exception) {
            DestroyFailedException failure = new DestroyFailedException("Recipient opener cleanup failed");
            failure.initCause(exception);
            throw failure;
        }
    }

    /**
     * Reports whether opener-owned resources have been released.
     *
     * @return {@code true} after processing or explicit cleanup
     */
    @Override
    public boolean isDestroyed() {
        return closed;
    }

    private void closeWithPrimary(Throwable primary) throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        closeOpeners(openers, primary);
    }

    /* default */ static void closeOpeners(List<RecipientOpener> ownedOpeners, Throwable primary)
            throws IOException {
        IOException cleanupFailure = null;
        for (RecipientOpener opener : ownedOpeners) { // NOPMD - each opener is closed in this loop
            try {
                opener.close();
            } catch (IOException wrapped) {
                if (primary != null) {
                    primary.addSuppressed(wrapped);
                } else if (cleanupFailure == null) {
                    cleanupFailure = wrapped;
                } else {
                    cleanupFailure.addSuppressed(wrapped);
                }
            }
        }
        if (primary == null && cleanupFailure != null) {
            throw cleanupFailure;
        }
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("Multi-recipient decrypting content has been closed");
        }
    }

    private void rejectOversizedCek(byte[] candidate, int fieldIndex, String recipientId,
            RecipientOpener opener) {
        try {
            if (LOG.isLoggable(Level.WARNING)) {
                LOG.log(Level.WARNING,
                        "Suspicious material in field {0}: {1}/{2} returned length {3}, while {4} is the limit. Ignoring.",
                        new Object[] { fieldIndex, recipientId, opener.getClass().getName(),
                                candidate.length, keyBytes });
            }
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
    }
}
