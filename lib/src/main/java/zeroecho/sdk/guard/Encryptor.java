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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.IntFunction;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import zeroecho.core.io.Util;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.alg.ChaChaDataContentBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.EncryptedContent;
import zeroecho.sdk.util.RandomSupport;

/**
 * Encrypting stage that emits the recipient table followed by the symmetric
 * builder output.
 */
final class Encryptor implements EncryptedContent, MultiRecipientContent {
    private final List<Recipient> recipients;
    private final AesDataContentBuilder aesBuilder;
    private final ChaChaDataContentBuilder chachaBuilder;
    private final int keyBytes;
    private final int maxRecipients;
    private final int maxEntryLen;
    private final IntFunction<byte[]> randomBytesFactory;
    private DataContent upstream;
    private boolean closed;

    /* package */ Encryptor(List<Recipient> recipients, AesDataContentBuilder aesBuilder,
            ChaChaDataContentBuilder chachaBuilder, int keyBytes, int maxRecipients, int maxEntryLen) {
        this(recipients, aesBuilder, chachaBuilder, keyBytes, maxRecipients, maxEntryLen,
                RandomSupport::generateRandom);
    }

    /* package */ Encryptor(List<Recipient> recipients, AesDataContentBuilder aesBuilder,
            ChaChaDataContentBuilder chachaBuilder, int keyBytes, int maxRecipients, int maxEntryLen,
            IntFunction<byte[]> randomBytesFactory) {
        this.recipients = recipients;
        this.aesBuilder = aesBuilder;
        this.chachaBuilder = chachaBuilder;
        this.keyBytes = keyBytes;
        this.maxRecipients = maxRecipients;
        this.maxEntryLen = maxEntryLen;
        this.randomBytesFactory = Objects.requireNonNull(randomBytesFactory,
                "randomBytesFactory must not be null");
    }

    /**
     * Sets the upstream input to be encrypted.
     *
     * @param input the upstream content
     * @throws NullPointerException if {@code input} is null
     */
    @Override
    public void setInput(DataContent input) {
        ensureOpen();
        this.upstream = Objects.requireNonNull(input);
    }

    /**
     * Returns a stream that yields the recipient header followed by the symmetric
     * payload stream.
     *
     * @return an input stream over the envelope and ciphertext
     * @throws IOException if building recipient entries fails or if upstream is
     *                     missing
     */
    @Override
    public InputStream getStream() throws IOException {
        ensureOpen();
        byte[] cek = null;
        byte[] decoyCek = null;
        Throwable failure = null;
        try {
            Objects.requireNonNull(upstream, "encrypt: missing input");
            if (recipients.size() > maxRecipients) {
                throw new IOException("too many recipients: " + recipients.size());
            }
            cek = requireRandomKey(randomBytesFactory.apply(keyBytes), keyBytes);
            try (ByteArrayOutputStream header = new ByteArrayOutputStream(1024)) {
                Util.writePack7I(header, recipients.size());
                for (Recipient recipient : recipients) {
                    String id = recipient.id();
                    Util.writeUTF8(header, id);
                    try {
                        byte[] recipientCek = cek;
                        if (recipient.decoy()) {
                            if (decoyCek == null) {
                                decoyCek = requireRandomKey(randomBytesFactory.apply(keyBytes), keyBytes);
                            }
                            recipientCek = decoyCek;
                        }
                        byte[] blob = recipient.buildRecipientEntry(recipientCek);
                        if (blob.length > maxEntryLen) {
                            throw new IOException("recipient entry too large: " + blob.length);
                        }
                        Util.write(header, blob);
                    } catch (GeneralSecurityException exception) {
                        throw new IOException("recipient build failed for " + id, exception);
                    }
                }

                final DataContent symmetric;
                if (aesBuilder != null) {
                    symmetric = aesBuilder.withKey(new SecretKeySpec(cek, "AES")).build(true);
                } else {
                    symmetric = chachaBuilder.withKey(new SecretKeySpec(cek, "ChaCha20")).build(true);
                }
                symmetric.setInput(upstream);

                InputStream headerStream = new ByteArrayInputStream(header.toByteArray());
                InputStream payloadStream = symmetric.getStream();
                return new SequenceInputStream(headerStream, payloadStream);
            }
        } catch (IOException | RuntimeException | Error exception) { // NOPMD - retain primary failure
            failure = exception;
            throw exception;
        } finally {
            if (cek != null) {
                Arrays.fill(cek, (byte) 0);
            }
            if (decoyCek != null) {
                Arrays.fill(decoyCek, (byte) 0);
            }
            closeWithPrimary(failure);
        }
    }

    /**
     * Releases recipient resources that have not yet been consumed.
     *
     * @throws IOException if recipient cleanup fails
     */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        closeRecipients(recipients, null);
    }

    /**
     * Destroys recipient resources that have not yet been consumed.
     *
     * @throws DestroyFailedException if recipient cleanup fails
     */
    @Override
    public void destroy() throws DestroyFailedException {
        try {
            close();
        } catch (IOException exception) {
            DestroyFailedException failure = new DestroyFailedException("Recipient cleanup failed");
            failure.initCause(exception);
            throw failure;
        }
    }

    /**
     * Reports whether recipient resources have been released.
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
        closeRecipients(recipients, primary);
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("Multi-recipient encrypting content has been closed");
        }
    }

    private static byte[] requireRandomKey(byte[] key, int expectedLength) {
        Objects.requireNonNull(key, "random source returned null");
        if (key.length != expectedLength) {
            Arrays.fill(key, (byte) 0);
            throw new IllegalStateException("random source returned an invalid key length");
        }
        return key;
    }

    /* default */ static void closeRecipients(List<Recipient> ownedRecipients, Throwable primary)
            throws IOException {
        IOException cleanupFailure = null;
        for (Recipient recipient : ownedRecipients) {
            try {
                closeRecipient(recipient);
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

    @SuppressWarnings("PMD.CloseResource") // type-pattern variables are closed immediately in every matching branch
    private static void closeRecipient(Recipient recipient) throws IOException {
        if (recipient instanceof PasswordRecipient passwordRecipient) {
            passwordRecipient.close();
        } else if (recipient instanceof KemCtxRecipient kemRecipient) {
            kemRecipient.close();
        } else if (recipient instanceof EncCtxRecipient encryptionRecipient) {
            encryptionRecipient.close();
        }
    }
}
