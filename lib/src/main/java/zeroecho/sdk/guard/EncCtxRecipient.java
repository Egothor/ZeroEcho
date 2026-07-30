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

import zeroecho.core.context.EncryptionContext;

/**
 * Recipient implementation that delegates content-encryption key (CEK) wrapping
 * to a provided {@link EncryptionContext}.
 *
 * <p>
 * Unlike {@link KemCtxRecipient}, which derives a key-encryption key (KEK) via
 * key encapsulation, this class directly uses an existing
 * {@code EncryptionContext} to transform the CEK into a wrapped form. The CEK
 * is streamed through the context, and the transformed output is returned as a
 * recipient entry.
 * </p>
 *
 * <h2>Thread-safety</h2> This class is not thread-safe. Each instance binds to
 * a single {@code EncryptionContext} and must not be reused concurrently.
 *
 * @since 1.0
 */
public final class EncCtxRecipient implements Recipient, AutoCloseable {
    private final EncryptionContext enc;
    private final boolean decoy;
    private boolean closed;

    /**
     * Constructs a recipient that uses the given {@link EncryptionContext}.
     *
     * @param enc the encryption context used to wrap CEKs
     */
    public EncCtxRecipient(EncryptionContext enc) {
        this(enc, false);
    }

    /**
     * Constructs a recipient backed by the specified {@link EncryptionContext}.
     *
     * <p>
     * The provided encryption context is used to wrap content-encryption keys
     * (CEKs) for this recipient. A recipient may also be marked as a decoy to
     * obscure the number of real recipients in a multi-recipient envelope.
     * </p>
     *
     * @param enc   the encryption context used to perform CEK wrapping; must not be
     *              {@code null}
     * @param decoy {@code true} if this recipient is a decoy entry (fake recipient
     *              that cannot unwrap a CEK), {@code false} if it is a real
     *              recipient
     */
    public EncCtxRecipient(EncryptionContext enc, boolean decoy) {
        this.enc = enc;
        this.decoy = decoy;
    }

    /**
     * Returns the identifier string for this recipient mechanism.
     *
     * <p>
     * The format is {@code "CTX-ENC:<algoId>"} where {@code <algoId>} is the
     * canonical identifier of the underlying {@link EncryptionContext} algorithm.
     * </p>
     *
     * @return identifier string for this recipient type
     */
    @Override
    public String id() {
        return "CTX-ENC:" + enc.algorithm().id();
    }

    /**
     * Builds a recipient entry for the given content-encryption key (CEK).
     *
     * <p>
     * The CEK bytes are streamed through the attached {@link EncryptionContext},
     * and the encrypted result is returned. The resulting byte array represents the
     * recipient entry that can later be processed for decryption with the
     * corresponding context.
     * </p>
     *
     * @param cek the content-encryption key to wrap
     * @return the wrapped CEK encoded as a recipient entry
     * @throws IOException if streaming through the encryption context fails
     */
    @Override
    public byte[] buildRecipientEntry(byte[] cek) throws IOException {
        if (closed) {
            throw new IllegalStateException("Encryption recipient has been closed");
        }
        ByteArrayInputStream in = new ByteArrayInputStream(cek);
        try (InputStream s = enc.attach(in); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            s.transferTo(out);
            return out.toByteArray();
        } finally {
            close();
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

    /**
     * Closes the owned encryption context.
     *
     * @throws IOException if context cleanup fails
     */
    @Override
    public void close() throws IOException {
        if (!closed) {
            closed = true;
            enc.close();
        }
    }
}
