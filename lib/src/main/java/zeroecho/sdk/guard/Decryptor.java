/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.sdk.guard;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.AEADBadTagException;
import javax.crypto.spec.SecretKeySpec;

import zeroecho.core.io.Util;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.alg.ChaChaDataContentBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;

/**
 * Decrypting stage that scans recipient entries to recover the CEK and then
 * delegates to the symmetric builder.
 */
final class Decryptor implements PlainContent {
    private static final Logger LOG = Logger.getLogger(Decryptor.class.getName());

    private final List<RecipientOpener> openers;
    private final UnlockMaterial material;
    private final AesDataContentBuilder aesBuilder;
    private final ChaChaDataContentBuilder chachaBuilder;
    private final int keyBytes;
    private final int maxRecipients;
    private final int maxEntryLen;
    private DataContent upstream;

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
        Objects.requireNonNull(upstream, "decrypt: missing input");
        InputStream in = upstream.getStream(); // NOPMD

        // 1) Read recipients
        int count = Util.readPack7I(in);
        if (count < 0 || count > maxRecipients) {
            in.close();
            throw new IOException("invalid recipient count: " + count);
        }

        String matchedId = null;
        byte[] cek = null;

        for (int i = 0; i < count; i++) {
            String id = Util.readUTF8(in, 256); // reasonable max id length
            byte[] blob = Util.read(in, maxEntryLen);

            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "round {0} id {1} material {2}", new Object[] { i, id, material.description() }); // NOPMD
            }

            for (RecipientOpener op : openers) {
                if (LOG.isLoggable(Level.FINE)) {
                    LOG.log(Level.FINE, "testing {0}", op.getClass().getName());
                }
                try {
                    byte[] maybe = op.tryOpen(id, blob, material);
                    if (maybe != null) {
                        if (maybe.length > keyBytes) {
                            if (LOG.isLoggable(Level.WARNING)) {
                                LOG.log(Level.WARNING,
                                        "Suspicious material in field {0}: {1}/{2} finds the secret of length {3}, while {4} is a limit. Ignoring.",
                                        new Object[] { i, id, op.toString(), maybe.length, keyBytes }); // NOPMD
                            }
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
                    LOG.log(Level.FINE, "failed AEAD {0}", ex);
                } catch (GeneralSecurityException | IOException | IllegalArgumentException ex) {
                    // entry not applicable to this opener/material; ignore and continue
                    LOG.log(Level.FINE, "failed {0}", ex);
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

        // 2) Build symmetric decrypt stage and feed the remaining stream
        final DataContent symmetric;
        if (aesBuilder != null) {
            symmetric = aesBuilder.withKey(new SecretKeySpec(cek, "AES")).build(false);
        } else {
            symmetric = chachaBuilder.withKey(new SecretKeySpec(cek, "ChaCha20")).build(false);
        }
        symmetric.setInput(new TailDataContent(in));
        return symmetric.getStream();
    }
}