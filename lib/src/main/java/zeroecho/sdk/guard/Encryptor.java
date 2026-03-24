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
import java.util.List;
import java.util.Objects;

import javax.crypto.spec.SecretKeySpec;

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
final class Encryptor implements EncryptedContent {
    private final List<Recipient> recipients;
    private final AesDataContentBuilder aesBuilder;
    private final ChaChaDataContentBuilder chachaBuilder;
    private final int keyBytes;
    private final int maxRecipients;
    private final int maxEntryLen;
    private DataContent upstream;

    /* package */ Encryptor(List<Recipient> recipients, AesDataContentBuilder aesBuilder,
            ChaChaDataContentBuilder chachaBuilder, int keyBytes, int maxRecipients, int maxEntryLen) {
        this.recipients = recipients;
        this.aesBuilder = aesBuilder;
        this.chachaBuilder = chachaBuilder;
        this.keyBytes = keyBytes;
        this.maxRecipients = maxRecipients;
        this.maxEntryLen = maxEntryLen;
    }

    /**
     * Sets the upstream input to be encrypted.
     *
     * @param input the upstream content
     * @throws NullPointerException if {@code input} is null
     */
    @Override
    public void setInput(DataContent input) {
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
        Objects.requireNonNull(upstream, "encrypt: missing input");

        // 1) Generate CEK for payload
        byte[] cek = RandomSupport.generateRandom(keyBytes);
        byte[] cekDecoy = RandomSupport.generateRandom(keyBytes);

        // 2) Build recipient entries
        if (recipients.size() > maxRecipients) {
            throw new IOException("too many recipients: " + recipients.size());
        }
        ByteArrayOutputStream header = new ByteArrayOutputStream(1024);
        Util.writePack7I(header, recipients.size());
        for (Recipient r : recipients) {
            String id = r.id();
            Util.writeUTF8(header, id);
            try {
                byte[] blob = r.buildRecipientEntry(r.decoy() ? cekDecoy : cek);
                if (blob.length > maxEntryLen) {
                    throw new IOException("recipient entry too large: " + blob.length);
                }
                Util.write(header, blob);
            } catch (GeneralSecurityException e) {
                throw new IOException("recipient build failed for " + id, e);
            }
        }

        // 3) Configure symmetric stage (it owns its own header)
        final DataContent symmetric;
        if (aesBuilder != null) {
            symmetric = aesBuilder.withKey(new SecretKeySpec(cek, "AES")).build(true);
        } else {
            symmetric = chachaBuilder.withKey(new SecretKeySpec(cek, "ChaCha20")).build(true);
        }
        symmetric.setInput(upstream);

        // 4) Return [recipient header] + [symmetric payload stream]
        InputStream headerStream = new ByteArrayInputStream(header.toByteArray());
        InputStream payloadStream = symmetric.getStream();
        return new SequenceInputStream(headerStream, payloadStream);
    }
}
