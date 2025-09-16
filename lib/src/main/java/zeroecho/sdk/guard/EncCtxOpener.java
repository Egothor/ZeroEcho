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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Objects;

import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.EncryptionContext;

/**
 * Opener that recognizes "CTX-ENC:&lt;algId&gt;" entries and attempts CEK
 * recovery using an {@link EncryptionContext} in DECRYPT role. If constructed
 * without a context, it derives one from the entryId and the supplied private
 * key.
 */
public final class EncCtxOpener implements RecipientOpener {
    private final EncryptionContext provided; // may be null

    /** Derive the context on demand from entryId and private key. */
    public EncCtxOpener() {
        this.provided = null;
    }

    /**
     * Use the provided context once for the matching entry. The opener will consume
     * and close this context when used.
     */
    public EncCtxOpener(EncryptionContext ctx) {
        this.provided = Objects.requireNonNull(ctx);
    }

    @Override
    public byte[] tryOpen(String entryId, byte[] blob, UnlockMaterial material)
            throws IOException, GeneralSecurityException {
        if (entryId == null || !entryId.startsWith("CTX-ENC:")) {
            return null; // NOPMD
        }

        final EncryptionContext dec;
        if (provided != null) {
            dec = provided;
        } else {
            if (!(material instanceof UnlockMaterial.Private)) {
                return null; // NOPMD
            }
            final String algId = entryId.substring("CTX-ENC:".length());
            final java.security.PrivateKey priv = ((UnlockMaterial.Private) material).key();
            dec = CryptoAlgorithms.create(algId, KeyUsage.DECRYPT, priv);
        }

        try (dec;
                InputStream s = dec.attach(new ByteArrayInputStream(blob));
                ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            s.transferTo(out);
            return out.toByteArray();
        }
    }
}