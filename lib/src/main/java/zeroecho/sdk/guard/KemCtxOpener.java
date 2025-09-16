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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Objects;

import javax.crypto.AEADBadTagException;

import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.KemContext;
import zeroecho.core.io.Util;
import zeroecho.sdk.util.Kdf;

/**
 * Opener for "KEM:&lt;algId&gt;:GCM-WRAP" entries. If a context is provided, it
 * is used directly; otherwise a context is derived from entryId and the
 * supplied private key.
 */
public final class KemCtxOpener implements RecipientOpener {
    private final KemContext provided; // may be null

    /** Derive the context on demand from entryId and private key. */
    public KemCtxOpener() {
        this.provided = null;
    }

    /**
     * Use the provided context once for the matching entry. The opener will consume
     * and close this context when used.
     */
    public KemCtxOpener(KemContext kem) {
        this.provided = Objects.requireNonNull(kem);
    }

    @Override
    public byte[] tryOpen(String entryId, byte[] entryBlob, UnlockMaterial material)
            throws GeneralSecurityException, IOException {
        if (entryId == null || !entryId.startsWith("KEM:")) {
            return null; // NOPMD
        }

        final int next = entryId.indexOf(':', 4);
        if (next <= 4) { // NOPMD
            return null; // NOPMD malformed id
        }
        final String kemId = entryId.substring(4, next);

        final KemContext kem;
        if (provided != null) {
            // Caller-supplied context (material not required)
            kem = provided;
        } else {
            if (!(material instanceof UnlockMaterial.Private)) {
                return null; // NOPMD
            }
            final java.security.PrivateKey prv = ((UnlockMaterial.Private) material).key();
            kem = CryptoAlgorithms.create(kemId, KeyUsage.DECAPSULATE, prv);
        }

        try (KemContext c = kem; ByteArrayInputStream in = new ByteArrayInputStream(entryBlob)) {
            byte[] kemCt = Util.read(in, 1 << 20);
            byte[] salt = Util.read(in, 64);
            byte[] wrapIv = Util.read(in, 64);
            byte[] wrapped = Util.read(in, 1 << 16);

            byte[] ss = c.decapsulate(kemCt);
            byte[] info = ("KDF:" + kem.algorithm().id()).getBytes(StandardCharsets.US_ASCII);
            byte[] kek = Kdf.hkdfSha256(ss, salt, info, 32);
            try {
                return MultiRecipientDataSourceBuilder.aesGcmUnwrap(kek, wrapIv, null, wrapped);
            } catch (AEADBadTagException e) {
                // Sender could have used 128-bit KEK
                kek = Kdf.hkdfSha256(ss, salt, "KEM:KEK".getBytes(StandardCharsets.UTF_8), 16);
                return MultiRecipientDataSourceBuilder.aesGcmUnwrap(kek, wrapIv, null, wrapped);
            }
        }
    }
}