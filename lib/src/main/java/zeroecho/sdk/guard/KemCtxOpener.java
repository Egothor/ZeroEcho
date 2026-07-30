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
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.AEADBadTagException;

import zeroecho.core.KeyUsage;
import zeroecho.core.context.KemContext;
import zeroecho.core.io.Util;
import zeroecho.sdk.ZeroEchoSession;

/**
 * Reusable opener for {@code KEM:<algorithm>:GCM-WRAP} entries.
 *
 * <p>
 * Each applicable recipient entry receives a fresh decapsulation context from
 * the explicit session. A failed same-algorithm entry therefore cannot consume
 * the opener state needed by a later legitimate entry.
 * </p>
 */
public final class KemCtxOpener implements RecipientOpener {
    private final ZeroEchoSession session;

    /**
     * Creates an opener that derives contexts through the explicit session.
     *
     * @param session runtime configuration used for context creation
     * @throws NullPointerException if {@code session} is {@code null}
     */
    public KemCtxOpener(ZeroEchoSession session) {
        this.session = Objects.requireNonNull(session, "session");
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
        if (!(material instanceof UnlockMaterial.Private)) {
            return null; // NOPMD
        }
        final String kemId = entryId.substring(4, next);
        java.security.PrivateKey privateKey = ((UnlockMaterial.Private) material).key();
        try (KemContext kem = session.createContext(kemId, KeyUsage.DECAPSULATE, privateKey)) {
            return openWithContext(kem, entryBlob);
        }
    }

    private static byte[] openWithContext(KemContext kem, byte[] entryBlob)
            throws GeneralSecurityException, IOException {
        try (ByteArrayInputStream in = new ByteArrayInputStream(entryBlob)) {
            byte[] kemCt = Util.read(in, 1 << 20);
            byte[] salt = Util.read(in, 64);
            byte[] wrapIv = Util.read(in, 64);
            byte[] wrapped = Util.read(in, 1 << 16);

            byte[] ss = kem.decapsulate(kemCt);
            byte[] kek = null;
            try {
                try {
                    kek = KemKeyDerivation.derive(ss, salt, kem.algorithm().id(), 32);
                    return MultiRecipientDataSourceBuilder.aesGcmUnwrap(kek, wrapIv, null, wrapped);
                } catch (AEADBadTagException exception) {
                    Arrays.fill(kek, (byte) 0);
                    kek = KemKeyDerivation.derive(ss, salt, kem.algorithm().id(), 16);
                    return MultiRecipientDataSourceBuilder.aesGcmUnwrap(kek, wrapIv, null, wrapped);
                }
            } finally {
                Arrays.fill(ss, (byte) 0);
                if (kek != null) {
                    Arrays.fill(kek, (byte) 0);
                }
            }
        }
    }

}
