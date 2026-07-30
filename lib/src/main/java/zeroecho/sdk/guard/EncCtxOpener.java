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
import java.security.GeneralSecurityException;
import java.util.Objects;

import zeroecho.core.KeyUsage;
import zeroecho.core.context.EncryptionContext;
import zeroecho.sdk.ZeroEchoSession;

/**
 * Reusable opener for {@code CTX-ENC:<algorithm>} entries.
 *
 * <p>
 * Each applicable recipient entry receives a fresh decryption context from the
 * explicit session. A failed same-algorithm entry therefore cannot consume the
 * opener state needed by a later legitimate entry.
 * </p>
 */
public final class EncCtxOpener implements RecipientOpener {
    private final ZeroEchoSession session;

    /**
     * Creates an opener that derives contexts through the explicit session.
     *
     * @param session runtime configuration used for context creation
     * @throws NullPointerException if {@code session} is {@code null}
     */
    public EncCtxOpener(ZeroEchoSession session) {
        this.session = Objects.requireNonNull(session, "session");
    }

    @Override
    public byte[] tryOpen(String entryId, byte[] blob, UnlockMaterial material)
            throws IOException, GeneralSecurityException {
        if (entryId == null || !entryId.startsWith("CTX-ENC:")) {
            return null; // NOPMD
        }

        if (!(material instanceof UnlockMaterial.Private)) {
            return null; // NOPMD
        }
        String algorithmId = entryId.substring("CTX-ENC:".length());
        java.security.PrivateKey privateKey = ((UnlockMaterial.Private) material).key();
        try (EncryptionContext context = session.createContext(algorithmId, KeyUsage.DECRYPT, privateKey)) {
            return openWithContext(context, blob);
        }
    }

    private static byte[] openWithContext(EncryptionContext context, byte[] blob) throws IOException {
        try (InputStream s = context.attach(new ByteArrayInputStream(blob));
                ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            s.transferTo(out);
            return out.toByteArray();
        }
    }

}
