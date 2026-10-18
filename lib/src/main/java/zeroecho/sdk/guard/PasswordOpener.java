/* *****************************************************************************
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

import javax.crypto.AEADBadTagException;

import zeroecho.core.io.Util;
import zeroecho.sdk.Pbkdf2Limits;

/**
 * Recipient opener for password-based entries that derives a KEK via PBKDF2 and
 * unwraps the CEK with AES-GCM.
 */
public final class PasswordOpener implements RecipientOpener {
    private final Pbkdf2Limits limits;

    /**
     * Creates an opener with explicit decoded-input limits.
     *
     * @param limits PBKDF2 safety limits
     */
    public PasswordOpener(Pbkdf2Limits limits) {
        this.limits = java.util.Objects.requireNonNull(limits, "limits must not be null");
    }

    /**
     * Attempts to open a password-based recipient entry using a password unlock
     * material.
     *
     * @param entryId   the recipient entry identifier
     * @param entryBlob the recipient entry blob encoding
     *                  {@code iter || salt || iv || wrappedCEK}
     * @param material  the unlocking material; must contain a password
     * @return the recovered CEK or {@code null} if {@code entryId} does not match
     *         the password scheme or material is not applicable
     * @throws GeneralSecurityException if PBKDF2 or AES-GCM fails or if
     *                                  authentication fails after a match
     * @throws IOException              if entry decoding fails
     */
    @Override
    public byte[] tryOpen(String entryId, byte[] entryBlob, UnlockMaterial material)
            throws GeneralSecurityException, IOException {
        if (!"PWD:PBKDF2-SHA256:GCM-WRAP".equals(entryId)) {
            return null; // NOPMD
        }
        if (!(material instanceof UnlockMaterial.Password)) {
            return null; // NOPMD
        }

        ByteArrayInputStream in = new ByteArrayInputStream(entryBlob);
        int iterations = Util.readPack7I(in);
        try {
            limits.validateDecoded(iterations);
        } catch (IllegalArgumentException exception) {
            throw new IOException("Invalid decoded PBKDF2 iteration count", exception);
        }
        byte[] salt = Util.read(in, 64);
        byte[] wrapIv = Util.read(in, 64);
        byte[] wrapped = Util.read(in, 1 << 16);

        char[] password = ((UnlockMaterial.Password) material).password();
        byte[] kek = null;
        try {
            kek = MultiRecipientDataSourceBuilder.pbkdf2HmacSha256(password, salt, iterations, 32);
            try {
                return MultiRecipientDataSourceBuilder.aesGcmUnwrap(kek, wrapIv, null, wrapped);
            } catch (AEADBadTagException e256) {
                Arrays.fill(kek, (byte) 0);
                kek = MultiRecipientDataSourceBuilder.pbkdf2HmacSha256(password, salt, iterations, 16);
                return MultiRecipientDataSourceBuilder.aesGcmUnwrap(kek, wrapIv, null, wrapped);
            }
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(wrapIv, (byte) 0);
            Arrays.fill(wrapped, (byte) 0);
            if (kek != null) {
                Arrays.fill(kek, (byte) 0);
            }
        }
    }
}
