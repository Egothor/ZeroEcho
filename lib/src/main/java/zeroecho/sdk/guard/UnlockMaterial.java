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

import zeroecho.core.annotation.Describable;

/**
 * UnlockMaterial represents the unlocking data supplied to a recipient opener
 * to recover a content-encryption key (CEK).
 *
 * <h2>Overview</h2> The multi-recipient envelope scans recipient entries and
 * delegates each attempt to a {@code RecipientOpener}. An opener may require
 * either a private key or a password to unwrap or derive the CEK. This sealed
 * interface defines the two supported kinds of unlocking material and
 * centralizes their lifetime and handling.
 *
 * <h2>Usage</h2> <pre>{@code
 * // Decrypt with a private key
 * DataContent decRsa = new MultiRecipientDataSourceBuilder()
 *     .withAes(AesDataContentBuilder.builder().modeGcm(128).withHeader())
 *     .payloadKeyBytes(32)
 *     .unlockWith(new UnlockMaterial.Private(rsaPrivateKey))
 *     .build(false);
 *
 * // Decrypt with a password
 * char[] pwd = "correct horse battery staple".toCharArray();
 * DataContent decPwd = new MultiRecipientDataSourceBuilder()
 *     .withAes(AesDataContentBuilder.builder().modeCbcPkcs7().withHeader())
 *     .payloadKeyBytes(32)
 *     .unlockWith(new UnlockMaterial.Password(pwd))
 *     .build(false);
 * // Clear the password when no longer needed
 * java.util.Arrays.fill(pwd, '\0');
 * }</pre>
 *
 * <h2>Security notes</h2>
 * <ul>
 * <li>{@link Password} stores a reference to the caller-provided {@code char[]}
 * for performance and zeroization. The caller is responsible for clearing the
 * array after use.</li>
 * <li>{@link Private} holds a {@link java.security.PrivateKey}. Manage the
 * key's lifetime outside the opener and avoid logging or copying it
 * unnecessarily.</li>
 * </ul>
 */
sealed public interface UnlockMaterial extends Describable {
    /**
     * Private holds a private key used to decrypt or decapsulate a recipient entry.
     *
     * <p>
     * Typical uses include RSA-OAEP decryption, ElGamal decryption, or KEM
     * decapsulation with a private KEM key.
     * </p>
     *
     * @param key the private key used by a matching {@code RecipientOpener}; must
     *            not be null
     */
    record Private(java.security.PrivateKey key) implements UnlockMaterial, Describable {

        @Override
        public String description() {
            return "Unlock via key of " + key.getAlgorithm();
        }
    }

    /**
     * Password holds characters used to derive a key-encryption key (KEK) for
     * unwrapping the CEK.
     *
     * <p>
     * The array reference is stored as provided to allow the caller to clear it
     * after use. If defensive copying is desired, the caller should provide a copy
     * and clear both copies after decryption.
     * </p>
     *
     * @param password the password characters; the caller should clear the array
     *                 when no longer needed
     */
    record Password(char[] password) implements UnlockMaterial, Describable {

        @Override
        public String description() {
            return "Unlock via password";
        }
    }
}
