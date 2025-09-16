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
import java.security.GeneralSecurityException;

/**
 * RecipientOpener attempts to recover a content-encryption key (CEK) from a
 * single recipient entry during decryption.
 *
 * <h2>Behavior</h2> Implementations examine the envelope header fields for one
 * recipient, optionally use the {@code entryId} as a hint, and try to derive or
 * unwrap the CEK from the opaque {@code entryBlob} using the provided
 * {@code UnlockMaterial}. In hardened configurations the {@code entryId} may be
 * an empty string; openers should still attempt a best-effort decode based on
 * the blob format and the supplied material.
 *
 * <p>
 * Return and failure semantics:
 * </p>
 * <ul>
 * <li>Return a non-null byte array containing the CEK on success.</li>
 * <li>Return {@code null} if this opener is clearly not applicable to the entry
 * (for example, mismatched id or unsupported blob format).</li>
 * <li>Throw {@link GeneralSecurityException} when the opener considers the
 * entry applicable but the cryptographic attempt fails (for example,
 * authentication failure, padding error, malformed ciphertext, or key
 * mismatch).</li>
 * <li>Throw {@link IOException} for structural or I/O errors while parsing the
 * blob (for example, truncated data).</li>
 * </ul>
 *
 * <p>
 * Implementation notes:
 * </p>
 * <ul>
 * <li>Openers are expected to be stateless and reusable; they must not retain
 * references to {@code UnlockMaterial} or the returned CEK.</li>
 * <li>Do not log sensitive values, and avoid timing-sensitive distinctions
 * beyond what the caller needs to continue scanning other entries.</li>
 * </ul>
 *
 * <p>
 * Typical scan loop:
 * </p>
 * <pre>{@code
 * for (RecipientOpener opener : openers) {
 *     try {
 *         byte[] cek = opener.tryOpen(entryId, entryBlob, material);
 *         if (cek != null) {
 *             // success; use CEK and stop scanning
 *             break;
 *         }
 *     } catch (javax.crypto.AEADBadTagException wrongKeyOrPassword) {
 *         // applicable but authentication failed; continue scanning others
 *     } catch (GeneralSecurityException ignore) {
 *         // not applicable or other crypto failure; continue scanning
 *     }
 * }
 * }</pre>
 */
interface RecipientOpener { // NOPMD
    /**
     * Tries to recover the content-encryption key from the supplied recipient
     * entry.
     *
     * @param entryId   identifier string written by the sender; may be empty when
     *                  labels are suppressed; used only as a routing hint
     * @param entryBlob opaque bytes of the recipient entry produced by the matching
     *                  {@code Recipient}; never null
     * @param material  unlocking material to use (for example, a private key or a
     *                  password); never null
     * @return a newly allocated byte array containing the recovered CEK, or
     *         {@code null} if this opener is not applicable
     * @throws GeneralSecurityException if the entry appears applicable but
     *                                  cryptographic verification or unwrapping
     *                                  fails
     * @throws IOException              if parsing the entry blob fails due to
     *                                  structural errors or truncated data
     */
    byte[] tryOpen(String entryId, byte[] entryBlob, UnlockMaterial material)
            throws GeneralSecurityException, IOException;
}
