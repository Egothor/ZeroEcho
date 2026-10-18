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

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Recipient describes how to encode a single recipient entry that can recover a
 * content-encryption key (CEK) during decryption.
 *
 * <h2>Responsibilities</h2> Implementations provide a stable identifier and
 * produce an opaque binary blob that contains everything the matching
 * {@code RecipientOpener} needs to recover the CEK (for example, KEM
 * ciphertext, salts, nonces, or wrapped CEK bytes). The multi-recipient
 * envelope writes the identifier and a length-prefixed copy of the blob into
 * its header.
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // RSA-OAEP recipient; the header will contain the id and the RSA-wrapped CEK
 * Recipient r = new MultiRecipientDataSourceBuilder.RsaOaepRecipient(rsaPublicKey);
 * byte[] entryBlob = r.buildRecipientEntry(cek);
 * }</pre>
 */
public interface Recipient {
    /**
     * Indicates whether this recipient entry is a decoy (fake recipient).
     *
     * <p>
     * A decoy recipient is included in the envelope to obscure the actual number
     * and identity of real recipients. Its entry is syntactically valid but
     * intentionally unusable for recovering the content-encryption key (CEK).
     * </p>
     *
     * <h4>Security considerations</h4>
     * <ul>
     * <li>Decoys prevent traffic analysis from revealing how many legitimate
     * recipients are present.</li>
     * <li>They are indistinguishable from real recipients to outsiders until a
     * matching {@code RecipientOpener} attempts decryption and fails.</li>
     * <li>Applications should balance the number of decoys against performance and
     * bandwidth overhead.</li>
     * </ul>
     *
     * @return {@code true} if this entry is a decoy and cannot be used to recover
     *         the CEK; {@code false} if it is a real recipient entry
     */
    boolean decoy();

    /**
     * Returns a stable, self-describing identifier for this recipient entry.
     *
     * <p>
     * The identifier is written as UTF-8 into the envelope header and allows fast
     * routing to a suitable {@code RecipientOpener} (for example,
     * {@code "RSA:OAEP-SHA256"}, {@code "KEM:ML-KEM:GCM-WRAP"}). When the envelope
     * is configured to suppress labels for hardening, it may write an empty string
     * in place of this value; implementations should still return their normal
     * identifier here.
     * </p>
     *
     * @return non-null identifier string used in the envelope header; may be empty
     *         only when the caller chooses to suppress labels
     */
    String id();

    /**
     * Builds the binary recipient entry for this recipient and the provided CEK.
     *
     * <p>
     * The returned blob is an opaque byte array that the matching
     * {@code RecipientOpener} can parse and use to recover the CEK. Implementations
     * must not modify or retain the {@code cek} array; copy it if needed. The
     * multi-recipient envelope is responsible for framing and length-prefixing, so
     * the blob itself must not include additional length headers.
     * </p>
     *
     * @param cek the content-encryption key to protect for this recipient; never
     *            null
     * @return an opaque blob encoding the data required to recover {@code cek} for
     *         this recipient
     * @throws GeneralSecurityException if a cryptographic operation fails (for
     *                                  example, KEM, RSA-OAEP, or AEAD wrap)
     * @throws IOException              if serialization of the entry blob fails
     */
    byte[] buildRecipientEntry(byte[] cek) throws GeneralSecurityException, IOException;
}
