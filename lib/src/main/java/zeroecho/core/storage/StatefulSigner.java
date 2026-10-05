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
package zeroecho.core.storage;

import java.io.IOException;
import java.security.GeneralSecurityException;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;

/**
 * Durable signing capability for a newly enrolled LMS/XMSS key. Every invocation
 * reloads the key and validates the independent authority. This handle borrows
 * its keyring and authority; both must remain open. It owns no closeable resource.
 * Generic signature contexts continue to reject stateful private keys.
 */
public final class StatefulSigner {
    private final KeyringStore store;
    private final LocalStatefulSigningAuthority authority;
    private final String alias;

    /* default */ StatefulSigner(KeyringStore store, LocalStatefulSigningAuthority authority, String alias) {
        this.store = store;
        this.authority = authority;
        this.alias = alias;
    }

    /**
     * Signs after durably advancing the stored parent by one leaf. A cancellation,
     * content error or provider failure after reservation burns that leaf. Pending
     * or uncertain persistence fails closed and requires recovery; it is never retried.
     * Content is borrowed, and each opened stream is closed. Calls serialize with
     * store mutation, closure and other signatures. XMSS's provider buffers the
     * message, bounded by the caller's explicit size policy. Persistence rewrites
     * the whole encrypted keyring image per signature.
     * All keys sharing an authority serialize, including content I/O. Callers
     * must supply bounded or interruptible I/O: cancellation is cooperative
     * between reads and does not interrupt lock acquisition or a blocked read.
     * @param content repeatable content
     * @param cancellation cancellation signal
     * @param maximumMessageBytes nonnegative caller-selected input-size limit;
     *                            provider memory is O(n), not an exact byte budget
     * @return independently owned signature bytes
     * @throws IOException if content, cancellation or durable state handling fails
     * @throws GeneralSecurityException if the cryptographic operation fails
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if the input-size limit is negative
     */
    public byte[] sign(RepeatableContent content, CancellationSignal cancellation, int maximumMessageBytes)
            throws IOException, GeneralSecurityException {
        return store.signStateful(alias, authority, content, cancellation, maximumMessageBytes);
    }

    /**
     * Reads signature-size metadata without reserving a leaf or signing a probe.
     * @return exact signature length in bytes
     * @throws IOException if the enrollment cannot be authenticated
     * @throws GeneralSecurityException if key parameters are unsupported
     */
    public int signatureLength() throws IOException, GeneralSecurityException {
        return store.statefulSignatureLength(alias, authority);
    }
}
