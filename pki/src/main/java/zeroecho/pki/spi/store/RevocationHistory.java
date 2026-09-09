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
package zeroecho.pki.spi.store;

import java.io.IOException;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.core.io.CancellationSignal;

/**
 * Closeable one-pass history of one credential in credential-local revision order.
 *
 * <p>The cursor reads authenticated authoritative frames incrementally. Its
 * auxiliary heap is independent of the number of transitions. Opening is
 * constant time. The first advance validates the captured prefix, and complete
 * consumption costs at most two linear passes over the global log prefix.</p>
 */
public interface RevocationHistory extends AutoCloseable {

    /**
     * Returns the credential selected for this history.
     *
     * @return exact credential identity selected for this history
     */
    PkiId credentialId();

    /**
     * Advances to the next transition.
     *
     * @param cancellation cancellation signal checked during scanning
     * @return {@code true} when {@link #current()} is available
     * @throws IOException if the authoritative history is unreadable or invalid
     */
    boolean next(CancellationSignal cancellation) throws IOException;

    /**
     * Advances without external cancellation.
     *
     * @return {@code true} when a transition is available
     * @throws IOException if the authoritative history is unreadable or invalid
     */
    default boolean next() throws IOException {
        return next(CancellationSignal.NONE);
    }

    /**
     * Returns the current transition.
     *
     * @return current transition
     * @throws IllegalStateException if the cursor is not positioned
     */
    RevocationTransition current();

    /**
     * Closes the underlying authoritative-log channel. Repeated close is harmless.
     *
     * @throws IOException if channel closure fails
     */
    @Override
    void close() throws IOException;
}
