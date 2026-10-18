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
package zeroecho.core.io;

import java.io.IOException;
import java.io.InputStream;
import java.util.OptionalLong;

/**
 * Immutable, provider-independent source of repeatable operation content.
 *
 * <p>
 * Every call to {@link #openStream()} returns a new sequential reader positioned
 * at the first byte. Implementations may be backed by files, object storage,
 * databases or explicitly small immutable byte values. Callers own and must close
 * each returned stream. Closing the content releases its implementation-owned
 * resources but does not close streams already returned unless the implementation
 * documents a stronger local rule.
 * </p>
 *
 * <p>
 * The contract does not impose an aggregate content-size limit. Completion remains
 * subject to available storage, I/O, technical representability and explicitly
 * injected deployment policy. Content never carries key material or cryptographic
 * provider authority.
 * </p>
 */
public interface RepeatableContent extends AutoCloseable {

    /**
     * Opens a new sequential reader.
     *
     * @return newly opened content stream
     * @throws IOException if the immutable content cannot be opened or its
     *                     integrity cannot be established
     */
    InputStream openStream() throws IOException;

    /**
     * Returns the known aggregate length when cheaply and authoritatively
     * available.
     *
     * @return non-negative length, or empty when the length is unknown
     */
    OptionalLong length();

    /**
     * Returns a stable, non-secret identifier for integrity and durable provenance.
     *
     * <p>
     * The identifier is metadata, not authorization, and must not expose a
     * temporary physical path.
     * </p>
     *
     * @return stable non-blank identifier
     */
    String contentId();

    /**
     * Releases implementation-owned resources.
     *
     * @throws IOException if cleanup fails
     */
    @Override
    void close() throws IOException;
}
