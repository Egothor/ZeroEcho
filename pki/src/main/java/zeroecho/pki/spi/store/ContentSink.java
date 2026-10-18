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
package zeroecho.pki.spi.store;

import java.io.IOException;
import java.io.OutputStream;

import zeroecho.pki.api.content.DurableContentReference;

/**
 * Atomic sequential sink for staged operation content.
 *
 * <p>
 * A sink is thread-confined. Completion atomically makes the resulting immutable
 * content visible. Closing or aborting before completion removes partial content.
 * Aggregate byte accounting uses {@code long}; the sink never falls back to
 * aggregate heap buffering.
 * </p>
 */
public interface ContentSink extends AutoCloseable {

    /**
     * Returns the sequential output stream owned by this sink.
     *
     * @return output stream
     * @throws IOException           if writing cannot begin
     * @throws IllegalStateException if the sink is already completed or aborted
     */
    OutputStream outputStream() throws IOException;

    /**
     * Returns the bytes accepted so far.
     *
     * @return non-negative byte count
     */
    long length();

    /**
     * Atomically completes the content.
     *
     * @return immutable durable reference
     * @throws IOException           if data or metadata cannot be committed
     * @throws IllegalStateException if the sink is not open
     */
    DurableContentReference complete() throws IOException;

    /**
     * Aborts and removes partial content.
     *
     * @throws IOException if cleanup fails
     */
    void abort() throws IOException;

    /**
     * Aborts an incomplete sink. Closing a completed sink is a no-op.
     *
     * @throws IOException if cleanup fails
     */
    @Override
    void close() throws IOException;
}
