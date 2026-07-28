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

import java.io.IOException;
import java.io.InputStream;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import zeroecho.sdk.content.api.DataContent;

/**
 * Represents one-shot multi-recipient content that owns temporary recipient
 * resources until processing or explicit cleanup.
 *
 * <p>
 * Callers must invoke {@link #close()} when a built instance is abandoned before
 * {@link #getStream()} is called. Successful or failed stream construction also
 * releases the owned recipient resources. Unlocking keys and password material
 * supplied separately remain caller-owned and are never destroyed by this
 * content.
 * </p>
 *
 * <p>
 * Implementations are not thread-safe. Cleanup is idempotent, and content cannot
 * be used after cleanup. Calling {@link #getStream()} is terminal even when stream
 * construction fails.
 * </p>
 */
public interface MultiRecipientContent extends DataContent, Destroyable, AutoCloseable {
    /**
     * Connects the upstream content before the one processing attempt.
     *
     * @param input non-null upstream plaintext or encrypted content
     * @throws NullPointerException  if {@code input} is {@code null}
     * @throws IllegalStateException if this content has already processed input or
     *                               has been closed
     */
    @Override
    void setInput(DataContent input);

    /**
     * Creates the processed stream and releases all recipient resources.
     *
     * <p>
     * This method may be called only once. Recipient resources are released before
     * it returns or throws. On success, the caller owns the returned stream and
     * must close it; closing this content does not replace closing an already
     * returned stream.
     * </p>
     *
     * @return the encrypted or decrypted stream
     * @throws IOException           if envelope processing, cryptographic stream
     *                               creation, or resource cleanup fails
     * @throws NullPointerException  if no upstream content was supplied
     * @throws IllegalStateException if this content has already processed input or
     *                               has been closed
     */
    @Override
    InputStream getStream() throws IOException;

    /**
     * Releases all recipient resources still owned by this content.
     *
     * @throws IOException if an owned context cannot be closed
     */
    @Override
    void close() throws IOException;

    /**
     * Destroys all recipient resources still owned by this content.
     *
     * @throws DestroyFailedException if cleanup fails
     */
    @Override
    void destroy() throws DestroyFailedException;

    /**
     * Reports whether this content has released its recipient resources.
     *
     * @return {@code true} after processing, {@link #close()}, or
     *         {@link #destroy()}
     */
    @Override
    boolean isDestroyed();
}
