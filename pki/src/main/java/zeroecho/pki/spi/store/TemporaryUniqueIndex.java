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

/**
 * Runtime-owned file-backed uniqueness index for bounded individual values.
 *
 * <p>
 * Implementations retain no aggregate in heap. The index exists only for one
 * operation and is removed deterministically on close.
 * </p>
 */
public interface TemporaryUniqueIndex extends AutoCloseable {

    /**
     * Adds one immutable bounded value.
     *
     * @param value exact value
     * @return {@code true} when newly added, {@code false} when already present
     * @throws IOException if the index cannot be updated
     */
    boolean add(byte[] value) throws IOException;

    /**
     * Tests whether an exact bounded value is present.
     *
     * @param value exact value
     * @return {@code true} when present
     * @throws IOException if the index cannot be read
     */
    boolean contains(byte[] value) throws IOException;

    /**
     * Removes one exact bounded value after validating its physical record.
     *
     * @param value exact value
     * @return {@code true} when removed, {@code false} when absent
     * @throws IOException if the namespace or record is invalid, or removal fails
     */
    boolean remove(byte[] value) throws IOException;

    /**
     * Validates every committed entry before the namespace is trusted.
     *
     * <p>
     * Validation rejects unknown files, non-regular entries, malformed records,
     * and records whose complete semantic value does not derive their physical
     * key. The index-local lock serializes validation with mutation.
     * </p>
     *
     * @throws IOException if any namespace entry is invalid
     */
    void validateNamespace() throws IOException;

    /**
     * Removes all index storage.
     *
     * @throws IOException if cleanup fails
     */
    @Override
    void close() throws IOException;
}
