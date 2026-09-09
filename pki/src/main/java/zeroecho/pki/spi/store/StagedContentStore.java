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

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.OneShotContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.content.DurableContentOwner;

/**
 * Durable, runtime-owned staging boundary for signed-object content.
 *
 * <p>
 * ZeroEcho core does not impose an arbitrary product-wide limit on aggregate CRL
 * size or revocation-entry cardinality. Implementations stream to durable storage
 * and use {@code long} accounting. Completion remains subject to available
 * storage, I/O, technical representability and explicitly injected deployment
 * policy.
 * </p>
 */
public interface StagedContentStore {

    /**
     * Returns the stable logical store identifier.
     *
     * @return non-blank identifier
     */
    String contentStoreId();

    /**
     * Begins an atomic staged write.
     *
     * @param encoding  content encoding
     * @param lifecycle ownership classification
     * @return new incomplete sink
     * @throws IOException if staging cannot begin
     */
    ContentSink beginContent(Encoding encoding, DurableContentReference.Lifecycle lifecycle) throws IOException;

    /**
     * Stages a one-shot input incrementally.
     *
     * @param input        one-shot source
     * @param encoding     content encoding
     * @param lifecycle    ownership classification
     * @param cancellation cancellation signal
     * @return durable reference
     * @throws IOException if reading, writing, cancellation or completion fails
     */
    default DurableContentReference stage(OneShotContent input, Encoding encoding,
            DurableContentReference.Lifecycle lifecycle, CancellationSignal cancellation) throws IOException {
        try (OneShotContent source = input; ContentSink sink = beginContent(encoding, lifecycle);
                java.io.InputStream stream = source.openStream(); java.io.OutputStream output = sink.outputStream()) {
            byte[] buffer = new byte[16 * 1024];
            try {
                int read;
                while ((read = stream.read(buffer)) >= 0) {
                    cancellation.throwIfCancelled();
                    if (read > 0) {
                        output.write(buffer, 0, read);
                    }
                }
                return sink.complete();
            } finally {
                java.util.Arrays.fill(buffer, (byte) 0);
            }
        }
    }

    /**
     * Resolves a completed reference to immutable repeatable content.
     *
     * @param reference durable reference owned by this store
     * @return repeatable content
     * @throws IOException              if content is missing or fails integrity
     * @throws IllegalArgumentException if the reference belongs to another store
     */
    RepeatableContent openContent(DurableContentReference reference) throws IOException;

    /**
     * Restores one persisted reference through this owning store.
     *
     * <p>
     * The supplied fields are untrusted persistence data. The store validates the
     * current schema values against its sealed immutable metadata and returns its
     * own authoritative reference only on an exact match. This method does not
     * create content and does not establish durable business-object ownership.
     * Earlier pre-release formats are rejected rather than migrated.
     * </p>
     *
     * @param storeId owning-store identity from the persisted record
     * @param contentId logical content identity from the persisted record
     * @param encoding persisted transport encoding
     * @param length persisted exact byte length
     * @param sha256 persisted canonical SHA-256 integrity value
     * @param lifecycle persisted purpose classification
     * @return store-issued immutable reference after exact metadata validation
     * @throws IOException if metadata is missing, malformed, or inconsistent
     * @throws IllegalArgumentException if the store identity is foreign or an
     *         identifier is malformed
     */
    DurableContentReference restoreReference(String storeId, String contentId, Encoding encoding, long length,
            String sha256, DurableContentReference.Lifecycle lifecycle) throws IOException;

    /**
     * Durably retains sealed content for one typed business owner.
     *
     * @param reference store-issued sealed reference
     * @param owner exact durable owner
     * @return {@code true} when a new association was written; {@code false} when
     *         the same association already existed
     * @throws IOException if content or ownership metadata cannot be validated or
     *         persisted
     */
    boolean retainContent(DurableContentReference reference, DurableContentOwner owner) throws IOException;

    /**
     * Durably releases one exact owner and retires content after its last owner.
     *
     * @param reference store-issued sealed reference
     * @param owner exact durable owner
     * @return {@code true} when the association existed and was removed
     * @throws IOException if ownership metadata cannot be validated or persisted
     */
    boolean releaseContent(DurableContentReference reference, DurableContentOwner owner) throws IOException;

    /**
     * Returns the immutable exact owner set for sealed content.
     *
     * @param reference store-issued sealed reference
     * @return immutable owner set
     * @throws IOException if ownership metadata is corrupt
     */
    java.util.Set<DurableContentOwner> contentOwners(DurableContentReference reference) throws IOException;

    /**
     * Retires sealed content that has no durable owner.
     *
     * @param reference store-issued sealed reference
     * @throws IOException if content is retained or deletion fails
     */
    void retireUnownedContent(DurableContentReference reference) throws IOException;

    /**
     * Removes completed content not referenced by durable runtime state.
     *
     * <p>
     * The supplied disk-backed index permits recovery without retaining all
     * durable references in heap. Temporary content is always abandoned across a
     * restart. Operation and persisted content survive only when present in the
     * retained index.
     * </p>
     *
     * @param retained completed content identifiers referenced by durable state
     * @param retainedOwners durable owner identifiers that remain live
     * @throws IOException if recovery or cleanup fails
     */
    void recoverContent(TemporaryUniqueIndex retained, TemporaryUniqueIndex retainedOwners) throws IOException;

    /**
     * Begins one file-backed uniqueness index for bounded individual values.
     *
     * @return temporary index
     * @throws IOException if temporary storage cannot be created
     */
    TemporaryUniqueIndex beginUniqueIndex() throws IOException;
}
