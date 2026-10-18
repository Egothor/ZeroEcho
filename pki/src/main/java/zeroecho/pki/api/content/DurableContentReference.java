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
package zeroecho.pki.api.content;

import zeroecho.pki.api.Encoding;

/**
 * Stable, payload-free reference to immutable staged content.
 *
 * <p>
 * The reference is durable provenance rather than a live file handle. It carries
 * no physical path, payload, key material or runtime authorization token. It may
 * be resolved only through the staged-content store whose immutable identifier
 * matches {@link #storeId()}.
 * </p>
 *
 * A durable content reference is authoritative only when issued and validated
 * by its owning staged-content store. This read-only interface deliberately has
 * no public construction factory: callers cannot turn arbitrary metadata into
 * an authoritative reference. Persistence decoders must restore references
 * through the owning store, which rejects foreign stores and metadata mismatch.
 * Sealing and reference issuance do not imply durable business-object ownership.
 *
 * <p>
 * Implementations are immutable and expose no physical path, temporary name,
 * payload, key material, open handle, or mutable lifecycle state. Earlier
 * pre-release persistence forms are not accepted or migrated. Phase B key
 * isolation is outside this contract.
 * </p>
 */
public interface DurableContentReference {

    /**
     * Returns the canonical logical identity of the owning store.
     *
     * @return path-independent store identity
     */
    String storeId();

    /**
     * Returns the opaque canonical content identity issued by the store.
     *
     * @return path-independent content identity
     */
    String contentId();

    /**
     * Returns the semantic transport encoding.
     *
     * @return content encoding
     */
    Encoding encoding();

    /**
     * Returns the exact checked byte length.
     *
     * @return non-negative content length
     */
    long length();

    /**
     * Returns the canonical lowercase SHA-256 integrity value.
     *
     * @return integrity value; callers must not treat it as issuance authority
     */
    String sha256();

    /**
     * Returns the immutable content purpose classification.
     *
     * @return lifecycle classification; not durable ownership state
     */
    Lifecycle lifecycle();

    /**
     * Durable ownership classification.
     */
    enum Lifecycle {
        /** Content retained while a durable operation is pending. */
        OPERATION,
        /** Content owned by an immutable persisted PKI object. */
        PERSISTED,
        /** Content eligible for release after its immediate operation. */
        TEMPORARY
    }
}
