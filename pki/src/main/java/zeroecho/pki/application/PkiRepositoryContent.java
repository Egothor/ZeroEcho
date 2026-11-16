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
package zeroecho.pki.application;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;

/**
 * Lifecycle-owned immutable repository content lease without store internals.
 */
public final class PkiRepositoryContent implements AutoCloseable {
    /**
     * Closed semantic role of public repository content.
     */
    public enum Role {
        /**
         * Public credential in its original or explicitly selected format representation.
         */
        CERTIFICATE,
        /**
         * X.509 certificate-revocation-list DER.
         */
        CRL,
        /**
         * Other immutable status-object representation.
         */
        STATUS_OBJECT
    }

    private final PkiId objectId;
    private final PkiId authorityId;
    private final Role role;
    private final long contentLength;
    private final String contentDigest;
    private final RepeatableContent content;

    /**
     * Creates a validated application-layer content lease.
     *
     * @param objectId exact public repository object identity
     * @param authorityId owning authority identity
     * @param role semantic representation role
     * @param reference durable content length and SHA-256 commitment
     * @param content owned content lease released when this wrapper closes
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if the referenced length or digest is invalid
     */
    /* default */ PkiRepositoryContent(PkiId objectId, PkiId authorityId, Role role,
            DurableContentReference reference,
            RepeatableContent content) {
        this(objectId, authorityId, role, Objects.requireNonNull(reference, "reference").length(), reference.sha256(), content);
    }

    /**
     * Creates a transient export lease without manufacturing durable store provenance.
     *
     * @param objectId exact public repository object identity
     * @param authorityId owning authority identity
     * @param role semantic representation role
     * @param contentLength nonnegative committed length in bytes
     * @param contentDigest canonical lowercase SHA-256 hexadecimal commitment
     * @param content owned content lease released when this wrapper closes
     * @throws NullPointerException if a required reference is null
     * @throws IllegalArgumentException if the length is negative or the digest is not canonical
     */
    /* default */ PkiRepositoryContent(PkiId objectId, PkiId authorityId, Role role,
            long contentLength, String contentDigest, RepeatableContent content) {
        this.objectId = Objects.requireNonNull(objectId, "objectId");
        this.authorityId = Objects.requireNonNull(authorityId, "authorityId");
        this.role = Objects.requireNonNull(role, "role");
        this.contentLength = contentLength;
        this.contentDigest = Objects.requireNonNull(contentDigest, "contentDigest");
        if (contentLength < 0 || !contentDigest.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Invalid content commitment");
        this.content = Objects.requireNonNull(content, "content");
    }

    /**
     * Returns the exact repository-object identity.
     *
     * @return exact object identity
     */
    public PkiId objectId() { return objectId; }
    /**
     * Returns the owning authority.
     *
     * @return exact owning authority
     */
    public PkiId authorityId() { return authorityId; }
    /**
     * Returns the representation role.
     *
     * @return semantic representation role
     */
    public Role role() { return role; }
    /**
     * Returns the validated content length.
     *
     * @return exact length in bytes
     */
    public long length() { return contentLength; }
    /**
     * Returns the immutable content commitment.
     *
     * @return lowercase SHA-256 content commitment
     */
    public String sha256() { return contentDigest; }
    /**
     * Opens a new integrity-checking sequential content stream.
     *
     * @return newly opened stream positioned at the first content byte
     * @throws IOException if the content cannot be opened
     */
    public InputStream openStream() throws IOException { return content.openStream(); }
    /**
     * Releases provider-owned lease resources.
     * @throws IOException if the owned content lease cannot be released
     */
    @Override public void close() throws IOException { content.close(); }
}
