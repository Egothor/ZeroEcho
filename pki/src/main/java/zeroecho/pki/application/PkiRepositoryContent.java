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

/** Lifecycle-owned immutable repository content lease without store internals. */
public final class PkiRepositoryContent implements AutoCloseable {
    /** Closed semantic role of public repository content. */
    public enum Role {
        /** X.509 certificate DER. */
        CERTIFICATE,
        /** X.509 certificate-revocation-list DER. */
        CRL,
        /** Other immutable status-object representation. */
        STATUS_OBJECT
    }

    private final PkiId objectId;
    private final PkiId authorityId;
    private final Role role;
    private final DurableContentReference reference;
    private final RepeatableContent content;

    /** Creates a validated application-layer content lease. */
    /* default */ PkiRepositoryContent(PkiId objectId, PkiId authorityId, Role role,
            DurableContentReference reference,
            RepeatableContent content) {
        this.objectId = Objects.requireNonNull(objectId, "objectId");
        this.authorityId = Objects.requireNonNull(authorityId, "authorityId");
        this.role = Objects.requireNonNull(role, "role");
        this.reference = Objects.requireNonNull(reference, "reference");
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
    public long length() { return reference.length(); }
    /**
     * Returns the immutable content commitment.
     *
     * @return lowercase SHA-256 content commitment
     */
    public String sha256() { return reference.sha256(); }
    /**
     * Opens a new integrity-checking sequential content stream.
     *
     * @return newly opened stream positioned at the first content byte
     * @throws IOException if the content cannot be opened
     */
    public InputStream openStream() throws IOException { return content.openStream(); }
    /** Releases provider-owned lease resources. */
    @Override public void close() throws IOException { content.close(); }
}
