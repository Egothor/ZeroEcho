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

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.orch.SigningSubmissionId;

/**
 * Typed immutable identity of a durable business owner of staged content.
 *
 * <p>
 * Owner identities contain no path, content, key material, provider name, or
 * implementation class. The staged-content store is the sole authority that
 * persists retain and release transitions. Constructing this value does not
 * itself retain content.
 * </p>
 *
 * @param category closed durable-owner category
 * @param identifier canonical category-specific identifier
 */
public record DurableContentOwner(Category category, String identifier) {

    private static final int MAX_IDENTIFIER_BYTES = 512;

    /** Creates and validates one typed owner identity. */
    public DurableContentOwner {
        Objects.requireNonNull(category, "category");
        String exact = Objects.requireNonNull(identifier, "identifier");
        if (exact.isBlank() || !exact.equals(exact.strip())
                || exact.getBytes(StandardCharsets.UTF_8).length > MAX_IDENTIFIER_BYTES) {
            throw new IllegalArgumentException("Durable content owner identifier is not canonical");
        }
        for (int index = 0; index < exact.length(); index++) {
            char value = exact.charAt(index);
            if (value < 0x21 || value > 0x7e || value == '/' || value == '\\') {
                throw new IllegalArgumentException("Durable content owner identifier is not canonical");
            }
        }
        if (category == Category.SIGNING_OPERATION) {
            SigningSubmissionId.parse(new PkiId(exact));
        }
    }

    /**
     * Creates the canonical owner for one signing operation.
     *
     * @param operationId canonical signing submission identifier
     * @return signing-operation owner
     * @throws IllegalArgumentException if the identifier is not a canonical
     *         signing submission identifier
     */
    public static DurableContentOwner signingOperation(PkiId operationId) {
        Objects.requireNonNull(operationId, "operationId");
        SigningSubmissionId parsed = SigningSubmissionId.parse(operationId);
        return new DurableContentOwner(Category.SIGNING_OPERATION, parsed.id().value());
    }

    /**
     * Creates the canonical owner for one persisted credential record.
     *
     * @param credentialId canonical credential identifier
     * @return credential-record owner
     * @throws IllegalArgumentException if the identifier cannot be represented as
     *         a canonical durable owner identifier
     */
    public static DurableContentOwner credentialRecord(PkiId credentialId) {
        Objects.requireNonNull(credentialId, "credentialId");
        return new DurableContentOwner(Category.CREDENTIAL_RECORD, credentialId.value());
    }

    /**
     * Returns a deterministic persistence token containing no path or payload.
     *
     * @return canonical category and identifier token
     */
    public String canonicalForm() {
        return category.name() + ":" + identifier;
    }

    /** Closed durable-owner categories reserved by the Phase A lifecycle. */
    public enum Category {
        /** Pending or recoverable signing operation. */
        SIGNING_OPERATION,
        /** Persisted credential record; integration is deferred. */
        CREDENTIAL_RECORD,
        /** Persisted status-object record; integration is deferred. */
        STATUS_OBJECT_RECORD
    }
}
