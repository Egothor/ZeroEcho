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
package zeroecho.pki.application;

import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiId;

/**
 * Exact authorization projection recovered from one durable domain continuation.
 *
 * <p>The projection contains no requester identity. It describes only the
 * immutable action and resource committed before signing yielded, so possession
 * of the operation identifier never grants access.</p>
 *
 * @param action original domain action
 * @param resourceType original protected resource type
 * @param authorityId exact authority scope, when the original resource was scoped
 * @param profileId exact profile scope, when the original resource was scoped
 * @param objectId exact protected object identity, when known before signing
 */
public record SigningOperationAuthorization(Action action, ResourceType resourceType,
        Optional<PkiId> authorityId, Optional<String> profileId, Optional<PkiId> objectId) {

    /** Closed domain actions that may yield durable signing. */
    public enum Action {
        /** Creates a logical certificate authority. */
        AUTHORITY_CREATE,
        /** Creates another issuer generation for an existing authority. */
        ISSUER_CREATE,
        /** Issues an end-entity certificate. */
        CERTIFICATE_ISSUE,
        /** Generates a durable status object. */
        STATUS_GENERATE
    }

    /** Closed protected resource types for durable signing status. */
    public enum ResourceType {
        /** Logical certificate authority. */
        AUTHORITY,
        /** Authority issuer generation. */
        ISSUER,
        /** End-entity certificate. */
        CERTIFICATE,
        /** CRL or another durable status object. */
        STATUS_OBJECT
    }

    /** Validates and snapshots the exact immutable authorization projection. */
    public SigningOperationAuthorization {
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(resourceType, "resourceType");
        authorityId = Objects.requireNonNull(authorityId, "authorityId");
        profileId = Objects.requireNonNull(profileId, "profileId");
        profileId.ifPresent(value -> {
            if (value.isBlank() || value.length() > 128) {
                throw new IllegalArgumentException("profileId must be finite and non-blank");
            }
        });
        objectId = Objects.requireNonNull(objectId, "objectId");
    }
}
