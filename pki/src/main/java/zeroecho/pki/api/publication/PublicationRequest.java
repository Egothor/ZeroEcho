/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *******************************************************************************/
package zeroecho.pki.api.publication;

import java.util.Objects;
import zeroecho.pki.api.PkiId;

/**
 * Immutable request to register distribution of one already committed PKI object.
 *
 * @param publicationId caller-selected stable operation identity
 * @param sourceType authoritative source-object type
 * @param sourceId exact authoritative source-object identity
 * @param target configured destination identity
 */
public record PublicationRequest(PkiId publicationId, PublicationSourceType sourceType,
        PkiId sourceId, PublicationTarget target) {
    /** Creates a validated publication request. */
    public PublicationRequest {
        Objects.requireNonNull(publicationId, "publicationId");
        Objects.requireNonNull(sourceType, "sourceType");
        Objects.requireNonNull(sourceId, "sourceId");
        Objects.requireNonNull(target, "target");
    }
}
