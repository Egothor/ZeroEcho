/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *******************************************************************************/
package zeroecho.pki.spi.publish;

import java.util.Objects;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.publication.PublicationTarget;

/**
 * Immutable non-secret identity and content commitment for one external attempt.
 *
 * @param publicationId operation identity
 * @param sourceType authoritative source type
 * @param sourceId authoritative source identity
 * @param target configured target identity
 * @param attemptNumber positive attempt number
 * @param attemptToken stable canonical idempotency token
 * @param encoding payload encoding
 * @param length exact payload length
 * @param sha256 exact lowercase SHA-256 commitment
 */
public record PublicationAttempt(PkiId publicationId, PublicationSourceType sourceType, PkiId sourceId,
        PublicationTarget target, long attemptNumber, String attemptToken, Encoding encoding,
        long length, String sha256) {
    /** Creates a validated immutable attempt descriptor. */
    public PublicationAttempt {
        Objects.requireNonNull(publicationId, "publicationId");
        Objects.requireNonNull(sourceType, "sourceType");
        Objects.requireNonNull(sourceId, "sourceId");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(attemptToken, "attemptToken");
        Objects.requireNonNull(encoding, "encoding");
        Objects.requireNonNull(sha256, "sha256");
        if (attemptNumber <= 0L || length < 0L || !attemptToken.matches("[0-9a-f]{64}")
                || !sha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Publication attempt commitment is invalid");
        }
    }
}
