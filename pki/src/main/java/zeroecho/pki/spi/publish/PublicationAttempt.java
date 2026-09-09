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
