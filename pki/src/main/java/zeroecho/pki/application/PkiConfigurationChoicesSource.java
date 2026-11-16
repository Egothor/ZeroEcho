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

import java.util.List;
import java.util.Map;
import zeroecho.pki.spi.framework.CredentialFramework;
import java.util.Objects;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.publication.PublicationTarget;

/**
 * Read-only runtime configuration metadata; implementations expose no provider options or key material.
 */
@FunctionalInterface
public interface PkiConfigurationChoicesSource {
    /**
     * Immutable safe configuration metadata and a bounded key page.
     * @param formats configured credential formats
     * @param signingProviders configured runtime signing provider identifiers
     * @param publicationTargets configured runtime publication destinations
     * @param keys sorted distinct key references, at most the requested limit
     * @param nextCursor last returned key reference when another key is known
     * @param algorithms signature algorithms supported by the configured signing provider
     * @param formatMetadata safe presentation metadata supplied by each configured framework
     */
    record Choices(List<FormatId> formats, List<String> signingProviders,
            List<PublicationTarget> publicationTargets, List<KeyRef> keys, Optional<String> nextCursor,
            List<String> algorithms, Map<FormatId, FormatMetadata> formatMetadata) {
        /**
         * Retains source compatibility for callers that have only opaque format IDs.
         * @param formats configured credential format IDs
         * @param signingProviders configured signing providers
         * @param publicationTargets configured publication targets
         * @param keys bounded known key page
         * @param nextCursor exclusive next-page key cursor
         * @param algorithms configured signing algorithm IDs
         */
        public Choices(List<FormatId> formats, List<String> signingProviders, List<PublicationTarget> publicationTargets,
                List<KeyRef> keys, Optional<String> nextCursor, List<String> algorithms) {
            this(formats, signingProviders, publicationTargets, keys, nextCursor, algorithms,
                    formats.stream().collect(java.util.stream.Collectors.toUnmodifiableMap(
                            value -> value, value -> new FormatMetadata(value.value(), CredentialFramework.SubjectInput.generic()))));
        }

        /**
         * Snapshots the immutable non-secret metadata.
         * @param formats configured credential formats
         * @param signingProviders configured runtime signing provider identifiers
         * @param publicationTargets configured runtime publication destinations
         * @param keys sorted distinct key references, at most the requested limit
         * @param nextCursor last returned key reference when another key is known
         * @param algorithms signature algorithms supported by the configured signing provider
         * @param formatMetadata safe presentation metadata supplied by each configured framework
         * @throws NullPointerException if nextCursor is null or a supplied collection contains a null member
         * @throws IllegalArgumentException if formatMetadata does not describe exactly the configured formats
         */
        public Choices {
            formats = List.copyOf(formats);
            signingProviders = List.copyOf(signingProviders);
            publicationTargets = List.copyOf(publicationTargets);
            keys = List.copyOf(keys);
            nextCursor = Objects.requireNonNull(nextCursor, "nextCursor");
            algorithms = List.copyOf(algorithms);
            formatMetadata = Map.copyOf(formatMetadata);
            if (!formatMetadata.keySet().equals(java.util.Set.copyOf(formats))) {
                throw new IllegalArgumentException("Format metadata must match configured formats");
            }
        }
    }

    /**
     * Immutable non-secret presentation data for one configured credential format.
     * @param displayName user-facing format name
     * @param subjectInput format-owned subject input guidance
     */
    record FormatMetadata(String displayName, CredentialFramework.SubjectInput subjectInput) {
        /**
         * Validates bounded names and required subject guidance.
         * @param displayName user-facing format name
         * @param subjectInput format-owned subject input guidance
         * @throws NullPointerException if displayName, subjectInput is null
         * @throws IllegalArgumentException if displayName is blank or exceeds 128 characters
         */
        public FormatMetadata {
            Objects.requireNonNull(displayName, "displayName");
            Objects.requireNonNull(subjectInput, "subjectInput");
            if (displayName.isBlank() || displayName.length() > 128) throw new IllegalArgumentException("Invalid format name");
        }
    }

    /**
     * Reads configured choices and known key references in ascending key-reference order.
     * No remote-only key inventory is requested. The caller must authorize configuration access.
     * @param limit maximum key rows, 1 through 1000
     * @param after exclusive previously returned key reference
     * @param cancellation cooperative cancellation
     * @return immutable safe metadata
     */
    Choices configurationChoices(int limit, Optional<String> after, CancellationSignal cancellation);
}
