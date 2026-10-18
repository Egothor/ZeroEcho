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
import java.util.Objects;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.publication.PublicationTarget;

/** Read-only runtime configuration metadata; implementations expose no provider options or key material. */
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
     */
    record Choices(List<FormatId> formats, List<String> signingProviders,
            List<PublicationTarget> publicationTargets, List<KeyRef> keys, Optional<String> nextCursor,
            List<String> algorithms) {
        /** Snapshots the immutable non-secret metadata. */
        public Choices {
            formats = List.copyOf(formats);
            signingProviders = List.copyOf(signingProviders);
            publicationTargets = List.copyOf(publicationTargets);
            keys = List.copyOf(keys);
            nextCursor = Objects.requireNonNull(nextCursor, "nextCursor");
            algorithms = List.copyOf(algorithms);
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
