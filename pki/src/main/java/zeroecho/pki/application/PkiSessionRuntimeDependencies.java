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

import zeroecho.core.spi.KeyringUnlockProvider;
import zeroecho.pki.spi.audit.AuditSink;

/**
 * Immutable process-local capabilities for one PKI session composition.
 *
 * @param keyringUnlockProvider optional secure key-unlock capability
 * @param auditSink optional precomposed lifecycle-owned audit sink
 */
public record PkiSessionRuntimeDependencies(Optional<KeyringUnlockProvider> keyringUnlockProvider,
        Optional<AuditSink> auditSink) {

    /** Creates dependencies without an externally composed audit sink. */
    public PkiSessionRuntimeDependencies(Optional<KeyringUnlockProvider> keyringUnlockProvider) {
        this(keyringUnlockProvider, Optional.empty());
    }

    /** Validates the optional capability container. */
    public PkiSessionRuntimeDependencies {
        keyringUnlockProvider = Objects.requireNonNull(keyringUnlockProvider, "keyringUnlockProvider");
        auditSink = Objects.requireNonNull(auditSink, "auditSink");
    }

    /** @return an immutable dependency set without key-unlock access */
    public static PkiSessionRuntimeDependencies none() {
        return new PkiSessionRuntimeDependencies(Optional.empty(), Optional.empty());
    }

    /**
     * Creates dependencies containing one explicit process-local unlock provider.
     *
     * @param provider secure unlock capability
     * @return immutable runtime dependencies
     */
    public static PkiSessionRuntimeDependencies withKeyringUnlockProvider(KeyringUnlockProvider provider) {
        return new PkiSessionRuntimeDependencies(Optional.of(Objects.requireNonNull(provider, "provider")),
                Optional.empty());
    }

    /**
     * Returns a dependency set using one lifecycle-owned shared audit sink.
     *
     * <p>The opened session assumes ownership and closes the sink. This enables
     * transport-neutral compositions to share one audit authority with adjacent
     * control services without exposing it through {@link PkiSession}.</p>
     *
     * @param sink configured audit sink transferred to the session
     * @return immutable dependencies preserving any key-unlock capability
     */
    public PkiSessionRuntimeDependencies withAuditSink(AuditSink sink) {
        return new PkiSessionRuntimeDependencies(keyringUnlockProvider,
                Optional.of(Objects.requireNonNull(sink, "sink")));
    }
}
