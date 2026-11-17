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
package zeroecho.pki.spi.store;

import java.time.Clock;
import java.util.Objects;

/**
 * Process-local clock and optional public-verification dependencies for opening a store.
 *
 * <p>The dependency references are immutable and retained as supplied; callbacks are
 * not cloned or invoked by construction. Their presence is a configured capability,
 * not evidence that a particular certificate, candidate or native child was verified.
 * They do not supply private keys or authorize signing.</p>
 */
public final class PkiStoreRuntimeDependencies {
    private final Clock clock;
    private final java.util.Optional<IssuerAlgorithmEvidenceVerifier> issuerEvidenceVerifier;
    private final java.util.Optional<CrlHybridNativeChildVerifier> crlHybridNativeChildVerifier;

    /**
     * Creates dependencies with one authoritative store clock.
     *
     * @param clock authoritative non-null clock shared with the owning PKI session
     * @throws NullPointerException if {@code clock} is {@code null}
     */
    public PkiStoreRuntimeDependencies(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.issuerEvidenceVerifier = java.util.Optional.empty();
        this.crlHybridNativeChildVerifier = java.util.Optional.empty();
    }

    /**
     * Creates dependencies retaining the supplied issuer-evidence verifier and no CRL-child verifier.
     *
     * @param clock authoritative store clock
     * @param verifier trusted configured public algorithm verifier; never a private-key resolver
     * @throws NullPointerException if the clock or verifier is null
     */
    public PkiStoreRuntimeDependencies(Clock clock, IssuerAlgorithmEvidenceVerifier verifier) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.issuerEvidenceVerifier = java.util.Optional.of(Objects.requireNonNull(verifier, "verifier"));
        this.crlHybridNativeChildVerifier = java.util.Optional.empty();
    }

    /**
     * Creates immutable process-local public verification authorities for issuer
     * metadata and streamed hybrid CRL child adoption. Neither callback supplies
     * private keys or signing capability; implementations must be thread-safe.
     *
     * @param clock authoritative store clock
     * @param verifier trusted configured public issuer algorithm verifier
     * @param crlVerifier trusted configured pure hybrid CRL adoption verifier
     * @throws NullPointerException if any dependency is null
     */
    public PkiStoreRuntimeDependencies(Clock clock, IssuerAlgorithmEvidenceVerifier verifier,
            CrlHybridNativeChildVerifier crlVerifier) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.issuerEvidenceVerifier = java.util.Optional.of(Objects.requireNonNull(verifier, "verifier"));
        this.crlHybridNativeChildVerifier = java.util.Optional.of(Objects.requireNonNull(crlVerifier, "crlVerifier"));
    }

    /**
     * Returns the retained hybrid-CRL adoption verifier, when explicitly configured.
     *
     * @return the configured verifier; empty for the one- and two-argument constructors
     */
    public java.util.Optional<CrlHybridNativeChildVerifier> crlHybridNativeChildVerifier() {
        return crlHybridNativeChildVerifier;
    }

    /**
     * Returns the retained public issuer-algorithm evidence verifier.
     *
     * @return the configured verifier; empty for the clock-only constructor
     */
    public java.util.Optional<IssuerAlgorithmEvidenceVerifier> issuerAlgorithmEvidenceVerifier() {
        return issuerEvidenceVerifier;
    }

    /**
     * Returns dependencies using the production system UTC clock.
     *
     * @return new dependencies backed by {@link Clock#systemUTC()}, with both verifiers absent
     */
    public static PkiStoreRuntimeDependencies systemUtc() {
        return new PkiStoreRuntimeDependencies(Clock.systemUTC());
    }

    /**
     * Returns the exact authoritative clock supplied by the runtime owner.
     *
     * @return authoritative store clock
     */
    public Clock clock() {
        return clock;
    }
}
