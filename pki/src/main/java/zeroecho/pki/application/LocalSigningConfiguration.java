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

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import zeroecho.pki.spi.ProviderConfig;

/**
 * Immutable bounded caller-thread signing configuration without a reactor topology.
 *
 * @param provider local {@code zeroecho-lib} provider configuration
 * @param signatureAlgorithm nonblank configured signing algorithm
 * @param signingTtl positive signing deadline interval
 * @param unlockEnvironmentVariable optional environment reference, never a secret
 * @param claimLease positive claim lease, at most one day and greater than call timeout
 * @param providerCallTimeout positive per-call timeout, at most one day
 * @param pureEdDsaMaximumTbsBytes optional positive raw-message limit, at most the JCA array bound
 */
public record LocalSigningConfiguration(ProviderConfig provider, String signatureAlgorithm,
        Duration signingTtl, Optional<String> unlockEnvironmentVariable, Duration claimLease,
        Duration providerCallTimeout, OptionalLong pureEdDsaMaximumTbsBytes) {
    private static final long MAXIMUM_JCA_MESSAGE_BYTES = Integer.MAX_VALUE - 8L;
    private static final long EDDSA_TRANSFER_BUFFER_BYTES = 16L * 1024L;

    /** Validates all bounds and rejects nonlocal providers before resource construction. */
    public LocalSigningConfiguration {
        Objects.requireNonNull(provider, "provider");
        if (!"zeroecho-lib".equals(provider.backendId())) {
            throw new IllegalArgumentException("Local signing requires the zeroecho-lib provider");
        }
        provider = new ProviderConfig(provider.backendId(), provider.properties());
        if (signatureAlgorithm == null || signatureAlgorithm.isBlank()) {
            throw new IllegalArgumentException("Signing algorithm must not be blank");
        }
        if (signingTtl == null || signingTtl.isZero() || signingTtl.isNegative()) {
            throw new IllegalArgumentException("signingTtl must be positive");
        }
        Objects.requireNonNull(unlockEnvironmentVariable, "unlockEnvironmentVariable").ifPresent(value -> {
            if (!value.matches("[A-Z][A-Z0-9_]{0,127}")) {
                throw new IllegalArgumentException("Unlock environment-variable reference is invalid");
            }
        });
        requireDuration(claimLease, "claimLease");
        requireDuration(providerCallTimeout, "providerCallTimeout");
        if (claimLease.compareTo(providerCallTimeout) <= 0) {
            throw new IllegalArgumentException("claimLease must exceed providerCallTimeout");
        }
        Objects.requireNonNull(pureEdDsaMaximumTbsBytes, "pureEdDsaMaximumTbsBytes");
        if (pureEdDsaMaximumTbsBytes.isPresent() && (pureEdDsaMaximumTbsBytes.getAsLong() <= 0
                || pureEdDsaMaximumTbsBytes.getAsLong() > MAXIMUM_JCA_MESSAGE_BYTES)) {
            throw new IllegalArgumentException("pureEdDsaMaximumTbsBytes is outside its finite bound");
        }
    }

    /**
     * Resolves the existing pure-EdDSA buffering budget for one executing signer.
     * @param maximumHeapBytes positive maximum JVM heap, used only for a derived bound
     * @return positive inclusive raw-message bound
     * @throws IllegalArgumentException if the heap cannot provide a positive derived limit
     */
    public long resolvePureEdDsaMaximumTbsBytes(long maximumHeapBytes) {
        if (pureEdDsaMaximumTbsBytes.isPresent()) { return pureEdDsaMaximumTbsBytes.getAsLong(); }
        if (maximumHeapBytes <= 0) { throw new IllegalArgumentException("maximumHeapBytes must be positive"); }
        long derived = (maximumHeapBytes / 2L - EDDSA_TRANSFER_BUFFER_BYTES) / 3L;
        if (derived <= 0) { throw new IllegalArgumentException("Maximum heap is too small for pure EdDSA signing"); }
        return Math.min(derived, MAXIMUM_JCA_MESSAGE_BYTES);
    }

    private static void requireDuration(Duration duration, String name) {
        Objects.requireNonNull(duration, name);
        if (duration.isZero() || duration.isNegative() || duration.compareTo(Duration.ofDays(1)) > 0) {
            throw new IllegalArgumentException(name + " is outside its finite bound");
        }
    }
}
