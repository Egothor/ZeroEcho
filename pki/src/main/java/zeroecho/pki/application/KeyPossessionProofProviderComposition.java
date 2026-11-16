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
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallenge;
import zeroecho.pki.spi.confirmation.KeyPossessionProofDescriptor;
import zeroecho.pki.spi.confirmation.KeyPossessionProofProvider;
import zeroecho.pki.spi.confirmation.KeyPossessionProofResponse;

/**
 * Immutable session-local lookup of explicitly trusted proof providers.
 */
final class KeyPossessionProofProviderComposition {
    private static final String VALIDATION_COMMITMENT = "0".repeat(64);

    private final Map<String, KeyPossessionProofProvider> providersBySuiteId;

    private KeyPossessionProofProviderComposition(
            Map<String, KeyPossessionProofProvider> providersBySuiteId) {
        this.providersBySuiteId = Map.copyOf(providersBySuiteId);
    }

    /**
     * Indexes an explicitly trusted provider snapshot by canonical proof-suite identity.
     *
     * @param providers configured providers; the list is copied, while provider instances are borrowed
     * @return immutable suite lookup without opening or closing providers
     * @throws NullPointerException if the list or an entry is null
     * @throws IllegalArgumentException if a suite identifier is invalid or duplicated
     */
    /* default */ static KeyPossessionProofProviderComposition compose(
            List<KeyPossessionProofProvider> providers) {
        List<KeyPossessionProofProvider> exact = List.copyOf(providers);
        Map<String, KeyPossessionProofProvider> indexed = new TreeMap<>();
        for (KeyPossessionProofProvider provider : exact) {
            String suiteId = provider.suiteId();
            validateSuiteId(suiteId);
            if (indexed.putIfAbsent(suiteId, provider) != null) {
                throw new IllegalArgumentException("Duplicate key-possession proof-suite identity");
            }
        }
        return new KeyPossessionProofProviderComposition(indexed);
    }

    private static void validateSuiteId(String suiteId) {
        new ConfirmationProofSuiteRef(suiteId, VALIDATION_COMMITMENT);
    }

    /**
     * Looks up a trusted provider without creating a fallback provider.
     *
     * @param suiteId exact canonical suite identifier
     * @return configured borrowed provider, or an empty optional if absent
     * @throws NullPointerException if the immutable map rejects a null lookup key
     */
    /* default */ Optional<KeyPossessionProofProvider> find(String suiteId) {
        return Optional.ofNullable(providersBySuiteId.get(suiteId));
    }

    /**
     * Checks that an enabled confirmation policy matches an explicitly trusted provider descriptor.
     *
     * @param policy configured runtime policy, or an empty optional to disable this check
     * @throws NullPointerException if the optional or a required descriptor is null
     * @throws IllegalArgumentException if no provider exists or its suite, challenge length or response bound differs
     */
    /* default */ void validatePolicy(
            Optional<CredentialConfirmationProofRuntimePolicy> policy) {
        Objects.requireNonNull(policy, "credentialConfirmationProofPolicy")
                .ifPresent(this::validatePolicy);
    }

    private void validatePolicy(CredentialConfirmationProofRuntimePolicy policy) {
        String suiteId = policy.proofSuiteBinding().proofSuiteRef().suiteId();
        KeyPossessionProofProvider provider = find(suiteId).orElseThrow(() ->
                new IllegalArgumentException(
                        "Credential confirmation proof policy has no trusted provider"));
        KeyPossessionProofDescriptor descriptor = Objects.requireNonNull(
                provider.descriptor(policy.proofSuiteBinding().rsaMaximumModulusBits()),
                "credential confirmation proof descriptor");
        if (!descriptor.proofSuiteBinding().equals(policy.proofSuiteBinding())
                || descriptor.challengeBytes() != CredentialConfirmationChallenge.RAW_CHALLENGE_BYTES
                || descriptor.maximumResponseBytes() < 1
                || descriptor.maximumResponseBytes() > KeyPossessionProofResponse.MAXIMUM_BYTES) {
            throw new IllegalArgumentException(
                    "Credential confirmation proof policy and provider descriptor differ");
        }
    }

    /**
     * Returns the immutable configured suite lookup without transferring provider ownership.
     *
     * @return unmodifiable canonical suite-to-provider mapping
     */
    /* default */ Map<String, KeyPossessionProofProvider> providersBySuiteId() {
        return providersBySuiteId;
    }
}
