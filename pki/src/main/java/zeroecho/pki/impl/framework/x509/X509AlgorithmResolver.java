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
package zeroecho.pki.impl.framework.x509;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapabilities;
import zeroecho.core.spi.AlgorithmExecutionCapability;

/**
 * Provider-independent intersection of exact identity, binding, installed
 * execution capability, immutable security floor, configured policy, and key
 * compatibility.
 *
 * <p>
 * The resolver returns an immutable effective selection and never falls back to
 * a default or provider alias. It contains no key material and performs no
 * cryptographic execution.
 * </p>
 */
public final class X509AlgorithmResolver {

    private static final int UNIQUE_MATCH_COUNT = 1;

    private final X509BindingCatalog bindings;
    private final AlgorithmExecutionCapabilities capabilities;
    private final Policy policy;

    /**
     * Stable resolution failure categories.
     */
    public enum Failure {
        /** No authoritative X.509 binding exists. */
        NO_BINDING,
        /** No installed implementation supports the tuple. */
        NO_CAPABILITY,
        /** More than one implementation remains without explicit selection. */
        AMBIGUOUS_IMPLEMENTATION,
        /** Explicit implementation is unavailable for the tuple. */
        UNKNOWN_IMPLEMENTATION,
        /** Semantic capability has no process-local executor binding. */
        NO_EXECUTOR,
        /** Non-overridable security floor rejected the identity. */
        SECURITY_FLOOR,
        /** Configured policy rejected the suite. */
        POLICY,
        /** Signature and key identities are incompatible. */
        INCOMPATIBLE_KEY
    }

    /**
     * Policy decision over exact identity data.
     */
    @FunctionalInterface
    public interface Policy {

        /**
         * Tests whether configured policy permits the exact operation.
         *
         * @param suite     complete suite
         * @param direction execution direction
         * @return {@code true} when permitted
         */
        boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction);

        /**
         * Returns stable non-secret policy semantics for snapshot provenance.
         *
         * @return deterministic policy fingerprint
         */
        default String semanticFingerprint() {
            return getClass().getName();
        }
    }

    /**
     * Immutable effective selection.
     *
     * @param requested      exact requested identity
     * @param suite          compatible exact suite
     * @param binding        exact X.509 representation
     * @param implementation selected execution metadata
     * @param direction      authorized execution direction
     * @param provenance     stable default identifier or {@code explicit}
     * @param authorityFingerprint authority snapshot fingerprint
     */
    public record Selection(AlgorithmIdentity requested, AlgorithmSuite suite, X509AlgorithmIdentifier binding,
            AlgorithmExecutionCapability implementation, AlgorithmExecutionCapability.Direction direction,
            String provenance, String authorityFingerprint) {

        /**
         * Creates an immutable selection.
         *
         * @throws NullPointerException if an argument is {@code null}
         */
        public Selection {
            Objects.requireNonNull(requested, "requested");
            Objects.requireNonNull(suite, "suite");
            Objects.requireNonNull(binding, "binding");
            Objects.requireNonNull(implementation, "implementation");
            Objects.requireNonNull(provenance, "provenance");
            Objects.requireNonNull(authorityFingerprint, "authorityFingerprint");
        }
    }

    /**
     * Resolution exception with a stable non-sensitive category.
     */
    public static final class ResolutionException extends IllegalArgumentException {

        private static final long serialVersionUID = 1L;
        /** Stable non-sensitive resolution failure. */
        private final Failure failure;

        /* default */ ResolutionException(Failure failure) {
            super("X.509 algorithm resolution failed: " + failure);
            this.failure = failure;
        }

        private ResolutionException(Failure failure, IllegalArgumentException cause) {
            super("X.509 algorithm resolution failed: " + failure, cause);
            this.failure = failure;
        }

        /**
         * Returns the stable failure category.
         *
         * @return resolution failure
         */
        public Failure failure() {
            return failure;
        }
    }

    /**
     * Creates an immutable resolver snapshot.
     *
     * @param bindings     authoritative binding snapshot
     * @param capabilities installed execution snapshot
     * @param policy       configured restrictive policy
     */
    public X509AlgorithmResolver(X509BindingCatalog bindings, AlgorithmExecutionCapabilities capabilities,
            Policy policy) {
        this.bindings = Objects.requireNonNull(bindings, "bindings");
        this.capabilities = Objects.requireNonNull(capabilities, "capabilities");
        this.policy = Objects.requireNonNull(policy, "policy");
    }

    /**
     * Resolves an exact explicit selection.
     *
     * @param requested       exact signature identity
     * @param key             exact public-key identity
     * @param direction       execution direction
     * @param implementation optional explicit implementation identifier
     * @param provenance      stable default identifier or {@code explicit}
     * @param authorityFingerprint semantic fingerprint of the resolving authority
     * @return immutable effective selection
     * @throws ResolutionException for a precise fail-closed category
     */
    public Selection resolve(AlgorithmIdentity requested, AlgorithmIdentity key,
            AlgorithmExecutionCapability.Direction direction, Optional<String> implementation, String provenance,
            String authorityFingerprint) {
        return resolve(requested, key, direction, implementation, provenance, authorityFingerprint,
                Optional.empty());
    }

    /**
     * Resolves an operation with an optional explicit X.509 binding identity.
     * @param requested exact signature identity
     * @param key exact public-key identity
     * @param direction execution direction
     * @param implementation optional explicit implementation identifier
     * @param provenance stable default identifier or {@code explicit}
     * @param authorityFingerprint semantic fingerprint of the resolving authority
     * @param bindingId optional explicit role-specific binding identifier
     * @return immutable effective selection
     */
    public Selection resolve(AlgorithmIdentity requested, AlgorithmIdentity key,
            AlgorithmExecutionCapability.Direction direction, Optional<String> implementation, String provenance,
            String authorityFingerprint, Optional<String> bindingId) {
        Objects.requireNonNull(requested, "requested");
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(direction, "direction");
        Objects.requireNonNull(implementation, "implementation");
        Objects.requireNonNull(provenance, "provenance");
        Objects.requireNonNull(authorityFingerprint, "authorityFingerprint");
        try {
            X509SecurityFloor.requirePermitted(requested);
        } catch (IllegalArgumentException rejected) {
            throw new ResolutionException(Failure.SECURITY_FLOOR, rejected);
        }
        AlgorithmSuite suite;
        try {
            suite = X509SuiteCompatibility.requireCompatible(requested, key);
        } catch (IllegalArgumentException incompatible) {
            throw new ResolutionException(Failure.INCOMPATIBLE_KEY, incompatible);
        }
        X509AlgorithmIdentifier binding;
        try {
            binding = bindingId.isPresent()
                    ? bindings.resolve(bindingId.orElseThrow(), requested, X509AlgorithmRole.SIGNATURE_ALGORITHM)
                    : bindings.resolve(requested, X509AlgorithmRole.SIGNATURE_ALGORITHM);
        } catch (IllegalArgumentException missing) {
            throw new ResolutionException(Failure.NO_BINDING, missing);
        }
        if (!policy.permits(suite, direction)) {
            throw new ResolutionException(Failure.POLICY);
        }
        List<AlgorithmExecutionCapability> matches = capabilities.supporting(requested, suite, direction);
        AlgorithmExecutionCapability selected = select(matches, implementation);
        return new Selection(requested, suite, binding, selected, direction, provenance, authorityFingerprint);
    }

    private static AlgorithmExecutionCapability select(List<AlgorithmExecutionCapability> matches,
            Optional<String> requestedImplementation) {
        if (requestedImplementation.isPresent()) {
            return matches.stream()
                    .filter(capability -> requestedImplementation.get().equals(capability.implementationId()))
                    .findFirst().orElseThrow(() -> new ResolutionException(Failure.UNKNOWN_IMPLEMENTATION));
        }
        if (matches.isEmpty()) {
            throw new ResolutionException(Failure.NO_CAPABILITY);
        }
        if (matches.size() != UNIQUE_MATCH_COUNT) {
            throw new ResolutionException(Failure.AMBIGUOUS_IMPLEMENTATION);
        }
        return matches.get(0);
    }
}
