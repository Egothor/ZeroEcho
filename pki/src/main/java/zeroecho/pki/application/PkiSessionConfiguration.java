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
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.spi.ProviderConfig;

/**
 * Immutable configuration for one PKI backend session.
 *
 * <p>The project is pre-release. This type describes only the current format;
 * it provides no compatibility constructors or migration interpretation.</p>
 *
 * @param version exact configuration schema version
 * @param store store-provider configuration
 * @param audit audit-provider configuration
 * @param signing optional provider/domain configuration reserved for the reactive signing layer
 * @param publishers explicitly enabled publication destinations
 * @param bindingProviders explicitly activated X.509 binding providers
 */
public record PkiSessionConfiguration(int version, ProviderConfig store, ProviderConfig audit,
        Optional<SigningConfiguration> signing, List<ProviderConfig> publishers,
        List<BindingProviderConfiguration> bindingProviders) {

    /** Current and only accepted configuration schema version. */
    public static final int CURRENT_VERSION = 6;

    /** Validates and snapshots the current configuration. */
    public PkiSessionConfiguration {
        if (version != CURRENT_VERSION) {
            throw new IllegalArgumentException("Unsupported PKI session configuration version");
        }
        store = snapshot(Objects.requireNonNull(store, "store"));
        audit = snapshot(Objects.requireNonNull(audit, "audit"));
        signing = Objects.requireNonNull(signing, "signing").map(SigningConfiguration::snapshot);
        publishers = Objects.requireNonNull(publishers, "publishers").stream()
                .map(PkiSessionConfiguration::snapshot).toList();
        bindingProviders = List.copyOf(Objects.requireNonNull(bindingProviders, "bindingProviders"));
        if (bindingProviders.stream().map(BindingProviderConfiguration::providerId).distinct().count()
                != bindingProviders.size()) {
            throw new IllegalArgumentException("Duplicate X.509 binding-provider identity");
        }
    }

    private static ProviderConfig snapshot(ProviderConfig config) {
        return new ProviderConfig(config.backendId(), config.properties());
    }

    /**
     * Provider, domain and explicit bounded runtime values for reactive signing.
     *
     * @param provider signing-provider configuration
     * @param signatureAlgorithm canonical configured signing algorithm
     * @param signingTtl positive signing deadline
     * @param unlockEnvironmentVariable optional environment-variable reference
     * @param topology explicit bounded signing routing topology
     * @param pureEdDsaMaximumTbsBytes optional operator-selected maximum raw
     *        {@code TBSCertList} size for pure Ed25519 or Ed448; empty selects
     *        the heap- and concurrency-aware default
     */
    public record SigningConfiguration(ProviderConfig provider,
            String signatureAlgorithm, Duration signingTtl, Optional<String> unlockEnvironmentVariable,
            SigningTopology topology, OptionalLong pureEdDsaMaximumTbsBytes) {

        private static final long MAXIMUM_JCA_MESSAGE_BYTES = Integer.MAX_VALUE - 8L;
        private static final long EDDSA_TRANSFER_BUFFER_BYTES = 16L * 1024L;

        /** Validates and snapshots provider/domain configuration. */
        public SigningConfiguration {
            provider = PkiSessionConfiguration.snapshot(Objects.requireNonNull(provider, "provider"));
            if (signatureAlgorithm == null || signatureAlgorithm.isBlank()) {
                throw new IllegalArgumentException("Signing algorithm must not be blank");
            }
            if (signingTtl == null || signingTtl.isZero() || signingTtl.isNegative()) {
                throw new IllegalArgumentException("signingTtl must be positive");
            }
            unlockEnvironmentVariable = Objects.requireNonNull(unlockEnvironmentVariable,
                    "unlockEnvironmentVariable");
            unlockEnvironmentVariable.ifPresent(value -> {
                if (!value.matches("[A-Z][A-Z0-9_]{0,127}")) {
                    throw new IllegalArgumentException("Unlock environment-variable reference is invalid");
                }
            });
            topology = Objects.requireNonNull(topology, "topology");
            pureEdDsaMaximumTbsBytes = Objects.requireNonNull(pureEdDsaMaximumTbsBytes,
                    "pureEdDsaMaximumTbsBytes");
            if (pureEdDsaMaximumTbsBytes.isPresent()
                    && (pureEdDsaMaximumTbsBytes.getAsLong() <= 0
                            || pureEdDsaMaximumTbsBytes.getAsLong() > MAXIMUM_JCA_MESSAGE_BYTES)) {
                throw new IllegalArgumentException("pureEdDsaMaximumTbsBytes is outside its finite bound");
            }
        }

        private static SigningConfiguration snapshot(SigningConfiguration source) {
            return new SigningConfiguration(source.provider, source.signatureAlgorithm,
                    source.signingTtl, source.unlockEnvironmentVariable, source.topology,
                    source.pureEdDsaMaximumTbsBytes);
        }

        /**
         * Resolves the maximum raw pure-EdDSA {@code TBSCertList} size.
         *
         * <p>An explicit operator value is returned unchanged. Otherwise, half of
         * the supplied maximum heap is treated as the aggregate budget for all
         * signing lanes. The SunEC pure-EdDSA buffering model reserves three bytes
         * per input byte plus one transfer buffer per lane. The result is also
         * capped by the JCA array representation.</p>
         *
         * @param maximumHeapBytes positive maximum JVM heap in bytes
         * @return positive inclusive message-size limit in bytes
         * @throws IllegalArgumentException if the heap cannot provide a positive
         *         derived limit
         */
        public long resolvePureEdDsaMaximumTbsBytes(long maximumHeapBytes) {
            if (pureEdDsaMaximumTbsBytes.isPresent()) {
                return pureEdDsaMaximumTbsBytes.getAsLong();
            }
            if (maximumHeapBytes <= 0) {
                throw new IllegalArgumentException("maximumHeapBytes must be positive");
            }
            long perLaneBudget = maximumHeapBytes / 2L / topology.totalLaneCount();
            long available = perLaneBudget - EDDSA_TRANSFER_BUFFER_BYTES;
            long derived = available / 3L;
            if (derived <= 0) {
                throw new IllegalArgumentException("Maximum heap is too small for pure EdDSA signing");
            }
            return Math.min(derived, MAXIMUM_JCA_MESSAGE_BYTES);
        }
    }

    /**
     * Immutable P1c signing topology with disjoint exact-key groups and one
     * mandatory catch-all lane pool.
     *
     * @param coordinator limits shared by the topology coordinator
     * @param exactGroups disjoint exact-key routing groups; may be empty
     * @param catchAll mandatory lane pool for keys not assigned to an exact group
     */
    public record SigningTopology(SigningCoordinatorLimits coordinator,
            List<SigningKeyGroup> exactGroups, SigningLanePool catchAll) {
        private static final int MAXIMUM_LANES = 256;
        private static final int MAXIMUM_PREFETCH_ENTRIES = 4096;
        private static final int MAXIMUM_EXACT_GROUPS = 255;
        private static final int MAXIMUM_EXACT_KEYS = 4096;

        /** Validates aggregate bounds, routing uniqueness, and snapshots groups. */
        public SigningTopology {
            coordinator = Objects.requireNonNull(coordinator, "coordinator");
            catchAll = Objects.requireNonNull(catchAll, "catchAll");
            List<SigningKeyGroup> suppliedGroups =
                    Objects.requireNonNull(exactGroups, "exactGroups");
            if (suppliedGroups.size() > MAXIMUM_EXACT_GROUPS) {
                throw new IllegalArgumentException(
                        "Exact signing-key group count exceeds its finite bound");
            }
            exactGroups = List.copyOf(suppliedGroups);

            int totalLanes = catchAll.laneCount();
            int totalPrefetch = catchAll.prefetchSize();
            int totalExactKeys = 0;
            Set<KeyRef> assignedKeys = new HashSet<>();
            for (SigningKeyGroup group : exactGroups) {
                SigningKeyGroup exactGroup = Objects.requireNonNull(group, "exact group");
                totalLanes = addWithinBound(totalLanes, exactGroup.lanePool().laneCount(),
                        MAXIMUM_LANES, "Total signing lane count exceeds its finite bound");
                totalPrefetch = addWithinBound(totalPrefetch, exactGroup.lanePool().prefetchSize(),
                        MAXIMUM_PREFETCH_ENTRIES,
                        "Total signing prefetch count exceeds its finite bound");
                totalExactKeys = addWithinBound(totalExactKeys, exactGroup.keyRefs().size(),
                        MAXIMUM_EXACT_KEYS,
                        "Total exact signing-key count exceeds its finite bound");
                for (KeyRef keyRef : exactGroup.keyRefs()) {
                    if (!assignedKeys.add(keyRef)) {
                        throw new IllegalArgumentException(
                                "A signing key is assigned to more than one exact route");
                    }
                }
            }
            if (coordinator.pageSize() > totalPrefetch) {
                throw new IllegalArgumentException(
                        "Signing page size exceeds aggregate prefetch capacity");
            }
        }

        private static int addWithinBound(int current, int increment, int maximum,
                String message) {
            try {
                int total = Math.addExact(current, increment);
                if (total > maximum) {
                    throw new IllegalArgumentException(message);
                }
                return total;
            } catch (ArithmeticException exception) {
                throw new IllegalArgumentException(message, exception);
            }
        }

        /**
         * Returns the maximum number of concurrent provider calls owned by this
         * topology.
         *
         * @return positive aggregate lane count
         */
        public int totalLaneCount() {
            int total = catchAll.laneCount();
            for (SigningKeyGroup group : exactGroups) {
                total += group.lanePool().laneCount();
            }
            return total;
        }
    }

    /**
     * Shared finite coordinator and provider-call bounds for a P1c signing
     * topology.
     *
     * @param pageSize durable due-work page size, from 1 through 4096
     * @param claimLease positive claim lease, strictly longer than one provider call timeout
     * @param providerCallTimeout positive finite provider-call timeout
     * @param idlePollInterval finite idle polling interval of at least one millisecond
     * @param closeTimeout positive finite close timeout
     */
    public record SigningCoordinatorLimits(int pageSize, Duration claimLease,
            Duration providerCallTimeout, Duration idlePollInterval, Duration closeTimeout) {
        private static final int MAXIMUM_PAGE_ENTRIES = 4096;
        private static final Duration MINIMUM_IDLE_POLL_INTERVAL = Duration.ofMillis(1L);
        private static final Duration MAXIMUM_DURATION = Duration.ofDays(1L);

        /** Validates explicit finite coordinator and duration bounds. */
        public SigningCoordinatorLimits {
            if (pageSize < 1 || pageSize > MAXIMUM_PAGE_ENTRIES) {
                throw new IllegalArgumentException("pageSize is outside its finite bound");
            }
            requireCoordinatorDuration(claimLease, "claimLease");
            requireCoordinatorDuration(providerCallTimeout, "providerCallTimeout");
            requireCoordinatorDuration(idlePollInterval, "idlePollInterval");
            requireCoordinatorDuration(closeTimeout, "closeTimeout");
            if (idlePollInterval.compareTo(MINIMUM_IDLE_POLL_INTERVAL) < 0) {
                throw new IllegalArgumentException(
                        "idlePollInterval must be at least one millisecond");
            }
            if (claimLease.compareTo(providerCallTimeout) <= 0) {
                throw new IllegalArgumentException("claimLease must exceed providerCallTimeout");
            }
        }

        private static void requireCoordinatorDuration(Duration value, String name) {
            Objects.requireNonNull(value, name);
            if (value.isZero() || value.isNegative() || value.compareTo(MAXIMUM_DURATION) > 0) {
                throw new IllegalArgumentException(name + " is outside its finite bound");
            }
        }
    }

    /**
     * One exact-key routing group and its dedicated lane pool.
     *
     * @param keyRefs nonempty immutable exact-key set expressed as a list
     * @param lanePool dedicated bounded lane pool
     */
    public record SigningKeyGroup(List<KeyRef> keyRefs, SigningLanePool lanePool) {
        private static final int MAXIMUM_KEYS = 4096;
        private static final long MAXIMUM_KEY_REFERENCE_UTF8_BYTES = 1_048_576L; // NOPMD - LongVariable: descriptive byte-unit/projection name preserves its established contract.

        /** Validates and snapshots one exact-key group without exposing key values. */
        public SigningKeyGroup {
            lanePool = Objects.requireNonNull(lanePool, "lanePool");
            List<KeyRef> suppliedKeys = Objects.requireNonNull(keyRefs, "keyRefs");
            int keyCount = suppliedKeys.size();
            if (keyCount < 1 || keyCount > MAXIMUM_KEYS) {
                throw new IllegalArgumentException(
                        "Exact signing-key group size is outside its finite bound");
            }
            for (KeyRef keyRef : suppliedKeys) {
                KeyRef exact = Objects.requireNonNull(keyRef, "keyRef");
                if (exact.utf8Length() > MAXIMUM_KEY_REFERENCE_UTF8_BYTES) {
                    throw new IllegalArgumentException(
                            "Signing key reference exceeds its finite byte bound");
                }
            }
            keyRefs = List.copyOf(suppliedKeys);
            Set<KeyRef> uniqueKeys = new HashSet<>();
            for (KeyRef keyRef : keyRefs) {
                if (!uniqueKeys.add(Objects.requireNonNull(keyRef, "keyRef"))) {
                    throw new IllegalArgumentException(
                            "An exact signing-key group contains a duplicate key");
                }
            }
        }

        @Override
        public String toString() {
            return "SigningKeyGroup[keyRefs=<redacted>, lanePool=" + lanePool + ']';
        }
    }

    /**
     * Finite execution and prefetch capacity owned by one signing route.
     *
     * @param laneCount lane count, from 1 through 256
     * @param prefetchSize prefetched identifier capacity, from 1 through 4096
     */
    public record SigningLanePool(int laneCount, int prefetchSize) {
        private static final int MAXIMUM_LANES = 256;
        private static final int MAXIMUM_PREFETCH_ENTRIES = 4096;

        /** Validates explicit finite per-pool bounds. */
        public SigningLanePool {
            if (laneCount < 1 || laneCount > MAXIMUM_LANES) {
                throw new IllegalArgumentException("laneCount is outside its finite bound");
            }
            if (prefetchSize < 1 || prefetchSize > MAXIMUM_PREFETCH_ENTRIES) {
                throw new IllegalArgumentException("prefetchSize is outside its finite bound");
            }
        }
    }

    /**
     * Activation and OID namespace authorization for an installed binding provider.
     *
     * @param providerId stable installed provider identity
     * @param authorizedOidRoots finite roots owned by the deployment
     * @param expectedBindingSetVersion optional pinned binding-set version
     */
    public record BindingProviderConfiguration(String providerId, List<String> authorizedOidRoots,
            Optional<String> expectedBindingSetVersion) {

        /** Validates and snapshots the activation. */
        public BindingProviderConfiguration {
            if (providerId == null || providerId.isBlank()) {
                throw new IllegalArgumentException("binding providerId must not be blank");
            }
            authorizedOidRoots = List.copyOf(Objects.requireNonNull(authorizedOidRoots, "authorizedOidRoots"));
            if (authorizedOidRoots.isEmpty() || authorizedOidRoots.stream().anyMatch(root -> root == null
                    || !root.matches("[0-2](?:\\.[0-9]+)+"))) {
                throw new IllegalArgumentException("Authorized OID roots are invalid");
            }
            if (authorizedOidRoots.stream().distinct().count() != authorizedOidRoots.size()) {
                throw new IllegalArgumentException("Authorized OID roots are duplicated");
            }
            expectedBindingSetVersion = Objects.requireNonNull(expectedBindingSetVersion,
                    "expectedBindingSetVersion").map(value -> {
                        if (value.isBlank() || value.length() > 512) {
                            throw new IllegalArgumentException("Expected binding-set version is invalid");
                        }
                        return value;
                    });
        }
    }
}
