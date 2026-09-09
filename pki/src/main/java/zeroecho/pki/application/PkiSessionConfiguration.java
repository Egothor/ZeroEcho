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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.spi.ProviderConfig;

/**
 * Immutable, versioned configuration for one synchronous PKI backend session.
 *
 * <p>Provider values may be sensitive. Callers must not render or log this
 * object. Validation of provider identities and closed property sets occurs
 * before backend allocation.</p>
 *
 * @param version configuration schema version
 * @param store store-provider configuration
 * @param audit audit-provider configuration
 * @param signing optional signing and X.509 service composition
 * @param publishers explicitly enabled publication destinations
 * @param bindingProviders explicitly activated X.509 binding providers
 */
public record PkiSessionConfiguration(int version, ProviderConfig store, ProviderConfig audit,
        Optional<SigningConfiguration> signing, List<ProviderConfig> publishers,
        List<BindingProviderConfiguration> bindingProviders) {

    /** Current configuration schema version. */
    public static final int CURRENT_VERSION = 4;

    /**
     * Creates a read-only-compatible version-one configuration.
     *
     * @param version schema version, from 1 through {@link #CURRENT_VERSION}
     * @param store store-provider configuration
     * @param audit audit-provider configuration
     */
    public PkiSessionConfiguration(int version, ProviderConfig store, ProviderConfig audit) {
        this(version, store, audit, Optional.empty(), List.of(), List.of());
    }

    /**
     * Creates a version-one or version-two configuration without custom bindings.
     *
     * @param version schema version, from 1 through {@link #CURRENT_VERSION}
     * @param store store-provider configuration
     * @param audit audit-provider configuration
     * @param signing optional signing and X.509 service composition
     * @param publishers explicitly enabled publication destinations
     */
    public PkiSessionConfiguration(int version, ProviderConfig store, ProviderConfig audit,
            Optional<SigningConfiguration> signing, List<ProviderConfig> publishers) {
        this(version, store, audit, signing, publishers, List.of());
    }

    /** Validates and snapshots the configuration. */
    public PkiSessionConfiguration {
        if (version < 1 || version > CURRENT_VERSION) {
            throw new IllegalArgumentException("Unsupported PKI session configuration version");
        }
        store = snapshot(Objects.requireNonNull(store, "store"));
        audit = snapshot(Objects.requireNonNull(audit, "audit"));
        signing = Objects.requireNonNull(signing, "signing").map(SigningConfiguration::snapshot);
        publishers = Objects.requireNonNull(publishers, "publishers").stream()
                .map(PkiSessionConfiguration::snapshot).toList();
        bindingProviders = List.copyOf(Objects.requireNonNull(bindingProviders, "bindingProviders"));
        if (version == 1 && (signing.isPresent() || !publishers.isEmpty())) {
            throw new IllegalArgumentException("Version-one configuration cannot enable optional capabilities");
        }
        if (version < 3 && !bindingProviders.isEmpty()) {
            throw new IllegalArgumentException("Custom X.509 bindings require configuration version three");
        }
        if (bindingProviders.stream().map(BindingProviderConfiguration::providerId).distinct().count()
                != bindingProviders.size()) {
            throw new IllegalArgumentException("Duplicate X.509 binding-provider identity");
        }
    }

    private static ProviderConfig snapshot(ProviderConfig config) {
        return new ProviderConfig(config.backendId(), config.properties());
    }

    /**
     * Explicit signing and X.509 service-graph configuration.
     *
     * @param workflow signature-workflow provider configuration
     * @param framework credential-framework provider configuration
     * @param signatureAlgorithm canonical configured signing algorithm
     * @param signingTtl positive synchronous signing deadline
     * @param unlockEnvironmentVariable optional environment-variable reference used
     *        only by the default process composition
     * @param certificateSignatureBinding optional explicit certificate signature binding
     * @param crlSignatureBinding optional explicit CRL signature binding
     * @param subjectPublicKeyBinding optional explicit SPKI binding
     * @param laneCount number of concurrently executing provider steps
     * @param queueCapacity maximum ready steps retained outside the lanes
     * @param gracefulDrain maximum natural-drain duration during close
     * @param forcedCancellation maximum drain duration after cancellation
     * @param signingServices additional named signing services
     * @param caRouting signing-key-reference to service-identifier routing map
     */
    // The record components are the stable serialized configuration schema and cannot be grouped compatibly.
    @SuppressWarnings("PMD.ExcessiveParameterList")
    public record SigningConfiguration(ProviderConfig workflow, ProviderConfig framework,
            String signatureAlgorithm, Duration signingTtl, Optional<String> unlockEnvironmentVariable,
            Optional<String> certificateSignatureBinding, Optional<String> crlSignatureBinding,
            Optional<String> subjectPublicKeyBinding, int laneCount, int queueCapacity,
            Duration gracefulDrain, Duration forcedCancellation,
            List<SigningServiceConfiguration> signingServices, Map<String, String> caRouting) {

        /** Default number of concurrently executing signing steps. */
        public static final int DEFAULT_LANE_COUNT = 16;
        /** Default number of ready signing steps waiting for a lane. */
        public static final int DEFAULT_QUEUE_CAPACITY = 64;
        /** Default time allowed for cooperative signing drain. */
        public static final Duration DEFAULT_GRACEFUL_DRAIN = Duration.ofSeconds(30);
        /** Default time allowed after active signing steps are interrupted. */
        public static final Duration DEFAULT_FORCED_CANCELLATION = Duration.ofSeconds(10);
        /** Smallest supported lane count. */
        public static final int MINIMUM_LANE_COUNT = 1;
        /** Largest supported lane count. */
        public static final int MAXIMUM_LANE_COUNT = 256;
        /** Smallest supported ready-queue capacity. */
        public static final int MINIMUM_QUEUE_CAPACITY = 0;
        /** Largest supported ready-queue capacity. */
        public static final int MAXIMUM_QUEUE_CAPACITY = 65_535;
        /** Largest supported total admission population. */
        public static final int MAXIMUM_ADMISSION_CAPACITY = 65_536;
        /** Smallest supported lifecycle duration. */
        public static final Duration MINIMUM_LIFECYCLE_DURATION = Duration.ofMillis(1);
        /** Largest supported lifecycle duration. */
        public static final Duration MAXIMUM_LIFECYCLE_DURATION = Duration.ofMinutes(10);

        /**
         * Creates standard-mode signing configuration with default execution bounds.
         *
         * @param workflow signature-workflow provider configuration
         * @param framework credential-framework provider configuration
         * @param signatureAlgorithm nonblank canonical signing algorithm
         * @param signingTtl positive synchronous signing deadline
         * @param unlockEnvironmentVariable optional environment-variable reference for key unlocking
         */
        public SigningConfiguration(ProviderConfig workflow, ProviderConfig framework,
                String signatureAlgorithm, Duration signingTtl, Optional<String> unlockEnvironmentVariable) {
            this(workflow, framework, signatureAlgorithm, signingTtl, unlockEnvironmentVariable,
                    Optional.empty(), Optional.empty(), Optional.empty(), DEFAULT_LANE_COUNT,
                    DEFAULT_QUEUE_CAPACITY, DEFAULT_GRACEFUL_DRAIN, DEFAULT_FORCED_CANCELLATION);
        }

        /**
         * Creates a signing configuration with the default bounded execution
         * runtime. This source-compatible constructor is retained for configurations
         * created before schema version four.
         *
         * @param workflow signature-workflow provider configuration
         * @param framework credential-framework provider configuration
         * @param signatureAlgorithm nonblank canonical signing algorithm
         * @param signingTtl positive synchronous signing deadline
         * @param unlockEnvironmentVariable optional environment-variable reference for key unlocking
         * @param certificateSignatureBinding optional explicit certificate-signature binding
         * @param crlSignatureBinding optional explicit CRL-signature binding
         * @param subjectPublicKeyBinding optional explicit subject-public-key binding
         */
        public SigningConfiguration(ProviderConfig workflow, ProviderConfig framework,
                String signatureAlgorithm, Duration signingTtl, Optional<String> unlockEnvironmentVariable,
                Optional<String> certificateSignatureBinding, Optional<String> crlSignatureBinding,
                Optional<String> subjectPublicKeyBinding) {
            this(workflow, framework, signatureAlgorithm, signingTtl, unlockEnvironmentVariable,
                    certificateSignatureBinding, crlSignatureBinding, subjectPublicKeyBinding,
                    DEFAULT_LANE_COUNT, DEFAULT_QUEUE_CAPACITY, DEFAULT_GRACEFUL_DRAIN,
                    DEFAULT_FORCED_CANCELLATION);
        }

        /**
         * Creates a single default-service signing configuration with no additional
         * per-CA routed services. Retained for source compatibility with
         * configurations created before per-CA signing routing.
         *
         * @param workflow signature-workflow provider configuration
         * @param framework credential-framework provider configuration
         * @param signatureAlgorithm nonblank canonical signing algorithm
         * @param signingTtl positive synchronous signing deadline
         * @param unlockEnvironmentVariable optional environment-variable reference for key unlocking
         * @param certificateSignatureBinding optional explicit certificate-signature binding
         * @param crlSignatureBinding optional explicit CRL-signature binding
         * @param subjectPublicKeyBinding optional explicit subject-public-key binding
         * @param laneCount number of concurrently executing provider steps
         * @param queueCapacity maximum ready steps retained outside the lanes
         * @param gracefulDrain maximum natural-drain duration during close
         * @param forcedCancellation maximum drain duration after cancellation
         */
        public SigningConfiguration(ProviderConfig workflow, ProviderConfig framework,
                String signatureAlgorithm, Duration signingTtl, Optional<String> unlockEnvironmentVariable,
                Optional<String> certificateSignatureBinding, Optional<String> crlSignatureBinding,
                Optional<String> subjectPublicKeyBinding, int laneCount, int queueCapacity,
                Duration gracefulDrain, Duration forcedCancellation) {
            this(workflow, framework, signatureAlgorithm, signingTtl, unlockEnvironmentVariable,
                    certificateSignatureBinding, crlSignatureBinding, subjectPublicKeyBinding, laneCount, queueCapacity,
                    gracefulDrain, forcedCancellation, List.of(), Map.of());
        }

        /**
         * Validates and snapshots the signing configuration.
         *
         * <p>{@code signingServices} declares additional signing services (each
         * identified by a stable {@code serviceId} that must equal its allocated
         * workflow's id); {@code caRouting} maps a signing key-reference value to the
         * id of the additional service that must handle it. Any key reference not
         * mapped is handled by the default {@code workflow} service.</p>
         */
        public SigningConfiguration {
            workflow = PkiSessionConfiguration.snapshot(Objects.requireNonNull(workflow, "workflow"));
            framework = PkiSessionConfiguration.snapshot(Objects.requireNonNull(framework, "framework"));
            if (signatureAlgorithm == null || signatureAlgorithm.isBlank()) {
                throw new IllegalArgumentException("Signing algorithm must not be blank");
            }
            if (signingTtl == null || signingTtl.isZero() || signingTtl.isNegative()) {
                throw new IllegalArgumentException("signingTtl must be positive");
            }
            unlockEnvironmentVariable = Objects.requireNonNull(unlockEnvironmentVariable,
                    "unlockEnvironmentVariable");
            certificateSignatureBinding = binding(certificateSignatureBinding, "certificateSignatureBinding");
            crlSignatureBinding = binding(crlSignatureBinding, "crlSignatureBinding");
            subjectPublicKeyBinding = binding(subjectPublicKeyBinding, "subjectPublicKeyBinding");
            if (laneCount < MINIMUM_LANE_COUNT || laneCount > MAXIMUM_LANE_COUNT) {
                throw new IllegalArgumentException("laneCount must be between 1 and 256");
            }
            if (queueCapacity < MINIMUM_QUEUE_CAPACITY || queueCapacity > MAXIMUM_QUEUE_CAPACITY) {
                throw new IllegalArgumentException("queueCapacity must be between 0 and 65535");
            }
            int admissionCapacity;
            try {
                admissionCapacity = Math.addExact(laneCount, queueCapacity);
            } catch (ArithmeticException overflow) {
                throw new IllegalArgumentException("Signing admission capacity overflows", overflow);
            }
            if (admissionCapacity > MAXIMUM_ADMISSION_CAPACITY) {
                throw new IllegalArgumentException("laneCount plus queueCapacity must not exceed 65536");
            }
            gracefulDrain = lifecycleDuration(gracefulDrain, "gracefulDrain");
            forcedCancellation = lifecycleDuration(forcedCancellation, "forcedCancellation");
            unlockEnvironmentVariable.ifPresent(value -> {
                if (!value.matches("[A-Z][A-Z0-9_]{0,127}")) {
                    throw new IllegalArgumentException("Unlock environment-variable reference is invalid");
                }
            });
            signingServices = List.copyOf(Objects.requireNonNull(signingServices, "signingServices"));
            caRouting = Map.copyOf(Objects.requireNonNull(caRouting, "caRouting"));
            java.util.Set<String> serviceIds = new java.util.HashSet<>();
            for (SigningServiceConfiguration service : signingServices) {
                if (!serviceIds.add(service.serviceId())) {
                    throw new IllegalArgumentException("Duplicate signing service id: " + service.serviceId());
                }
            }
            for (Map.Entry<String, String> route : caRouting.entrySet()) {
                if (route.getKey().isBlank()) {
                    throw new IllegalArgumentException("Signing routing key reference must not be blank");
                }
                if (!serviceIds.contains(route.getValue())) {
                    throw new IllegalArgumentException("Signing routing references an unknown service id: "
                            + route.getValue());
                }
            }
        }

        private static SigningConfiguration snapshot(SigningConfiguration source) {
            return new SigningConfiguration(source.workflow, source.framework, source.signatureAlgorithm,
                    source.signingTtl, source.unlockEnvironmentVariable,
                    source.certificateSignatureBinding, source.crlSignatureBinding, source.subjectPublicKeyBinding,
                    source.laneCount, source.queueCapacity, source.gracefulDrain, source.forcedCancellation,
                    source.signingServices, source.caRouting);
        }

        /**
         * Returns the exact bounded admission population.
         *
         * @return {@code laneCount + queueCapacity}
         */
        public int admissionCapacity() {
            return Math.addExact(laneCount, queueCapacity);
        }

        private static Duration lifecycleDuration(Duration value, String name) {
            Duration exact = Objects.requireNonNull(value, name);
            if (exact.compareTo(MINIMUM_LIFECYCLE_DURATION) < 0
                    || exact.compareTo(MAXIMUM_LIFECYCLE_DURATION) > 0) {
                throw new IllegalArgumentException(name + " must be between PT0.001S and PT10M");
            }
            return exact;
        }

        private static Optional<String> binding(Optional<String> source, String name) {
            return Objects.requireNonNull(source, name).map(value -> {
                if (value.isBlank() || value.length() > 512) {
                    throw new IllegalArgumentException(name + " is invalid");
                }
                return value;
            });
        }
    }

    /**
     * One additional signing service that specific certification authorities route
     * their signing to, alongside the default {@code workflow} service.
     *
     * @param serviceId stable service identity; must equal the allocated workflow's
     *        {@code id()} so that per-record routing and namespaces line up
     * @param workflow signature-workflow provider configuration for this service
     */
    public record SigningServiceConfiguration(String serviceId, ProviderConfig workflow) {

        /** Validates and snapshots the service configuration. */
        public SigningServiceConfiguration {
            if (serviceId == null || serviceId.isBlank()) {
                throw new IllegalArgumentException("Signing service id must not be blank");
            }
            // The qualifier avoids resolving the record component accessor in this compact constructor.
            workflow = PkiSessionConfiguration.snapshot(Objects.requireNonNull(workflow, "workflow")); // NOPMD
        }
    }

    /**
     * Explicit activation and namespace authorization for one installed binding
     * provider.
     *
     * @param providerId stable installed provider identity
     * @param authorizedOidRoots finite roots owned by the deployment
     * @param expectedBindingSetVersion optional pinned provider binding-set version
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
