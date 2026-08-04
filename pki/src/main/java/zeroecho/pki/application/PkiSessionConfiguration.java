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
 */
public record PkiSessionConfiguration(int version, ProviderConfig store, ProviderConfig audit,
        Optional<SigningConfiguration> signing, List<ProviderConfig> publishers) {

    /** Current configuration schema version. */
    public static final int CURRENT_VERSION = 2;

    /** Creates a read-only-compatible version-one configuration. */
    public PkiSessionConfiguration(int version, ProviderConfig store, ProviderConfig audit) {
        this(version, store, audit, Optional.empty(), List.of());
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
        if (version == 1 && (signing.isPresent() || !publishers.isEmpty())) {
            throw new IllegalArgumentException("Version-one configuration cannot enable optional capabilities");
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
     * @param busPath durable signing-bus path
     * @param signatureAlgorithm canonical configured signing algorithm
     * @param signingTtl positive synchronous signing deadline
     * @param unlockEnvironmentVariable optional environment-variable reference used
     *        only by the default process composition
     */
    public record SigningConfiguration(ProviderConfig workflow, ProviderConfig framework, String busPath,
            String signatureAlgorithm, Duration signingTtl, Optional<String> unlockEnvironmentVariable) {

        /** Validates and snapshots the signing configuration. */
        public SigningConfiguration {
            workflow = PkiSessionConfiguration.snapshot(Objects.requireNonNull(workflow, "workflow"));
            framework = PkiSessionConfiguration.snapshot(Objects.requireNonNull(framework, "framework"));
            if (busPath == null || busPath.isBlank() || signatureAlgorithm == null || signatureAlgorithm.isBlank()) {
                throw new IllegalArgumentException("Signing paths and algorithm must not be blank");
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
        }

        private static SigningConfiguration snapshot(SigningConfiguration source) {
            return new SigningConfiguration(source.workflow, source.framework, source.busPath,
                    source.signatureAlgorithm, source.signingTtl, source.unlockEnvironmentVariable);
        }
    }
}
