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
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.spi.ProviderConfig;

/**
 * Immutable standalone configuration with an explicitly declared trusted local operator.
 *
 * @param store exclusive authoritative store configuration
 * @param audit existing audit sink configuration
 * @param operatorId nonblank local operator identity, at most 256 Java characters
 * @param signing optional local signing configuration
 * @param publishers explicit synchronous publication destinations
 * @param bindingProviders explicit algorithm binding activations
 */
public record LocalPkiSessionConfiguration(ProviderConfig store, ProviderConfig audit, String operatorId,
        Optional<LocalSigningConfiguration> signing, List<ProviderConfig> publishers,
        List<PkiSessionConfiguration.BindingProviderConfiguration> bindingProviders) {
    private static final int MAX_OPERATOR_LENGTH = 256;
    /** Standalone configuration document version; this does not version stored PKI data. */
    public static final int CURRENT_VERSION = 1;

    /** Validates identity and snapshots provider lists before opening any resource. */
    public LocalPkiSessionConfiguration {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(audit, "audit");
        new Principal("LOCAL_OPERATOR", operatorId);
        if (operatorId.length() > MAX_OPERATOR_LENGTH) {
            throw new IllegalArgumentException("Local operator identity exceeds the existing evidence bound");
        }
        Objects.requireNonNull(signing, "signing");
        publishers = List.copyOf(Objects.requireNonNull(publishers, "publishers"));
        bindingProviders = List.copyOf(Objects.requireNonNull(bindingProviders, "bindingProviders"));
        if (bindingProviders.stream().map(PkiSessionConfiguration.BindingProviderConfiguration::providerId)
                .distinct().count() != bindingProviders.size()) {
            throw new IllegalArgumentException("Duplicate X.509 binding-provider identity");
        }
    }
}
