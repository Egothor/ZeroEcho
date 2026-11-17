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
package zeroecho.pki.server;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.CredentialConfirmationProofAudience;
import zeroecho.pki.application.PkiOperationValue;

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Decodes realm proof, disclosure and authority exposure policies from JSON configuration.
 */
final class ConfigurationRealmPolicies {
    private static final long DEFAULT_CHALLENGE_TTL_MILLIS = 300_000L;
    private static final int DEFAULT_RSA_MAXIMUM_BITS = 8_192;

    private ConfigurationRealmPolicies() {}

    /* default */ static CredentialConfirmationProofPolicy confirmationProof(
            ConfigurationFields value) {
        value.allowed(Set.of("audience", "challengeTtlMillis", "rsaMaximumModulusBits"));
        long ttlMillis =
                value.optionalLong("challengeTtlMillis").orElse(DEFAULT_CHALLENGE_TTL_MILLIS);
        if (ttlMillis % 1_000L != 0) {
            throw new IllegalArgumentException(
                    "Credential confirmation proof TTL must be a whole number of seconds");
        }
        CredentialConfirmationProofPolicy result =
                new CredentialConfirmationProofPolicy(
                        new CredentialConfirmationProofAudience(value.text("audience")),
                        Duration.ofMillis(ttlMillis),
                        value.optionalInteger("rsaMaximumModulusBits")
                                .orElse(DEFAULT_RSA_MAXIMUM_BITS));
        value.complete();
        return result;
    }

    /* default */ static DisclosureService.Defaults disclosure(ConfigurationFields value) {
        value.exact("rootCa", "intermediateCa", "caChain", "crl", "leaf", "sensitiveLeaf");
        DisclosureService.Defaults result =
                new DisclosureService.Defaults(
                        policy(value.text("rootCa")),
                        policy(value.text("intermediateCa")),
                        policy(value.text("caChain")),
                        policy(value.text("crl")),
                        policy(value.text("leaf")),
                        policy(value.text("sensitiveLeaf")));
        value.complete();
        return result;
    }

    private static DisclosureService.Policy policy(String value) {
        return DisclosureService.Policy.valueOf(value);
    }

    /* default */ static AuthorityExposurePolicy exposure(ConfigurationFields value) {
        value.exact("mode", "authorityIds", "creationPermitted");
        Set<PkiId> authorities = new LinkedHashSet<>();
        for (PkiOperationValue item : value.list("authorityIds")) {
            authorities.add(new PkiId(ConfigurationFields.text(item)));
        }
        AuthorityExposurePolicy result =
                new AuthorityExposurePolicy(
                        AuthorityExposurePolicy.Mode.valueOf(value.text("mode")),
                        authorities,
                        value.bool("creationPermitted"));
        value.complete();
        return result;
    }
}
