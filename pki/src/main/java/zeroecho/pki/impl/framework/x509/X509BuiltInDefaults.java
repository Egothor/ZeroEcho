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

import java.util.Map;
import java.util.Objects;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmSuite;

/**
 * Immutable code-owned PKI defaults.
 *
 * <p>
 * Default identifiers and meanings cannot be registered, redirected, removed,
 * or shadowed by extensions or administrative configuration. A future
 * recommendation must use a new versioned identifier.
 * </p>
 */
public final class X509BuiltInDefaults {

    /**
     * Historical and current version-one certificate, CRL, and CA-proof signing
     * default.
     */
    public static final String PKI_SIGNATURE_DEFAULT_V1 = "zeroecho.default.pki-signature.v1";

    private static final Map<String, AlgorithmSuite> DEFAULTS = Map.of(PKI_SIGNATURE_DEFAULT_V1,
            BootstrapAlgorithmIdentities.PKI_SIGNATURE_DEFAULT_V1);

    private X509BuiltInDefaults() {
    }

    /**
     * Resolves one immutable built-in default.
     *
     * @param identifier stable versioned default identifier
     * @return exact suite
     * @throws IllegalArgumentException if the identifier is unknown
     */
    public static AlgorithmSuite resolve(String identifier) {
        Objects.requireNonNull(identifier, "identifier");
        AlgorithmSuite suite = DEFAULTS.get(identifier);
        if (suite == null) {
            throw new IllegalArgumentException("Unknown built-in default identifier");
        }
        return suite;
    }

    /**
     * Returns a semantic fingerprint of all immutable defaults.
     *
     * @return deterministic immutable identifier-to-suite map
     */
    public static Map<String, AlgorithmSuite> snapshot() {
        return DEFAULTS;
    }
}
