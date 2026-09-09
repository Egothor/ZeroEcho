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
package zeroecho.pki.impl.framework.x509.bc;

import java.io.IOException;
import java.util.Objects;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509BindingCatalog;
import zeroecho.pki.impl.framework.x509.X509BindingRule;

/**
 * Adapter for binding-owned {@code SubjectPublicKeyInfo} encodings, expressed
 * entirely in terms of canonical DER byte arrays and the ZeroEcho PKIX library.
 */
public final class BcX509PublicKeyAdapter {

    private static final int MAXIMUM_SPKI_BYTES = 1024 * 1024;
    private final X509BindingCatalog catalog;

    /**
     * Creates an adapter for one immutable binding catalog.
     *
     * @param catalog authoritative X.509 representation-binding catalog
     */
    public BcX509PublicKeyAdapter(X509BindingCatalog catalog) {
        this.catalog = Objects.requireNonNull(catalog, "catalog");
    }

    /**
     * Wraps canonical native SPKI DER under one explicit binding.
     *
     * @param nativeSpki canonical provider-native SPKI DER
     * @param identity exact public-key identity
     * @param bindingId explicit SPKI binding
     * @return canonical bound SPKI DER
     * @throws IOException if either SPKI cannot be represented canonically
     */
    public byte[] wrap(byte[] nativeSpki, AlgorithmIdentity identity, String bindingId) throws IOException {
        requireCanonical(nativeSpki);
        zeroecho.pkix.AlgorithmIdentifier algorithm = BcX509AlgorithmAdapter.toLib(
                catalog.resolve(bindingId, identity, X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM));
        byte[] wrapped = zeroecho.pkix.Pkix.buildSubjectPublicKeyInfo(algorithm, nativeSpki);
        requireCanonical(wrapped);
        return wrapped;
    }

    /**
     * Returns provider-native SPKI DER for verification or key import.
     *
     * @param input exact active SPKI DER
     * @return canonical native SPKI DER; the input itself for standard encodings
     * @throws IOException if nested SPKI bytes are malformed or non-canonical
     */
    public byte[] unwrap(byte[] input) throws IOException {
        Objects.requireNonNull(input, "input");
        String bindingId = catalog.bindingId(
                BcX509AlgorithmAdapter.fromLib(zeroecho.pkix.Pkix.subjectPublicKeyAlgorithm(input)),
                X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        X509BindingRule rule = catalog.rules().stream().filter(candidate -> candidate.id().equals(bindingId))
                .findFirst().orElseThrow(() -> new IllegalArgumentException("SPKI binding rule is unavailable"));
        if (rule.publicKeyEncoding() != X509BindingRule.PublicKeyEncoding.NESTED_SPKI_DER) {
            return input;
        }
        byte[] nested = zeroecho.pkix.Pkix.subjectPublicKeyBytes(input);
        requireCanonical(nested);
        return nested;
    }

    private static void requireCanonical(byte[] encoded) throws IOException {
        new StreamingDerReader().validateSubjectPublicKeyInfo(encoded, MAXIMUM_SPKI_BYTES);
    }
}
