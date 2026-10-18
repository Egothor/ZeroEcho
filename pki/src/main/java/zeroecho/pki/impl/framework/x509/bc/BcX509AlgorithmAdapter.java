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
package zeroecho.pki.impl.framework.x509.bc;

import java.util.Objects;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509BindingCatalog;

/**
 * Edge adapter between the provider-neutral X.509 binding authority and the
 * ZeroEcho PKIX library's {@link zeroecho.pkix.AlgorithmIdentifier} value type.
 *
 * <p>
 * This adapter owns no OID table, default, or alias. It performs only structural
 * conversion between the two provider-neutral representations and delegates
 * semantic resolution to an immutable {@link X509BindingCatalog}. It contains no
 * concrete cryptographic-toolkit type.
 * </p>
 */
public final class BcX509AlgorithmAdapter {

    private final X509BindingCatalog catalog;

    /**
     * Creates an adapter for one immutable catalog snapshot.
     *
     * @param catalog authoritative provider-neutral binding catalog
     */
    public BcX509AlgorithmAdapter(X509BindingCatalog catalog) {
        this.catalog = Objects.requireNonNull(catalog, "catalog");
    }

    /**
     * Resolves an exact identity and converts it to the PKIX library value type.
     *
     * @param identity exact identity
     * @param role     closed X.509 role
     * @return exact library algorithm identifier
     */
    public zeroecho.pkix.AlgorithmIdentifier encode(AlgorithmIdentity identity, X509AlgorithmRole role) {
        return toLib(catalog.resolve(identity, role));
    }

    /**
     * Converts and reverse-resolves a PKIX library algorithm identifier.
     *
     * @param identifier PKIX library structural representation
     * @param role       closed X.509 role
     * @return exact provider-independent identity
     * @throws IllegalArgumentException if encoding or parameters are invalid
     */
    public AlgorithmIdentity decode(zeroecho.pkix.AlgorithmIdentifier identifier, X509AlgorithmRole role) {
        return catalog.reverse(fromLib(identifier), role);
    }

    /**
     * Converts a provider-neutral identifier to the PKIX library value type.
     *
     * @param identifier provider-neutral value
     * @return PKIX library value
     */
    public static zeroecho.pkix.AlgorithmIdentifier toLib(X509AlgorithmIdentifier identifier) {
        Objects.requireNonNull(identifier, "identifier");
        return switch (identifier.parameterForm()) {
            case ABSENT -> zeroecho.pkix.AlgorithmIdentifier.absent(identifier.oid());
            case DER_NULL -> zeroecho.pkix.AlgorithmIdentifier.derNull(identifier.oid());
            case EXACT_DER -> zeroecho.pkix.AlgorithmIdentifier.exact(identifier.oid(), identifier.parameters());
        };
    }

    /**
     * Converts a PKIX library identifier to the exact provider-neutral representation.
     *
     * @param identifier PKIX library value
     * @return provider-neutral value
     */
    public static X509AlgorithmIdentifier fromLib(zeroecho.pkix.AlgorithmIdentifier identifier) {
        Objects.requireNonNull(identifier, "identifier");
        return switch (identifier.parameterForm()) {
            case ABSENT -> X509AlgorithmIdentifier.absent(identifier.oid());
            case DER_NULL -> X509AlgorithmIdentifier.derNull(identifier.oid());
            case EXACT_DER -> X509AlgorithmIdentifier.exact(identifier.oid(), identifier.parameters());
        };
    }

}
