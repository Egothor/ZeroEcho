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

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509BindingCatalog;

/**
 * Bouncy Castle edge adapter for the provider-neutral X.509 binding authority.
 *
 * <p>
 * This adapter owns no OID table, default, or alias. It performs only structural
 * conversion and delegates semantic resolution to an immutable
 * {@link X509BindingCatalog}.
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
     * Resolves an exact identity and converts it to Bouncy Castle representation.
     *
     * @param identity exact identity
     * @param role     closed X.509 role
     * @return exact BC algorithm identifier
     */
    public AlgorithmIdentifier encode(AlgorithmIdentity identity, X509AlgorithmRole role) {
        return toBc(catalog.resolve(identity, role));
    }

    /**
     * Converts and reverse-resolves a BC algorithm identifier.
     *
     * @param identifier BC structural representation
     * @param role       closed X.509 role
     * @return exact provider-independent identity
     * @throws IllegalArgumentException if encoding or parameters are invalid
     */
    public AlgorithmIdentity decode(AlgorithmIdentifier identifier, X509AlgorithmRole role) {
        return catalog.reverse(fromBc(identifier), role);
    }

    /**
     * Converts a provider-neutral identifier to Bouncy Castle form.
     *
     * @param identifier provider-neutral value
     * @return BC value
     */
    public static AlgorithmIdentifier toBc(X509AlgorithmIdentifier identifier) {
        Objects.requireNonNull(identifier, "identifier");
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(identifier.oid());
        return switch (identifier.parameterForm()) {
            case ABSENT -> new AlgorithmIdentifier(oid);
            case DER_NULL -> new AlgorithmIdentifier(oid, DERNull.INSTANCE);
            case EXACT_DER -> {
                try {
                    ASN1Primitive parameters = ASN1Primitive.fromByteArray(identifier.parameters());
                    yield new AlgorithmIdentifier(oid, parameters);
                } catch (IOException | IllegalArgumentException exception) {
                    throw new IllegalArgumentException("Invalid canonical X.509 parameter DER", exception);
                }
            }
        };
    }

    /**
     * Converts a BC identifier to an exact provider-neutral representation.
     *
     * @param identifier BC value
     * @return provider-neutral value
     * @throws IllegalArgumentException if parameter DER is malformed
     */
    public static X509AlgorithmIdentifier fromBc(AlgorithmIdentifier identifier) {
        Objects.requireNonNull(identifier, "identifier");
        String oid = identifier.getAlgorithm().getId();
        if (identifier.getParameters() == null) {
            return X509AlgorithmIdentifier.absent(oid);
        }
        if (DERNull.INSTANCE.equals(identifier.getParameters().toASN1Primitive())) {
            return X509AlgorithmIdentifier.derNull(oid);
        }
        try {
            return X509AlgorithmIdentifier.exact(oid,
                    identifier.getParameters().toASN1Primitive().getEncoded(ASN1Encoding.DER));
        } catch (IOException exception) {
            throw new IllegalArgumentException("Cannot encode X.509 algorithm parameters", exception);
        }
    }

}
