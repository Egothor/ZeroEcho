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
package zeroecho.pkix.bc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;

import zeroecho.pkix.AlgorithmIdentifier;

/**
 * Structural conversion between the provider-independent {@link AlgorithmIdentifier}
 * and the BouncyCastle {@code AlgorithmIdentifier}, plus OID-to-JCA name mapping.
 *
 * <p>
 * This class is confined to the {@code lib} module and never leaks BouncyCastle
 * types beyond {@code zeroecho.pkix.bc}.
 * </p>
 */
final class BcAlgorithmIdentifiers {

    private static final DefaultAlgorithmNameFinder NAME_FINDER = new DefaultAlgorithmNameFinder();

    private BcAlgorithmIdentifiers() {
    }

    /* default */ static org.bouncycastle.asn1.x509.AlgorithmIdentifier toBc(AlgorithmIdentifier identifier) {
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(identifier.oid());
        return switch (identifier.parameterForm()) {
            case ABSENT -> new org.bouncycastle.asn1.x509.AlgorithmIdentifier(oid);
            case DER_NULL -> new org.bouncycastle.asn1.x509.AlgorithmIdentifier(oid, DERNull.INSTANCE);
            case EXACT_DER -> {
                try {
                    ASN1Primitive parameters = ASN1Primitive.fromByteArray(identifier.parameters());
                    yield new org.bouncycastle.asn1.x509.AlgorithmIdentifier(oid, parameters);
                } catch (IOException | IllegalArgumentException failure) {
                    throw new IllegalArgumentException("Invalid canonical X.509 parameter DER", failure);
                }
            }
        };
    }

    /* default */ static AlgorithmIdentifier fromBc(org.bouncycastle.asn1.x509.AlgorithmIdentifier identifier) {
        String oid = identifier.getAlgorithm().getId();
        if (identifier.getParameters() == null) {
            return AlgorithmIdentifier.absent(oid);
        }
        if (DERNull.INSTANCE.equals(identifier.getParameters().toASN1Primitive())) {
            return AlgorithmIdentifier.derNull(oid);
        }
        try {
            return AlgorithmIdentifier.exact(oid,
                    identifier.getParameters().toASN1Primitive().getEncoded(ASN1Encoding.DER));
        } catch (IOException failure) {
            throw new IllegalArgumentException("Cannot encode X.509 algorithm parameters", failure);
        }
    }

    /**
     * Returns the JCA signature algorithm name (e.g. {@code SHA256withRSA}) for a
     * signature {@link AlgorithmIdentifier}.
     *
     * @param identifier the signature algorithm identifier
     * @return the JCA algorithm name
     */
    /* default */ static String jcaName(AlgorithmIdentifier identifier) {
        return NAME_FINDER.getAlgorithmName(new ASN1ObjectIdentifier(identifier.oid()));
    }
}
