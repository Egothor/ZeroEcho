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
package zeroecho.pki.impl.framework.x509;

import java.util.Objects;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;

/**
 * Contextual compatibility validation for current classic X.509 suites.
 *
 * <p>
 * Signature OIDs and SPKI identities are resolved independently and combined
 * only here. An ECDSA signature OID therefore never implies an EC curve.
 * Installed capabilities and policy may further restrict compatible suites.
 * </p>
 */
public final class X509SuiteCompatibility {

    private X509SuiteCompatibility() {
    }

    /**
     * Combines compatible signature and key identities.
     *
     * @param signature exact signature identity
     * @param publicKey exact SPKI identity
     * @return complete suite
     * @throws IllegalArgumentException if family roles are incompatible
     */
    public static AlgorithmSuite requireCompatible(AlgorithmIdentity signature, AlgorithmIdentity publicKey) {
        Objects.requireNonNull(signature, "signature");
        Objects.requireNonNull(publicKey, "publicKey");
        AlgorithmSuite suite = new AlgorithmSuite(signature, publicKey);
        String signatureFamily = signature.family().name();
        String keyFamily = publicKey.family().name();
        boolean compatible = switch (signatureFamily) {
            case "rsa-pkcs1-v1_5", "rsa-pss" -> "rsa".equals(keyFamily);
            case "ecdsa" -> "ec".equals(keyFamily);
            case "ed25519" -> "ed25519".equals(keyFamily);
            case "ed448" -> "ed448".equals(keyFamily);
            case "sphincs-plus" -> "sphincs-plus".equals(keyFamily);
            default -> (signatureFamily.startsWith("ml-dsa-") || signatureFamily.startsWith("slh-dsa-"))
                    && signatureFamily.equals(keyFamily);
        };
        if (!compatible) {
            throw new IllegalArgumentException("Incompatible signature and public-key identities");
        }
        return suite;
    }
}
