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

import java.util.Locale;
import java.util.Objects;

import zeroecho.core.spec.AlgorithmIdentity;

/**
 * Non-overridable PKI algorithm security floor.
 *
 * <p>
 * SHA-1 signatures, including RSA-PSS hash or MGF SHA-1, are rejected before
 * provider capability or configured policy is considered.
 * </p>
 */
public final class X509SecurityFloor {

    private static final String FINGERPRINT = "pki-floor-v1:no-sha1-signature-or-component";

    private X509SecurityFloor() {
    }

    /**
     * Returns immutable security-floor semantics for authority provenance.
     *
     * @return stable floor fingerprint
     */
    public static String semanticFingerprint() {
        return FINGERPRINT;
    }

    /**
     * Enforces the immutable security floor.
     *
     * @param identity requested exact identity
     * @throws IllegalArgumentException if the identity contains forbidden SHA-1
     *                                  semantics
     */
    public static void requirePermitted(AlgorithmIdentity identity) {
        Objects.requireNonNull(identity, "identity");
        String canonical = identity.canonicalForm().toLowerCase(Locale.ROOT);
        if (canonical.contains("sha1") || canonical.contains("sha-1")) {
            throw new IllegalArgumentException("SHA-1 is forbidden for PKI signatures");
        }
    }
}
