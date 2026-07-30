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
package zeroecho.sdk.hybrid.signature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

import zeroecho.core.context.SignatureContext;
import zeroecho.sdk.ZeroEchoSession;

/**
 * Factory for {@link SignatureContext}-compatible hybrid signature contexts.
 *
 * <p>
 * The returned contexts implement the standard ZeroEcho streaming contract:
 * wrapping a stream produces/verifies a signature trailer at EOF.
 * </p>
 *
 * @since 1.0
 */
public final class HybridSignatureContexts {

    private HybridSignatureContexts() {
    }

    /**
     * Creates a signing hybrid signature context.
     *
     * @param profile          hybrid signature profile
     * @param classicPrivate   private key for the classical signature engine
     * @param pqcPrivate       private key for the PQC signature engine
     * @param maxBufferedBytes maximum number of bytes buffered from the wrapped
     *                         stream (DoS guard)
     * @return signing signature context
     * @throws NullPointerException     if any mandatory argument is {@code null}
     * @throws IllegalArgumentException if {@code maxBufferedBytes <= 0}
     * @since 1.0
     */
    public static SignatureContext sign(ZeroEchoSession session, HybridSignatureProfile profile,
            PrivateKey classicPrivate, PrivateKey pqcPrivate, int maxBufferedBytes) {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(classicPrivate, "classicPrivate");
        Objects.requireNonNull(pqcPrivate, "pqcPrivate");
        return new HybridSignatureContext(session, profile, classicPrivate, pqcPrivate, maxBufferedBytes);
    }

    /**
     * Creates a verification hybrid signature context.
     *
     * @param profile          hybrid signature profile
     * @param classicPublic    public key for the classical signature engine
     * @param pqcPublic        public key for the PQC signature engine
     * @param maxBufferedBytes maximum number of bytes buffered from the wrapped
     *                         stream (DoS guard)
     * @return verifying signature context
     * @throws NullPointerException     if any mandatory argument is {@code null}
     * @throws IllegalArgumentException if {@code maxBufferedBytes <= 0}
     * @since 1.0
     */
    public static SignatureContext verify(ZeroEchoSession session, HybridSignatureProfile profile,
            PublicKey classicPublic, PublicKey pqcPublic, int maxBufferedBytes) {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(classicPublic, "classicPublic");
        Objects.requireNonNull(pqcPublic, "pqcPublic");
        return new HybridSignatureContext(session, profile, classicPublic, pqcPublic, maxBufferedBytes);
    }
}
