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

import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.spi.crypto.SigningProvider;

/**
 * Non-forgeable live completion of one X.509 signed status-object operation.
 *
 * <p>
 * Only the owning {@link X509AuthoritySnapshot} can construct this value. It
 * binds the immutable status metadata to the exact live SIGN plan and opaque
 * runtime provenance. The completion is not persisted and contains no key
 * material or signed-object payload.
 * </p>
 */
public final class X509SignedObjectCompletion implements zeroecho.pki.spi.framework.SignedObjectCompletion {
    private final StatusObject statusObject;
    private final X509ExecutionPlan<SigningProvider> signingPlan;
    private final Object authorityToken;

    /* default */ X509SignedObjectCompletion(StatusObject statusObject,
            X509ExecutionPlan<SigningProvider> signingPlan, Object authorityToken) {
        this.statusObject = Objects.requireNonNull(statusObject, "statusObject");
        this.signingPlan = Objects.requireNonNull(signingPlan, "signingPlan");
        this.authorityToken = Objects.requireNonNull(authorityToken, "authorityToken");
    }

    /**
     * Returns the completed immutable status-object metadata.
     *
     * @return completed status object
     */
    @Override
    public StatusObject statusObject() {
        return statusObject;
    }

    /* default */ X509ExecutionPlan<SigningProvider> signingPlan() {
        return signingPlan;
    }

    /* default */ boolean isOwnedBy(Object candidate) {
        return authorityToken.equals(candidate);
    }
}
