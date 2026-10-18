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

/**
 * Immutable process-local authorization to execute one resolved X.509
 * operation.
 *
 * <p>
 * Only a plan minted and subsequently authorized by its owning
 * {@link X509AuthoritySnapshot} is executable. The plan binds the public
 * semantic selection to the exact runtime executor and to a hidden,
 * process-local authority token. It contains no key material and is not
 * serializable.
 * </p>
 *
 * @param <E> exact runtime executor type
 */
public final class X509ExecutionPlan<E> {

    private final X509AlgorithmResolver.Selection selection;
    private final E executor;
    private final Object authorityToken;

    /* default */ X509ExecutionPlan(X509AlgorithmResolver.Selection selection, E executor, Object authorityToken) {
        this.selection = Objects.requireNonNull(selection, "selection");
        this.executor = Objects.requireNonNull(executor, "executor");
        this.authorityToken = Objects.requireNonNull(authorityToken, "authorityToken");
    }

    /**
     * Returns the immutable semantic selection.
     *
     * @return exact identity, suite, binding, direction, implementation, and
     *         provenance
     */
    public X509AlgorithmResolver.Selection selection() {
        return selection;
    }

    /**
     * Returns the exact runtime executor bound by the authority.
     *
     * <p>
     * An execution boundary must call
     * {@link X509AuthoritySnapshot#authorize(X509ExecutionPlan, Object, zeroecho.core.spi.AlgorithmExecutionCapability.Direction)}
     * immediately before invoking this object.
     * </p>
     *
     * @return process-local executor
     */
    public E executor() {
        return executor;
    }

    /*
     * Package-private boolean proof deliberately reveals no token value. A
     * same-package caller may reconstruct the public semantic fields but cannot
     * reproduce the owning snapshot's private provenance object.
     */
    /* default */ boolean isOwnedBy(Object candidateToken) {
        return candidateToken.equals(authorityToken);
    }
}
