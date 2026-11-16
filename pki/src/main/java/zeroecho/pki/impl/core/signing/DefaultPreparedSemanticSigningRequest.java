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

package zeroecho.pki.impl.core.signing;

import java.util.Objects;

import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;

/**
 * Opaque semantic view over the existing signing preparation's sole custody state.
 */
public final class DefaultPreparedSemanticSigningRequest implements PreparedSemanticSigningRequest {
    private final DefaultPreparedSigningRequest prepared;
    private final DefaultSemanticSigningService owner;

    /**
     * Creates a semantic view sharing the prepared request's sole custody state.
     *
     * @param prepared underlying prepared request; must not be null
     * @param owner semantic service owning this view; must not be null
     * @throws NullPointerException if either argument is null
     */
    /* default */ DefaultPreparedSemanticSigningRequest(DefaultPreparedSigningRequest prepared,
            DefaultSemanticSigningService owner) {
        this.prepared = Objects.requireNonNull(prepared, "prepared");
        this.owner = Objects.requireNonNull(owner, "owner");
    }

    /**
     * Returns the underlying prepared request only to its owning semantic service.
     *
     * @param expectedOwner expected service identity token
     * @return underlying prepared request, without transferring or consuming custody
     * @throws IllegalArgumentException if expectedOwner is not the identical owner
     */
    /* default */ // Identity comparison preserves ownership tokens or prevents Throwable self-suppression; value equality is incorrect here.
                  @SuppressWarnings({ "PMD.CompareObjectsWithEquals" })
                  DefaultPreparedSigningRequest unwrap(DefaultSemanticSigningService expectedOwner) {
        if (owner != expectedOwner) {
            throw new IllegalArgumentException("Prepared request belongs to another semantic signing service");
        }
        return prepared;
    }

    /**
     * {@inheritDoc}
     */
    @Override public SigningAcceptanceReceipt receipt() { return prepared.receipt(); }

    /**
     * Returns a representation that omits prepared operation data.
     * @return {@inheritDoc}
     */
    @Override public String toString() { return "PreparedSemanticSigningRequest[redacted]"; }
}
