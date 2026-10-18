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
package zeroecho.pki.api;

/**
 * References the exact issuer generation that produced a credential.
 *
 * @param caId identifier of the CA entity acting as issuer
 * @param issuerId canonical issuer-generation identifier
 * @param chainPathId exact issuance chain path selected for the credential
 */
public record IssuerRef(PkiId caId, PkiId issuerId, PkiId chainPathId) {

    /**
     * Creates a transient unresolved reference used only at framework adapter
     * boundaries. Application services must replace it before persistence.
     *
     * @param caId logical issuer authority
     */
    public IssuerRef(PkiId caId) {
        this(caId, new PkiId("issuer-unresolved:" + caId.value()), new PkiId("path-unresolved:" + caId.value()));
    }

    /**
     * Creates an issuer reference.
     *
     * @throws IllegalArgumentException if either identifier is {@code null}
     */
    public IssuerRef {
        if (caId == null) {
            throw new IllegalArgumentException("caId must not be null");
        }
        if (issuerId == null) {
            throw new IllegalArgumentException("issuerId must not be null");
        }
        if (chainPathId == null) {
            throw new IllegalArgumentException("chainPathId must not be null");
        }
    }
}
