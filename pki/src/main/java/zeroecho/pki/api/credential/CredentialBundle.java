/* ******************************************************************************
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
package zeroecho.pki.api.credential;

import java.util.List;

import zeroecho.pki.api.content.DurableContentReference;

/**
 * Bundle of a primary credential and supporting objects.
 *
 * <p>
 * Supporting objects enable distribution and validation. For X.509 these are
 * typically chain certificates. Frameworks may define additional supporting
 * artifacts.
 * </p>
 *
 * @param credential        primary credential
 * @param supportingObjects supporting artifacts (framework-defined ordering)
 */
public record CredentialBundle(Credential credential, List<DurableContentReference> supportingObjects) {

    /**
     * Creates a bundle.
     *
     * @param credential        primary credential
     * @param supportingObjects supporting artifacts (non-null, may be empty)
     * @throws IllegalArgumentException if inputs are null
     */
    public CredentialBundle {
        if (credential == null) {
            throw new IllegalArgumentException("credential must not be null");
        }
        if (supportingObjects == null) {
            throw new IllegalArgumentException("supportingObjects must not be null");
        }
    }
}
