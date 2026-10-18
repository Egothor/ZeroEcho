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
package zeroecho.pki.impl.core;

import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.CredentialProfileBinding;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.CertificateProfileRef;

/**
 * Exact credential-category binding validation.
 */
final class CredentialProfileBindings {

    // Shared exact binding validation stays inside the trusted PKI core.
    /* default */ static final String MISMATCH_CODE = "CREDENTIAL_PROFILE_BINDING_MISMATCH";

    private CredentialProfileBindings() {
    }

    /* default */ static void requireEndEntityBinding(CredentialProfileBinding binding,
            CertificateProfileRef expected) {
        if (!(binding instanceof EndEntityProfileBinding endEntity) || !endEntity.reference().equals(expected)) {
            throw mismatch();
        }
    }

    /* default */ static void requireCaBinding(CredentialProfileBinding binding, CertificateProfileRef expected) {
        if (!(binding instanceof CaProfileBinding ca) || !ca.reference().equals(expected)) {
            throw mismatch();
        }
    }

    private static Mismatch mismatch() {
        return new Mismatch();
    }

    /**
     * Internal typed mismatch used to preserve stable caller-specific audit
     * mapping.
     */
    // Construction and use are restricted to trusted profile-binding callers.
    /* default */ static final class Mismatch extends PkiException {
        private static final long serialVersionUID = 1L;

        private Mismatch() {
            super("Credential profile binding rejected: code=" + MISMATCH_CODE);
        }
    }
}
