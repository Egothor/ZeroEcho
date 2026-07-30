/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
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
        if (!(binding instanceof EndEntityProfileBinding endEntity)
                || !endEntity.reference().equals(expected)) {
            throw mismatch();
        }
    }

    /* default */ static void requireCaBinding(CredentialProfileBinding binding, CertificateProfileRef expected) {
        if (!(binding instanceof CaProfileBinding ca)
                || !ca.reference().equals(expected)) {
            throw mismatch();
        }
    }

    private static Mismatch mismatch() {
        return new Mismatch();
    }

    /**
     * Internal typed mismatch used to preserve stable caller-specific audit mapping.
     */
    // Construction and use are restricted to trusted profile-binding callers.
    /* default */ static final class Mismatch extends PkiException {
        private static final long serialVersionUID = 1L;

        private Mismatch() {
            super("Credential profile binding rejected: code=" + MISMATCH_CODE);
        }
    }
}
