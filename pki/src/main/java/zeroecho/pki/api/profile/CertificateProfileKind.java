/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

/**
 * Closed certificate category governed by a profile definition.
 */
public enum CertificateProfileKind {
    /** End-entity certificate. */
    END_ENTITY,
    /** Self-signed root certification-authority certificate. */
    ROOT_CA,
    /** Issuer-signed intermediate certification-authority certificate. */
    INTERMEDIATE_CA
}
