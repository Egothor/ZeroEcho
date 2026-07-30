/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.revocation;

/**
 * Effective state recorded by an authoritative revocation journal.
 */
public enum RevocationState {
    /** Credential has no effective revocation restriction. */
    CLEAR,
    /** Credential is temporarily held. */
    HELD,
    /** Credential is permanently revoked. */
    PERMANENTLY_REVOKED
}
