/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

/**
 * Closed X.509 key-usage set available to CA certificate profiles.
 */
public enum CaKeyUsage {
    /** keyCertSign. */
    KEY_CERT_SIGN,
    /** cRLSign. */
    CRL_SIGN
}
