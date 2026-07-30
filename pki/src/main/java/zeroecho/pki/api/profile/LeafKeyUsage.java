/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

/**
 * Closed X.509 key-usage bit set available to leaf certificate profiles.
 */
public enum LeafKeyUsage {
    /** digitalSignature. */
    DIGITAL_SIGNATURE,
    /** nonRepudiation/contentCommitment. */
    CONTENT_COMMITMENT,
    /** keyEncipherment. */
    KEY_ENCIPHERMENT,
    /** dataEncipherment. */
    DATA_ENCIPHERMENT,
    /** keyAgreement. */
    KEY_AGREEMENT,
    /** encipherOnly. */
    ENCIPHER_ONLY,
    /** decipherOnly. */
    DECIPHER_ONLY
}
