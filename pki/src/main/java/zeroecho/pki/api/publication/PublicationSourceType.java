/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *******************************************************************************/
package zeroecho.pki.api.publication;

/** Identifies the authoritative PKI object supplying publication content. */
public enum PublicationSourceType {
    /** An immutable committed credential. */
    CREDENTIAL,
    /** An immutable committed status object, such as a CRL or OCSP response. */
    STATUS_OBJECT
}
