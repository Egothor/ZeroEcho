/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

/**
 * Closed set of requester-supplied Subject Alternative Name types.
 */
public enum SubjectAlternativeNameType {
    /** DNS service name. */
    DNS_NAME,
    /** Raw IPv4 or IPv6 address. */
    IP_ADDRESS,
    /** Hierarchical absolute URI. */
    URI,
    /** RFC 822 mailbox name. */
    RFC822_NAME
}
