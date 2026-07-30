/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Validated exact X.509 extended-key-usage object identifier.
 *
 * @param oid dotted-decimal object identifier
 */
public record ExtendedKeyUsageId(String oid) {

    /**
     * Validates and constructs the identifier.
     */
    public ExtendedKeyUsageId {
        if (oid == null) {
            throw new IllegalArgumentException("Invalid extended key usage identifier");
        }
        oid = new ASN1ObjectIdentifier(oid).getId();
    }
}
