/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

/**
 * Closed set of X.509 subject distinguished-name attributes supported by
 * end-entity certificate profiles.
 */
// OID literals are ASN.1 identifiers, not IP addresses.
@SuppressWarnings("PMD.AvoidUsingHardCodedIP")
public enum SubjectRdnType {
    /** X.520 common name. */
    COMMON_NAME("2.5.4.3"),
    /** X.520 organization name. */
    ORGANIZATION_NAME("2.5.4.10"),
    /** X.520 organizational unit name. */
    ORGANIZATIONAL_UNIT_NAME("2.5.4.11"),
    /** X.520 country name. */
    COUNTRY_NAME("2.5.4.6"),
    /** X.520 state or province name. */
    STATE_OR_PROVINCE_NAME("2.5.4.8"),
    /** X.520 locality name. */
    LOCALITY_NAME("2.5.4.7"),
    /** X.520 serial number attribute. */
    SERIAL_NUMBER("2.5.4.5"),
    /** PKCS #9 email address. */
    EMAIL_ADDRESS("1.2.840.113549.1.9.1"),
    /** X.520 pseudonym. */
    PSEUDONYM("2.5.4.65");

    private final String oid;

    SubjectRdnType(String oid) {
        this.oid = oid;
    }

    /**
     * Returns the exact ASN.1 object identifier.
     *
     * @return dotted-decimal object identifier
     */
    public String oid() {
        return oid;
    }

    /**
     * Resolves a supported RDN type.
     *
     * @param oid dotted-decimal object identifier
     * @return supported type
     * @throws IllegalArgumentException if the identifier is unsupported
     */
    public static SubjectRdnType fromOid(String oid) {
        for (SubjectRdnType type : values()) {
            if (type.oid.equals(oid)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unsupported subject RDN type");
    }
}
