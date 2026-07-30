/*******************************************************************************
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
