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
package zeroecho.pkix;

import java.util.Arrays;
import java.util.Objects;

import javax.security.auth.x500.X500Principal;

/**
 * A typed X.509 {@code GeneralName} (RFC 5280, 4.2.1.6), used for subject/issuer
 * alternative names and related extensions.
 *
 * <p>
 * This sealed hierarchy is the deliberately-better-typed replacement for the
 * untyped {@code Collection<List<?>>} exposed by
 * {@link java.security.cert.X509Certificate#getSubjectAlternativeNames()} and for
 * toolkit-specific name classes: each variant carries exactly the data its name
 * type permits.
 * </p>
 */
public sealed interface GeneralName
        permits GeneralName.DnsName, GeneralName.IpAddress, GeneralName.Rfc822Name,
        GeneralName.UniformResourceIdentifier, GeneralName.DirectoryName,
        GeneralName.RegisteredId, GeneralName.OtherName {

    /**
     * {@code dNSName} (tag 2).
     * @param value DNS name text
     */
    record DnsName(String value) implements GeneralName {
        /** Canonicalizing constructor. */
        public DnsName {
            Objects.requireNonNull(value, "value");
        }
    }

    /**
     * {@code iPAddress} (tag 7), as a textual IPv4/IPv6 literal.
     * @param value textual IP address literal
     */
    record IpAddress(String value) implements GeneralName {
        /** Canonicalizing constructor. */
        public IpAddress {
            Objects.requireNonNull(value, "value");
        }
    }

    /**
     * {@code rfc822Name} (tag 1), an e-mail address.
     * @param value mailbox address text
     */
    record Rfc822Name(String value) implements GeneralName {
        /** Canonicalizing constructor. */
        public Rfc822Name {
            Objects.requireNonNull(value, "value");
        }
    }

    /**
     * {@code uniformResourceIdentifier} (tag 6).
     * @param value URI text
     */
    record UniformResourceIdentifier(String value) implements GeneralName {
        /** Canonicalizing constructor. */
        public UniformResourceIdentifier {
            Objects.requireNonNull(value, "value");
        }
    }

    /**
     * {@code directoryName} (tag 4).
     * @param value distinguished-name principal
     */
    record DirectoryName(X500Principal value) implements GeneralName {
        /** Canonicalizing constructor. */
        public DirectoryName {
            Objects.requireNonNull(value, "value");
        }
    }

    /**
     * {@code registeredID} (tag 8).
     * @param oid dotted-decimal registered object identifier
     */
    record RegisteredId(String oid) implements GeneralName {
        /** Canonicalizing constructor. */
        public RegisteredId {
            Objects.requireNonNull(oid, "oid");
        }
    }

    /**
     * {@code otherName} (tag 0): a type-id OID plus the exact DER of the value.
     *
     * @param typeOid the {@code type-id} OID
     * @param derValue exact DER of the {@code value} field
     */
    record OtherName(String typeOid, byte[] derValue) implements GeneralName {
        /** Canonicalizing constructor. */
        public OtherName {
            Objects.requireNonNull(typeOid, "typeOid");
            Objects.requireNonNull(derValue, "derValue");
            derValue = derValue.clone();
        }

        /**
         * Returns the encoded value without exposing the record's internal array.
         *
         * @return a defensive copy of the exact DER value
         */
        @Override
        public byte[] derValue() {
            return derValue.clone();
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof OtherName that && typeOid.equals(that.typeOid)
                    && Arrays.equals(derValue, that.derValue);
        }

        @Override
        public int hashCode() {
            return Objects.hash(typeOid, Arrays.hashCode(derValue));
        }

        @Override
        public String toString() {
            return "OtherName[typeOid=" + typeOid + ']';
        }
    }
}
