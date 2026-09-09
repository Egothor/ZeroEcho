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
package zeroecho.pki.api.request;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

import zeroecho.pki.api.profile.SubjectAlternativeNameType;

/**
 * Closed immutable canonical Subject Alternative Name representation.
 */
public sealed interface SubjectAlternativeName permits SubjectAlternativeName.DnsName, SubjectAlternativeName.IpAddress,
        SubjectAlternativeName.UriName, SubjectAlternativeName.Rfc822Name {
    /** IPv4 octet count. */
    int IPV4_OCTET_COUNT = 4;
    /** Maximum IPv4 octet value. */
    int MAXIMUM_IPV4_OCTET = 255;

    /**
     * Returns the exact SAN type.
     *
     * @return SAN type
     */
    SubjectAlternativeNameType type();

    /**
     * Canonical DNS A-label name.
     *
     * @param value lowercase ASCII DNS name, optionally with a complete leftmost
     *              wildcard
     */
    record DnsName(String value) implements SubjectAlternativeName {
        /** Maximum encoded DNS name length. */
        public static final int MAXIMUM_BYTES = 253;

        /**
         * Canonicalizes and validates the DNS name.
         */
        public DnsName {
            value = canonicalDns(value, true);
        }

        @Override
        public SubjectAlternativeNameType type() {
            return SubjectAlternativeNameType.DNS_NAME;
        }
    }

    /**
     * Canonical raw IPv4 or IPv6 address.
     *
     * @param bytes four or sixteen address bytes
     */
    record IpAddress(byte[] bytes) implements SubjectAlternativeName {
        /**
         * Defensively snapshots and validates the address.
         */
        public IpAddress {
            if (bytes == null || bytes.length != 4 && bytes.length != 16) {
                throw new IllegalArgumentException("IP SAN must contain 4 or 16 bytes");
            }
            bytes = bytes.clone();
        }

        /**
         * Returns a defensive copy of the encoded IP address.
         *
         * @return exactly 4 bytes for IPv4 or 16 bytes for IPv6
         */
        @Override
        public byte[] bytes() {
            return bytes.clone();
        }

        @Override
        public SubjectAlternativeNameType type() {
            return SubjectAlternativeNameType.IP_ADDRESS;
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof IpAddress address && Arrays.equals(bytes, address.bytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }

        @Override
        public String toString() {
            return "IpAddress[length=" + bytes.length + "]";
        }
    }

    /**
     * Canonical ASCII hierarchical absolute URI.
     *
     * @param value canonical URI text
     */
    record UriName(String value) implements SubjectAlternativeName {
        /** Maximum encoded URI length. */
        public static final int MAXIMUM_BYTES = 2048;

        /**
         * Canonicalizes and validates the URI.
         */
        public UriName {
            value = canonicalUri(value);
        }

        @Override
        public SubjectAlternativeNameType type() {
            return SubjectAlternativeNameType.URI;
        }
    }

    /**
     * Canonical ASCII RFC 822 mailbox.
     *
     * @param value mailbox with case-preserved local part and lowercase domain
     */
    record Rfc822Name(String value) implements SubjectAlternativeName {
        /** Maximum encoded mailbox length. */
        public static final int MAXIMUM_BYTES = 320;

        /**
         * Canonicalizes and validates the mailbox.
         */
        public Rfc822Name {
            value = canonicalMailbox(value);
        }

        @Override
        public SubjectAlternativeNameType type() {
            return SubjectAlternativeNameType.RFC822_NAME;
        }
    }

    // The branches directly encode the fixed DNS label grammar.
    @SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.NPathComplexity" })
    private static String canonicalDns(String supplied, boolean allowWildcardSyntax) {
        requireAscii(supplied, DnsName.MAXIMUM_BYTES, "DNS SAN");
        if (supplied.endsWith(".")) {
            throw new IllegalArgumentException("DNS SAN must not have a trailing dot");
        }
        String canonical = supplied.toLowerCase(Locale.ROOT);
        if (isIpLiteral(canonical)) {
            throw new IllegalArgumentException("An IP literal is not a DNS SAN");
        }
        String[] labels = canonical.split("\\.", -1);
        boolean wildcard = labels.length > 0 && "*".equals(labels[0]);
        if (wildcard && (!allowWildcardSyntax || labels.length < 3)) {
            throw new IllegalArgumentException("Invalid DNS wildcard");
        }
        for (int index = 0; index < labels.length; index++) {
            String label = labels[index];
            if (index == 0 && wildcard) {
                continue;
            }
            if (label.isEmpty() || label.length() > 63 || label.charAt(0) == '-'
                    || label.charAt(label.length() - 1) == '-') {
                throw new IllegalArgumentException("Invalid DNS label");
            }
            for (int charIndex = 0; charIndex < label.length(); charIndex++) {
                char character = label.charAt(charIndex);
                if (!(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9')
                        && character != '-') {
                    throw new IllegalArgumentException("Invalid DNS label character");
                }
            }
        }
        if (canonical.indexOf('*') >= 0 && !wildcard) {
            throw new IllegalArgumentException("Invalid DNS wildcard");
        }
        return canonical;
    }

    // URI syntax, host canonicalization, and public error redaction form one validation boundary.
    @SuppressWarnings({ "PMD.PreserveStackTrace", "PMD.CyclomaticComplexity" })
    private static String canonicalUri(String supplied) {
        requireAscii(supplied, UriName.MAXIMUM_BYTES, "URI SAN");
        rejectControlCharacters(supplied, "URI SAN");
        try {
            URI uri = new URI(supplied);
            if (!uri.isAbsolute() || uri.isOpaque() || uri.getScheme() == null || uri.getHost() == null
                    || uri.getHost().isEmpty() || uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
                throw new IllegalArgumentException("URI SAN must be an absolute hierarchical host URI");
            }
            String host = canonicalDns(uri.getHost(), false);
            StringBuilder canonical = new StringBuilder(supplied.length());
            canonical.append(uri.getScheme().toLowerCase(Locale.ROOT)).append("://").append(host);
            if (uri.getPort() >= 0) {
                canonical.append(':').append(uri.getPort());
            }
            canonical.append(uri.getRawPath());
            if (uri.getRawQuery() != null) {
                canonical.append('?').append(uri.getRawQuery());
            }
            String result = canonical.toString();
            URI reparsed = new URI(result);
            if (!host.equals(reparsed.getHost()) || reparsed.getPort() != uri.getPort()
                    || !java.util.Objects.equals(reparsed.getRawPath(), uri.getRawPath())
                    || !java.util.Objects.equals(reparsed.getRawQuery(), uri.getRawQuery())) {
                throw new IllegalArgumentException("URI SAN is structurally ambiguous");
            }
            return result;
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException("Malformed URI SAN");
        }
    }

    private static String canonicalMailbox(String supplied) {
        requireAscii(supplied, Rfc822Name.MAXIMUM_BYTES, "RFC822 SAN");
        rejectControlCharacters(supplied, "RFC822 SAN");
        if (supplied.indexOf(' ') >= 0 || supplied.indexOf('\t') >= 0 || supplied.indexOf('<') >= 0
                || supplied.indexOf('>') >= 0 || supplied.indexOf('(') >= 0 || supplied.indexOf(')') >= 0) {
            throw new IllegalArgumentException("RFC822 SAN must contain one bare mailbox");
        }
        int separator = supplied.indexOf('@');
        if (separator <= 0 || separator != supplied.lastIndexOf('@') || separator == supplied.length() - 1) {
            throw new IllegalArgumentException("RFC822 SAN must contain one mailbox");
        }
        String local = supplied.substring(0, separator);
        String domain = canonicalDns(supplied.substring(separator + 1), false);
        return local + '@' + domain;
    }

    private static void requireAscii(String value, int maximumBytes, String field) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(field + " must not be empty");
        }
        byte[] ascii = value.getBytes(StandardCharsets.US_ASCII);
        if (ascii.length > maximumBytes || !new String(ascii, StandardCharsets.US_ASCII).equals(value)) {
            throw new IllegalArgumentException(field + " must be bounded ASCII");
        }
    }

    private static void rejectControlCharacters(String value, String field) {
        for (int index = 0; index < value.length(); index++) {
            if (Character.isISOControl(value.charAt(index))) {
                throw new IllegalArgumentException(field + " must not contain control characters");
            }
        }
    }

    private static boolean isIpLiteral(String value) {
        if (value.indexOf(':') >= 0) {
            return true;
        }
        if (!value.matches("[0-9.]+")) {
            return false;
        }
        String[] octets = value.split("\\.", -1);
        if (octets.length != IPV4_OCTET_COUNT) {
            return false;
        }
        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3) {
                return false;
            }
            int numeric = 0;
            for (int index = 0; index < octet.length(); index++) {
                numeric = numeric * 10 + octet.charAt(index) - '0';
            }
            if (numeric > MAXIMUM_IPV4_OCTET) {
                return false;
            }
        }
        return true;
    }
}
