/* ******************************************************************************
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
package zeroecho.pki.api.credential;

import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.request.SubjectAlternativeName;

/**
 * Immutable filters for indexed credential inventory search. Subject and serial
 * filters are case-insensitive literal substrings. The legacy fingerprint
 * filter is a case-insensitive credential-ID prefix, not a digest. Status is
 * persisted inventory status, not effective revocation status.
 *
 * @param authorityId       exact issuing authority
 * @param subjectFilter     optional subject substring
 * @param serialFilter      optional serial substring
 * @param fingerprintFilter optional credential-ID prefix
 * @param statusFilter      optional exact inventory status
 * @param profileIdFilter   optional exact logical profile ID
 * @param sanFilter         optional exact canonical typed issued-certificate
 *                          SAN
 */
public record CredentialSearchQuery(PkiId authorityId, Optional<String> subjectFilter, Optional<String> serialFilter,
        Optional<String> fingerprintFilter, Optional<String> statusFilter, Optional<String> profileIdFilter,
        Optional<SubjectAlternativeName> sanFilter) {
    /** Creates a query without interpreting SQL or wildcard characters. */
    public CredentialSearchQuery {
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(subjectFilter, "subjectFilter");
        Objects.requireNonNull(serialFilter, "serialFilter");
        Objects.requireNonNull(fingerprintFilter, "fingerprintFilter");
        Objects.requireNonNull(statusFilter, "statusFilter");
        Objects.requireNonNull(profileIdFilter, "profileIdFilter");
        Objects.requireNonNull(sanFilter, "sanFilter");
    }

    /**
     * Rechecks non-SAN filters against authoritative inventory metadata.
     * 
     * @param credential current authoritative credential
     * @return whether all metadata filters match
     */
    public boolean matchesMetadata(Credential credential) {
        String profile = switch (credential.profileBinding()) {
            case EndEntityProfileBinding binding -> binding.reference().profileId();
            case CaProfileBinding binding -> binding.reference().profileId();
        };
        return authorityId.equals(credential.issuerRef().caId())
                && contains(credential.subjectRef().value(), subjectFilter)
                && contains(credential.serialOrUniqueId(), serialFilter)
                && fingerprintFilter.map(value -> credential.credentialId().value().toLowerCase(Locale.ROOT)
                        .startsWith(value.toLowerCase(Locale.ROOT))).orElse(true)
                && statusFilter.map(value -> value.equals(credential.status().name())).orElse(true)
                && profileIdFilter.map(profile::equals).orElse(true);
    }

    private static boolean contains(String value, Optional<String> filter) {
        return filter.map(part -> value.toLowerCase(Locale.ROOT).contains(part.toLowerCase(Locale.ROOT))).orElse(true);
    }

    /**
     * Parses an exact typed SAN filter using the existing canonical SAN grammar.
     * The prefix is one of DNS_NAME, IP_ADDRESS, URI or RFC822_NAME, followed by a
     * colon and the value. IP literals never trigger name resolution.
     * 
     * @param encoded bounded typed filter
     * @return canonical immutable SAN
     * @throws IllegalArgumentException if the type or value is unsupported or
     *                                  malformed
     */
    public static SubjectAlternativeName parseSanFilter(String encoded) {
        if (encoded == null || encoded.length() > 2060) {
            throw new IllegalArgumentException("Invalid SAN filter");
        }
        int separator = encoded.indexOf(':');
        if (separator < 1 || separator == encoded.length() - 1) {
            throw new IllegalArgumentException("Invalid SAN filter");
        }
        String value = encoded.substring(separator + 1);
        try {
            return switch (encoded.substring(0, separator)) {
                case "DNS_NAME" -> new SubjectAlternativeName.DnsName(value);
                case "IP_ADDRESS" -> ipFilter(value);
                case "URI" -> new SubjectAlternativeName.UriName(value);
                case "RFC822_NAME" -> new SubjectAlternativeName.Rfc822Name(value);
                default -> throw new IllegalArgumentException("Unsupported SAN filter type");
            };
        } catch (IllegalArgumentException malformed) { // NOPMD ExceptionAsFlowControl - Invalid input is rejected here
                                                       // and normalized at the protocol boundary; exceptions do not
                                                       // represent successful control flow.
            throw new IllegalArgumentException("Invalid SAN filter"); // NOPMD PreserveStackTrace,
                                                                      // AvoidThrowingNewInstanceOfSameException - The
                                                                      // public rejection must not retain
                                                                      // caller-controlled SAN text in provider causes.
        }
    }

    private static SubjectAlternativeName.IpAddress ipFilter(String value) {
        if (value.indexOf('%') >= 0 || value.indexOf('[') >= 0 || value.indexOf(']') >= 0) {
            throw new IllegalArgumentException("Invalid IP SAN filter");
        }
        return new SubjectAlternativeName.IpAddress(java.net.InetAddress.ofLiteral(value).getAddress());
    }
}
