/* *****************************************************************************
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
package zeroecho.pki.testkit;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Explicit strict JSON documents used by H7 issuance tests.
 *
 * <p>
 * These fixtures deliberately contain document syntax and never construct a
 * runtime profile or profile definition before entering the production import
 * boundary.
 * </p>
 */
public final class H7ProfileDocuments {
    private static final String CN = "{\"oid\":\"2.5.4.3\",\"source\":\"REQUESTER\",\"minimumOccurrences\":1,"
            + "\"maximumOccurrences\":1,\"maximumUtf8Bytes\":256}";
    private static final String SUBJECT_EMAIL = "{\"oid\":\"1.2.840.113549.1.9.1\",\"source\":\"REQUESTER\",\"minimumOccurrences\":1,"
            + "\"maximumOccurrences\":1,\"maximumUtf8Bytes\":256}";
    private static final String DNS_ONE = "{\"type\":\"DNS_NAME\",\"minimumOccurrences\":1,\"maximumOccurrences\":1,"
            + "\"wildcardAllowed\":false}";
    private static final String IPV4_ONE = "{\"type\":\"IP_ADDRESS\",\"minimumOccurrences\":1,\"maximumOccurrences\":1,"
            + "\"ipv4Allowed\":true,\"ipv6Allowed\":false}";
    private static final String IPV6_ONE = "{\"type\":\"IP_ADDRESS\",\"minimumOccurrences\":1,\"maximumOccurrences\":1,"
            + "\"ipv4Allowed\":false,\"ipv6Allowed\":true}";
    private static final String IP_BOTH_ONE = "{\"type\":\"IP_ADDRESS\",\"minimumOccurrences\":1,\"maximumOccurrences\":1,"
            + "\"ipv4Allowed\":true,\"ipv6Allowed\":true}";
    private static final String URI_ONE = "{\"type\":\"URI\",\"minimumOccurrences\":1,\"maximumOccurrences\":1,"
            + "\"allowedSchemes\":[\"https\"]}";
    private static final String RFC822_ONE = "{\"type\":\"RFC822_NAME\",\"minimumOccurrences\":1,\"maximumOccurrences\":1}";
    private static final String CONFIRMATION_POLICY = "{\"disclosurePolicy\":\"OWNER_ONLY\","
            + "\"confirmationWindow\":\"PT24H\",\"proofSuiteId\":\"zeroecho.signature-pop.v1\","
            + "\"proofSuiteCommitment\":\"5ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11\","
            + "\"policyCommitment\":\"4933b3d9a9dd31b972d5835884ed8ef9218f8d331928e6ac0feb802d28ab9a30\"}";

    private H7ProfileDocuments() {
    }

    /**
     * Creates the default CN-only profile document.
     *
     * @return default CN-only profile document
     */
    public static byte[] defaultProfile() {
        return profile("default", false, List.of(CN), 0, 0, false, false, false, List.of(), false,
                List.of("1.3.6.1.5.5.7.3.1"));
    }

    /**
     * Creates the imported but intentionally inactive profile document.
     *
     * @return imported but intentionally inactive profile document
     */
    public static byte[] inactiveProfile() {
        return profile("inactive", false, List.of(CN), 0, 0, false, false, false, List.of(), false, serverAuth());
    }

    /**
     * Creates the profile document using a deliberately mismatched format.
     *
     * @return profile document using a deliberately mismatched format
     */
    public static byte[] wrongFormatProfile() {
        return profile("wrong-format", "wrong", false, List.of(CN), 0, 0, false, false, false, List.of(), false,
                serverAuth());
    }

    /**
     * Creates the profile document used to reject an excessive validity request.
     *
     * @return profile document used to reject an excessive validity request
     */
    public static byte[] excessiveValidityProfile() {
        return profile("too-long", false, List.of(CN), 0, 0, false, false, false, List.of(), false, serverAuth());
    }

    /**
     * Creates the one-DNS profile document.
     *
     * @return one-DNS profile document
     */
    public static byte[] dnsProfile() {
        return profile("h7-dns", false, List.of(CN), 1, 1, true, false, false, List.of(DNS_ONE), false, serverAuth());
    }

    /**
     * Creates the multiple-DNS profile document.
     *
     * @return multiple-DNS profile document
     */
    public static byte[] multipleDnsProfile() {
        return profile("h7-dns-multiple", false, List.of(CN), 1, 3, true, false, false,
                List.of("{\"type\":\"DNS_NAME\",\"minimumOccurrences\":1,\"maximumOccurrences\":3,"
                        + "\"wildcardAllowed\":false}"),
                false, serverAuth());
    }

    /**
     * Creates the wildcard-DNS profile document.
     *
     * @return wildcard-DNS profile document
     */
    public static byte[] wildcardDnsProfile() {
        return profile("h7-wildcard", false, List.of(CN), 1, 1, true, false, false,
                List.of("{\"type\":\"DNS_NAME\",\"minimumOccurrences\":1,\"maximumOccurrences\":1,"
                        + "\"wildcardAllowed\":true}"),
                false, serverAuth());
    }

    /**
     * Creates the empty-subject DNS profile document.
     *
     * @return empty-subject DNS profile document
     */
    public static byte[] emptySubjectDnsProfile() {
        return profile("h7-dns-empty", true, List.of(), 1, 1, true, false, false, List.of(DNS_ONE), false,
                serverAuth());
    }

    /**
     * Creates the critical nonempty-subject DNS profile document.
     *
     * @return critical nonempty-subject DNS profile document
     */
    public static byte[] criticalDnsProfile() {
        return profile("h7-dns-critical", false, List.of(CN), 1, 1, true, false, true, List.of(DNS_ONE), false,
                serverAuth());
    }

    /**
     * Creates the one IPv4-or-IPv6 profile document.
     *
     * @return one IPv4-or-IPv6 profile document
     */
    public static byte[] ipProfile() {
        return profile("h7-ip", false, List.of(CN), 1, 1, true, false, false, List.of(IP_BOTH_ONE), false,
                serverAuth());
    }

    /**
     * Creates the exact mixed IPv4/IPv6 profile document.
     *
     * @return exact mixed IPv4/IPv6 profile document
     */
    public static byte[] mixedIpProfile() {
        String rule = "{\"type\":\"IP_ADDRESS\",\"minimumOccurrences\":2,\"maximumOccurrences\":2,"
                + "\"ipv4Allowed\":true,\"ipv6Allowed\":true}";
        return profile("h7-ip-mixed", false, List.of(CN), 2, 2, true, false, false, List.of(rule), false, serverAuth());
    }

    /**
     * Creates the empty-subject IP profile document.
     *
     * @return empty-subject IP profile document
     */
    public static byte[] emptySubjectIpProfile() {
        return profile("h7-ip-empty", true, List.of(), 1, 1, true, false, false, List.of(IP_BOTH_ONE), false,
                serverAuth());
    }

    /**
     * Creates the IPv4-only profile document.
     *
     * @return IPv4-only profile document
     */
    public static byte[] ipv4Profile() {
        return profile("h7-ipv4", false, List.of(CN), 1, 1, true, false, false, List.of(IPV4_ONE), false, serverAuth());
    }

    /**
     * Creates the IPv6-only profile document.
     *
     * @return IPv6-only profile document
     */
    public static byte[] ipv6Profile() {
        return profile("h7-ipv6", false, List.of(CN), 1, 1, true, false, false, List.of(IPV6_ONE), false, serverAuth());
    }

    /**
     * Creates the one-URI profile document.
     *
     * @return one-URI profile document
     */
    public static byte[] uriProfile() {
        return profile("h7-uri", false, List.of(CN), 1, 1, true, false, false, List.of(URI_ONE), false, serverAuth());
    }

    /**
     * Creates the multiple-URI profile document.
     *
     * @return multiple-URI profile document
     */
    public static byte[] multipleUriProfile() {
        String rule = "{\"type\":\"URI\",\"minimumOccurrences\":1,\"maximumOccurrences\":3,"
                + "\"allowedSchemes\":[\"https\"]}";
        return profile("h7-uri-multiple", false, List.of(CN), 1, 3, true, false, false, List.of(rule), false,
                serverAuth());
    }

    /**
     * Creates the empty-subject URI profile document.
     *
     * @return empty-subject URI profile document
     */
    public static byte[] emptySubjectUriProfile() {
        return profile("h7-uri-empty", true, List.of(), 1, 1, true, false, false, List.of(URI_ONE), false,
                serverAuth());
    }

    /**
     * Creates the one-RFC822 profile document.
     *
     * @return one-RFC822 profile document
     */
    public static byte[] rfc822Profile() {
        return profile("h7-rfc822", false, List.of(CN), 1, 1, false, true, false, List.of(RFC822_ONE), false,
                serverAuth());
    }

    /**
     * Creates the multiple-RFC822 profile document.
     *
     * @return multiple-RFC822 profile document
     */
    public static byte[] multipleRfc822Profile() {
        String rule = "{\"type\":\"RFC822_NAME\",\"minimumOccurrences\":1,\"maximumOccurrences\":3}";
        return profile("h7-rfc822-multiple", false, List.of(CN), 1, 3, false, true, false, List.of(rule), false,
                serverAuth());
    }

    /**
     * Creates the empty-subject RFC822 profile document.
     *
     * @return empty-subject RFC822 profile document
     */
    public static byte[] emptySubjectRfc822Profile() {
        return profile("h7-rfc822-empty", true, List.of(), 1, 1, false, true, false, List.of(RFC822_ONE), false,
                serverAuth());
    }

    /**
     * Creates the independent subject-email and RFC822-SAN profile document.
     *
     * @return independent subject-email and RFC822-SAN profile document
     */
    public static byte[] subjectEmailAndRfc822Profile() {
        return profile("h7-subject-email-rfc822", false, List.of(CN, SUBJECT_EMAIL), 1, 1, false, true, false,
                List.of(RFC822_ONE), false, serverAuth());
    }

    /**
     * Creates the mixed supported-SAN profile document.
     *
     * @return mixed supported-SAN profile document
     */
    public static byte[] mixedSanProfile() {
        return profile("h7-mixed", false, List.of(CN), 4, 4, true, true, false,
                List.of(DNS_ONE, IP_BOTH_ONE, RFC822_ONE, URI_ONE), false, serverAuth());
    }

    /**
     * Creates the adversarial-backend baseline profile document.
     *
     * @return adversarial-backend baseline profile document
     */
    public static byte[] backendMutationProfile() {
        String organization = "{\"oid\":\"2.5.4.10\",\"source\":\"REQUESTER\",\"minimumOccurrences\":1,"
                + "\"maximumOccurrences\":1,\"maximumUtf8Bytes\":256}";
        return profile("h7-backend-mutation", false, List.of(CN, organization), 4, 4, true, true, false,
                List.of(DNS_ONE, IP_BOTH_ONE, RFC822_ONE, URI_ONE), false,
                List.of("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"));
    }

    /**
     * Creates the CN-only profile forbidding SAN and EKU.
     *
     * @return CN-only profile forbidding SAN and EKU
     */
    public static byte[] noSanOrEkuProfile() {
        return profile("h7-no-san-eku", false, List.of(CN), 0, 0, false, false, false, List.of(), false, List.of());
    }

    private static List<String> serverAuth() {
        return List.of("1.3.6.1.5.5.7.3.1");
    }

    private static byte[] profile(String id, boolean allowEmpty, List<String> subjectRules, int minimumTotal,
            int maximumTotal, boolean serviceIdentity, boolean emailIdentity, boolean critical, List<String> sanRules,
            boolean noKeyEncipherment, List<String> eku) {
        return profile(id, "x509", allowEmpty, subjectRules, minimumTotal, maximumTotal, serviceIdentity, emailIdentity,
                critical, sanRules, noKeyEncipherment, eku);
    }

    private static byte[] profile(String id, String formatId, boolean allowEmpty, List<String> subjectRules,
            int minimumTotal, int maximumTotal, boolean serviceIdentity, boolean emailIdentity, boolean critical,
            List<String> sanRules, boolean noKeyEncipherment, List<String> eku) {
        String keyUsage = noKeyEncipherment ? "[\"DIGITAL_SIGNATURE\"]"
                : "[\"DIGITAL_SIGNATURE\",\"KEY_ENCIPHERMENT\"]";
        String json = "{\"schemaVersion\":5,\"certificateType\":\"END_ENTITY\",\"profileId\":\"" + id
                + "\",\"profileVersion\":1,\"formatId\":\"" + formatId + "\",\"displayName\":\"H7 Test Profile\","
                + "\"maxValidity\":\"PT8760H\",\"approvalRequirement\":\"NONE\","
                + "\"algorithmBindings\":{\"mode\":\"STANDARD_ONLY\"},"
                + "\"confirmationPolicy\":" + CONFIRMATION_POLICY
                + ",\"subject\":{\"allowEmpty\":" + allowEmpty + ",\"rules\":["
                + String.join(",", subjectRules) + "]}," + "\"subjectAlternativeNames\":{\"minimumTotal\":"
                + minimumTotal + ",\"maximumTotal\":" + maximumTotal + ",\"serviceIdentityRequired\":" + serviceIdentity
                + ",\"emailIdentityRequired\":" + emailIdentity + ",\"criticalWhenSubjectNonEmpty\":" + critical
                + ",\"rules\":[" + String.join(",", sanRules) + "]},"
                + "\"leafCertificate\":{\"basicConstraintsCritical\":true,\"keyUsageCritical\":true," + "\"keyUsage\":"
                + keyUsage + ",\"extendedKeyUsageCritical\":false," + "\"extendedKeyUsage\":[" + quoted(eku)
                + "],\"allowedKeyAlgorithms\":[\"RSA\"]}}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static String quoted(List<String> values) {
        return values.stream().map(value -> "\"" + value + "\"").collect(java.util.stream.Collectors.joining(","));
    }
}
