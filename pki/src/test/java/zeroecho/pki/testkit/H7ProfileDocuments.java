/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.testkit;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Explicit strict JSON documents used by H7 issuance tests.
 *
 * <p>These fixtures deliberately contain document syntax and never construct a
 * runtime profile or profile definition before entering the production import
 * boundary.</p>
 */
public final class H7ProfileDocuments {
    private static final String CN =
            "{\"oid\":\"2.5.4.3\",\"source\":\"REQUESTER\",\"minimumOccurrences\":1,"
                    + "\"maximumOccurrences\":1,\"maximumUtf8Bytes\":256}";
    private static final String SUBJECT_EMAIL =
            "{\"oid\":\"1.2.840.113549.1.9.1\",\"source\":\"REQUESTER\",\"minimumOccurrences\":1,"
                    + "\"maximumOccurrences\":1,\"maximumUtf8Bytes\":256}";
    private static final String DNS_ONE =
            "{\"type\":\"DNS_NAME\",\"minimumOccurrences\":1,\"maximumOccurrences\":1,"
                    + "\"wildcardAllowed\":false}";
    private static final String IPV4_ONE =
            "{\"type\":\"IP_ADDRESS\",\"minimumOccurrences\":1,\"maximumOccurrences\":1,"
                    + "\"ipv4Allowed\":true,\"ipv6Allowed\":false}";
    private static final String IPV6_ONE =
            "{\"type\":\"IP_ADDRESS\",\"minimumOccurrences\":1,\"maximumOccurrences\":1,"
                    + "\"ipv4Allowed\":false,\"ipv6Allowed\":true}";
    private static final String IP_BOTH_ONE =
            "{\"type\":\"IP_ADDRESS\",\"minimumOccurrences\":1,\"maximumOccurrences\":1,"
                    + "\"ipv4Allowed\":true,\"ipv6Allowed\":true}";
    private static final String URI_ONE =
            "{\"type\":\"URI\",\"minimumOccurrences\":1,\"maximumOccurrences\":1,"
                    + "\"allowedSchemes\":[\"https\"]}";
    private static final String RFC822_ONE =
            "{\"type\":\"RFC822_NAME\",\"minimumOccurrences\":1,\"maximumOccurrences\":1}";

    private H7ProfileDocuments() {
    }

    /** @return default CN-only profile document */
    public static byte[] defaultProfile() {
        return profile("default", false, List.of(CN), 0, 0, false, false, false, List.of(), false,
                List.of("1.3.6.1.5.5.7.3.1"));
    }

    /** @return imported but intentionally inactive profile document */
    public static byte[] inactiveProfile() {
        return profile("inactive", false, List.of(CN), 0, 0, false, false, false, List.of(), false,
                serverAuth());
    }

    /** @return profile document using a deliberately mismatched format */
    public static byte[] wrongFormatProfile() {
        return profile("wrong-format", "wrong", false, List.of(CN), 0, 0, false, false, false, List.of(),
                false, serverAuth());
    }

    /** @return profile document used to reject an excessive validity request */
    public static byte[] excessiveValidityProfile() {
        return profile("too-long", false, List.of(CN), 0, 0, false, false, false, List.of(), false,
                serverAuth());
    }

    /** @return one-DNS profile document */
    public static byte[] dnsProfile() {
        return profile("h7-dns", false, List.of(CN), 1, 1, true, false, false, List.of(DNS_ONE), false,
                serverAuth());
    }

    /** @return multiple-DNS profile document */
    public static byte[] multipleDnsProfile() {
        return profile("h7-dns-multiple", false, List.of(CN), 1, 3, true, false, false,
                List.of("{\"type\":\"DNS_NAME\",\"minimumOccurrences\":1,\"maximumOccurrences\":3,"
                        + "\"wildcardAllowed\":false}"), false, serverAuth());
    }

    /** @return wildcard-DNS profile document */
    public static byte[] wildcardDnsProfile() {
        return profile("h7-wildcard", false, List.of(CN), 1, 1, true, false, false,
                List.of("{\"type\":\"DNS_NAME\",\"minimumOccurrences\":1,\"maximumOccurrences\":1,"
                        + "\"wildcardAllowed\":true}"), false, serverAuth());
    }

    /** @return empty-subject DNS profile document */
    public static byte[] emptySubjectDnsProfile() {
        return profile("h7-dns-empty", true, List.of(), 1, 1, true, false, false, List.of(DNS_ONE), false,
                serverAuth());
    }

    /** @return critical nonempty-subject DNS profile document */
    public static byte[] criticalDnsProfile() {
        return profile("h7-dns-critical", false, List.of(CN), 1, 1, true, false, true, List.of(DNS_ONE), false,
                serverAuth());
    }

    /** @return one IPv4-or-IPv6 profile document */
    public static byte[] ipProfile() {
        return profile("h7-ip", false, List.of(CN), 1, 1, true, false, false, List.of(IP_BOTH_ONE), false,
                serverAuth());
    }

    /** @return exact mixed IPv4/IPv6 profile document */
    public static byte[] mixedIpProfile() {
        String rule = "{\"type\":\"IP_ADDRESS\",\"minimumOccurrences\":2,\"maximumOccurrences\":2,"
                + "\"ipv4Allowed\":true,\"ipv6Allowed\":true}";
        return profile("h7-ip-mixed", false, List.of(CN), 2, 2, true, false, false, List.of(rule), false,
                serverAuth());
    }

    /** @return empty-subject IP profile document */
    public static byte[] emptySubjectIpProfile() {
        return profile("h7-ip-empty", true, List.of(), 1, 1, true, false, false, List.of(IP_BOTH_ONE), false,
                serverAuth());
    }

    /** @return IPv4-only profile document */
    public static byte[] ipv4Profile() {
        return profile("h7-ipv4", false, List.of(CN), 1, 1, true, false, false, List.of(IPV4_ONE), false,
                serverAuth());
    }

    /** @return IPv6-only profile document */
    public static byte[] ipv6Profile() {
        return profile("h7-ipv6", false, List.of(CN), 1, 1, true, false, false, List.of(IPV6_ONE), false,
                serverAuth());
    }

    /** @return one-URI profile document */
    public static byte[] uriProfile() {
        return profile("h7-uri", false, List.of(CN), 1, 1, true, false, false, List.of(URI_ONE), false,
                serverAuth());
    }

    /** @return multiple-URI profile document */
    public static byte[] multipleUriProfile() {
        String rule = "{\"type\":\"URI\",\"minimumOccurrences\":1,\"maximumOccurrences\":3,"
                + "\"allowedSchemes\":[\"https\"]}";
        return profile("h7-uri-multiple", false, List.of(CN), 1, 3, true, false, false, List.of(rule), false,
                serverAuth());
    }

    /** @return empty-subject URI profile document */
    public static byte[] emptySubjectUriProfile() {
        return profile("h7-uri-empty", true, List.of(), 1, 1, true, false, false, List.of(URI_ONE), false,
                serverAuth());
    }

    /** @return one-RFC822 profile document */
    public static byte[] rfc822Profile() {
        return profile("h7-rfc822", false, List.of(CN), 1, 1, false, true, false, List.of(RFC822_ONE), false,
                serverAuth());
    }

    /** @return multiple-RFC822 profile document */
    public static byte[] multipleRfc822Profile() {
        String rule = "{\"type\":\"RFC822_NAME\",\"minimumOccurrences\":1,\"maximumOccurrences\":3}";
        return profile("h7-rfc822-multiple", false, List.of(CN), 1, 3, false, true, false, List.of(rule), false,
                serverAuth());
    }

    /** @return empty-subject RFC822 profile document */
    public static byte[] emptySubjectRfc822Profile() {
        return profile("h7-rfc822-empty", true, List.of(), 1, 1, false, true, false, List.of(RFC822_ONE), false,
                serverAuth());
    }

    /** @return independent subject-email and RFC822-SAN profile document */
    public static byte[] subjectEmailAndRfc822Profile() {
        return profile("h7-subject-email-rfc822", false, List.of(CN, SUBJECT_EMAIL), 1, 1, false, true, false,
                List.of(RFC822_ONE), false, serverAuth());
    }

    /** @return mixed supported-SAN profile document */
    public static byte[] mixedSanProfile() {
        return profile("h7-mixed", false, List.of(CN), 4, 4, true, true, false,
                List.of(DNS_ONE, IP_BOTH_ONE, RFC822_ONE, URI_ONE), false, serverAuth());
    }

    /** @return adversarial-backend baseline profile document */
    public static byte[] backendMutationProfile() {
        String organization = "{\"oid\":\"2.5.4.10\",\"source\":\"REQUESTER\",\"minimumOccurrences\":1,"
                + "\"maximumOccurrences\":1,\"maximumUtf8Bytes\":256}";
        return profile("h7-backend-mutation", false, List.of(CN, organization), 4, 4, true, true, false,
                List.of(DNS_ONE, IP_BOTH_ONE, RFC822_ONE, URI_ONE), false,
                List.of("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"));
    }

    /** @return CN-only profile forbidding SAN and EKU */
    public static byte[] noSanOrEkuProfile() {
        return profile("h7-no-san-eku", false, List.of(CN), 0, 0, false, false, false, List.of(), false,
                List.of());
    }

    private static List<String> serverAuth() {
        return List.of("1.3.6.1.5.5.7.3.1");
    }

    private static byte[] profile(String id, boolean allowEmpty, List<String> subjectRules,
            int minimumTotal, int maximumTotal, boolean serviceIdentity, boolean emailIdentity,
            boolean critical, List<String> sanRules, boolean noKeyEncipherment, List<String> eku) {
        return profile(id, "x509", allowEmpty, subjectRules, minimumTotal, maximumTotal, serviceIdentity,
                emailIdentity, critical, sanRules, noKeyEncipherment, eku);
    }

    private static byte[] profile(String id, String formatId, boolean allowEmpty, List<String> subjectRules,
            int minimumTotal, int maximumTotal, boolean serviceIdentity, boolean emailIdentity,
            boolean critical, List<String> sanRules, boolean noKeyEncipherment, List<String> eku) {
        String keyUsage = noKeyEncipherment
                ? "[\"DIGITAL_SIGNATURE\"]" : "[\"DIGITAL_SIGNATURE\",\"KEY_ENCIPHERMENT\"]";
        String json = "{\"schemaVersion\":2,\"certificateType\":\"END_ENTITY\",\"profileId\":\"" + id
                + "\",\"profileVersion\":1,\"formatId\":\"" + formatId
                + "\",\"displayName\":\"H7 Test Profile\","
                + "\"maxValidity\":\"PT8760H\",\"subject\":{\"allowEmpty\":" + allowEmpty
                + ",\"rules\":[" + String.join(",", subjectRules) + "]},"
                + "\"subjectAlternativeNames\":{\"minimumTotal\":" + minimumTotal
                + ",\"maximumTotal\":" + maximumTotal
                + ",\"serviceIdentityRequired\":" + serviceIdentity
                + ",\"emailIdentityRequired\":" + emailIdentity
                + ",\"criticalWhenSubjectNonEmpty\":" + critical
                + ",\"rules\":[" + String.join(",", sanRules) + "]},"
                + "\"leafCertificate\":{\"basicConstraintsCritical\":true,\"keyUsageCritical\":true,"
                + "\"keyUsage\":" + keyUsage + ",\"extendedKeyUsageCritical\":false,"
                + "\"extendedKeyUsage\":[" + quoted(eku) + "],\"allowedKeyAlgorithms\":[\"RSA\"]}}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static String quoted(List<String> values) {
        return values.stream().map(value -> "\"" + value + "\"")
                .collect(java.util.stream.Collectors.joining(","));
    }
}
