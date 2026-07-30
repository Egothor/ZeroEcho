/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiException;

final class BuiltInCertificateProfileCatalogTest {

    private static final String ROOT = "zeroecho/pki/profiles/v1/";
    private static final String SERVER = ROOT + "server-tls.json";
    private static final String VPN_SERVER = ROOT + "vpn-server.json";
    private static final String VPN_CLIENT = ROOT + "vpn-client.json";
    private static final String EMAIL = ROOT + "email-signing.json";
    private static final List<String> PROFILE_RESOURCES =
            List.of(SERVER, VPN_SERVER, VPN_CLIENT, EMAIL);
    private static final List<String> EXPECTED_ORDER =
            List.of("server-tls", "vpn-server", "vpn-client", "email-signing");
    private static final Set<String> EXPECTED_ALGORITHMS =
            Set.of("RSA", "ECDSA", "Ed25519");
    private static final ExtendedKeyUsageId SERVER_AUTH =
            new ExtendedKeyUsageId("1.3.6.1.5.5.7.3.1");
    private static final ExtendedKeyUsageId CLIENT_AUTH =
            new ExtendedKeyUsageId("1.3.6.1.5.5.7.3.2");
    private static final ExtendedKeyUsageId EMAIL_PROTECTION =
            new ExtendedKeyUsageId("1.3.6.1.5.5.7.3.4");

    private static boolean sentinelInitialized;

    @Test
    void productionCatalogueLoadsCanonicalImmutableTemplatesInDeterministicOrder()
            throws NoSuchAlgorithmException {
        List<BuiltInCertificateProfileTemplate> first =
                BuiltInCertificateProfileCatalog.load(getClass().getClassLoader());
        List<BuiltInCertificateProfileTemplate> second =
                BuiltInCertificateProfileCatalog.load(getClass().getClassLoader());

        assertEquals(4, first.size());
        assertEquals(EXPECTED_ORDER,
                first.stream().map(template -> template.definition().profileId()).toList());
        assertEquals(first, second);
        assertThrows(UnsupportedOperationException.class, () -> first.add(first.get(0)));
        for (BuiltInCertificateProfileTemplate template : first) {
            CertificateProfileDefinition definition = template.definition();
            byte[] canonical = template.canonicalJson();
            byte[] hash = template.canonicalSha256();
            assertEquals(1, definition.profileVersion());
            assertEquals("x509", definition.formatId().value());
            assertEquals(Duration.ofDays(365), definition.leafPolicy().maximumValidity());
            assertArrayEquals(canonical,
                    CertificateProfileDocumentCodec.writeCanonical(definition));
            assertEquals(definition, CertificateProfileDocumentCodec.parse(canonical));
            assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(canonical), hash);
            assertEquals(32, hash.length);
            assertFalse(template.toString().contains(new String(canonical,
                    StandardCharsets.UTF_8)));

            byte originalJson = canonical[0];
            byte originalHash = hash[0];
            canonical[0] ^= 1;
            hash[0] ^= 1;
            assertNotEquals(canonical[0], template.canonicalJson()[0]);
            assertNotEquals(hash[0], template.canonicalSha256()[0]);
            assertEquals(originalJson, template.canonicalJson()[0]);
            assertEquals(originalHash, template.canonicalSha256()[0]);
        }
    }

    @Test
    void serverAndVpnServerTemplatesHaveExactServiceIdentityPolicy() {
        Map<String, CertificateProfileDefinition> profiles = productionDefinitions();
        for (String profileId : List.of("server-tls", "vpn-server")) {
            LeafCertificatePolicy leaf = profiles.get(profileId).leafPolicy();
            SubjectAlternativeNamePolicy san = leaf.subjectAlternativeNamePolicy();

            assertOptionalCommonName(leaf);
            assertTrue(san.allowEmptySubject());
            assertEquals(1, san.minimumTotal());
            assertEquals(64, san.maximumTotal());
            assertTrue(san.requireServiceIdentity());
            assertFalse(san.requireEmailIdentity());
            assertFalse(san.allowDnsWildcard());
            assertFalse(san.criticalWithNonemptySubject());
            assertEquals(Set.of(SubjectAlternativeNameType.DNS_NAME,
                    SubjectAlternativeNameType.IP_ADDRESS), san.rules().stream()
                            .map(SubjectAlternativeNameRule::type).collect(java.util.stream.Collectors.toSet()));
            SubjectAlternativeNameRule ip = rule(san, SubjectAlternativeNameType.IP_ADDRESS);
            assertTrue(ip.allowIpv4());
            assertTrue(ip.allowIpv6());
            assertLeafPolicy(leaf, Set.of(SERVER_AUTH));
        }
    }

    @Test
    void vpnClientTemplateHasOnlySpiffeUriAndRfc822Identity() {
        LeafCertificatePolicy leaf = productionDefinitions().get("vpn-client").leafPolicy();
        SubjectAlternativeNamePolicy san = leaf.subjectAlternativeNamePolicy();

        assertOptionalCommonName(leaf);
        assertTrue(san.allowEmptySubject());
        assertEquals(1, san.minimumTotal());
        assertEquals(16, san.maximumTotal());
        assertFalse(san.requireServiceIdentity());
        assertFalse(san.requireEmailIdentity());
        assertFalse(san.allowDnsWildcard());
        assertEquals(Set.of("spiffe"), san.allowedUriSchemes());
        assertEquals(Set.of(SubjectAlternativeNameType.URI,
                SubjectAlternativeNameType.RFC822_NAME), san.rules().stream()
                        .map(SubjectAlternativeNameRule::type).collect(java.util.stream.Collectors.toSet()));
        assertLeafPolicy(leaf, Set.of(CLIENT_AUTH));
    }

    @Test
    void emailTemplateRequiresRfc822SanAndDoesNotEnableSubjectEmail() {
        LeafCertificatePolicy leaf = productionDefinitions().get("email-signing").leafPolicy();
        SubjectAlternativeNamePolicy san = leaf.subjectAlternativeNamePolicy();

        assertOptionalCommonName(leaf);
        assertEquals(List.of(SubjectRdnType.COMMON_NAME),
                leaf.subjectPolicy().rules().stream().map(SubjectRdnRule::type).toList());
        assertTrue(san.allowEmptySubject());
        assertEquals(1, san.minimumTotal());
        assertEquals(16, san.maximumTotal());
        assertFalse(san.requireServiceIdentity());
        assertTrue(san.requireEmailIdentity());
        assertEquals(List.of(SubjectAlternativeNameType.RFC822_NAME),
                san.rules().stream().map(SubjectAlternativeNameRule::type).toList());
        assertEquals(1, san.rules().get(0).minimum());
        assertLeafPolicy(leaf, Set.of(EMAIL_PROTECTION));
    }

    @Test
    void manifestRejectsUnknownDuplicateMissingInvalidPathsLimitsAndTrailingTokens() {
        List<String> invalidManifests = List.of(
                "{\"schemaVersion\":1,\"unknown\":true,\"profiles\":[]}",
                "{\"schemaVersion\":1,\"schemaVersion\":1,\"profiles\":[]}",
                "{\"schemaVersion\":1}",
                "{\"schemaVersion\":2,\"profiles\":[{\"resource\":\"" + SERVER + "\"}]}",
                "{\"schemaVersion\":1,\"profiles\":[]}",
                manifest(List.of(SERVER, SERVER)),
                manifest(List.of("/" + SERVER)),
                manifest(List.of(ROOT + "../server-tls.json")),
                manifest(List.of(ROOT + "nested\\\\server-tls.json")),
                manifest(List.of("https:" + SERVER)),
                manifest(List.of("outside/server-tls.json")),
                "{\"schemaVersion\":1,\"profiles\":[{\"resource\":\"" + SERVER
                        + "\",\"extra\":true}]}",
                "{\"schemaVersion\":1,\"profiles\":[{}]}",
                manifest(PROFILE_RESOURCES) + "{}");
        for (String manifest : invalidManifests) {
            Map<String, List<byte[]>> resources = baseResources();
            resources.put(BuiltInCertificateProfileCatalog.MANIFEST_RESOURCE,
                    List.of(bytes(manifest)));
            assertThrows(PkiException.class,
                    () -> BuiltInCertificateProfileCatalog.load(
                            new MemoryResourceClassLoader(resources)));
        }

        List<String> tooMany = new ArrayList<>();
        for (int index = 0; index < 129; index++) {
            tooMany.add(ROOT + "profile-" + index + ".json");
        }
        Map<String, List<byte[]>> resources = baseResources();
        resources.put(BuiltInCertificateProfileCatalog.MANIFEST_RESOURCE,
                List.of(bytes(manifest(tooMany))));
        assertCode(resources, "MANIFEST_LIMIT_EXCEEDED");
    }

    @Test
    void resourcesFailClosedForMissingDuplicateEmptyOversizeAndNoncanonicalContent() {
        Map<String, List<byte[]>> missing = baseResources();
        missing.put(SERVER, List.of());
        assertCode(missing, "RESOURCE_MISSING");

        Map<String, List<byte[]>> duplicate = baseResources();
        duplicate.put(SERVER, List.of(mainResource(SERVER), mainResource(SERVER)));
        assertCode(duplicate, "RESOURCE_DUPLICATE");

        Map<String, List<byte[]>> empty = baseResources();
        empty.put(SERVER, List.of(new byte[0]));
        assertCode(empty, "RESOURCE_EMPTY");

        Map<String, List<byte[]>> oversized = baseResources();
        oversized.put(SERVER, List.of(new byte[
                CertificateProfileDocumentCodec.MAXIMUM_DOCUMENT_BYTES + 1]));
        assertCode(oversized, "RESOURCE_TOO_LARGE");

        Map<String, List<byte[]>> noncanonical = baseResources();
        byte[] canonical = mainResource(SERVER);
        byte[] withNewline = java.util.Arrays.copyOf(canonical, canonical.length + 1);
        withNewline[withNewline.length - 1] = '\n';
        noncanonical.put(SERVER, List.of(withNewline));
        assertCode(noncanonical, "PROFILE_RESOURCE_NONCANONICAL");
    }

    @Test
    void profileDocumentsFailClosedForInvalidSchemaFieldsEncodingAndClassMetadata() {
        List<byte[]> invalidDocuments = List.of(
                replace(mainResource(SERVER), "\"schemaVersion\":1",
                        "\"schemaVersion\":2"),
                replace(mainResource(SERVER), "\"schemaVersion\":1,",
                        "\"schemaVersion\":1,\"active\":true,"),
                replace(mainResource(SERVER), "\"schemaVersion\":1,",
                        "\"schemaVersion\":1,\"@class\":\""
                                + InitializationSentinel.CLASS_NAME + "\","),
                malformedUtf8(mainResource(SERVER)));
        for (byte[] invalid : invalidDocuments) {
            Map<String, List<byte[]>> resources = baseResources();
            resources.put(SERVER, List.of(invalid));
            assertCode(resources, "PROFILE_RESOURCE_INVALID");
        }
        assertFalse(sentinelInitialized);
    }

    @Test
    void duplicateCanonicalHashIdentityAndUnexpectedBuiltInSetFailClosed() {
        Map<String, List<byte[]>> duplicateHash = baseResources();
        duplicateHash.put(VPN_SERVER, List.of(mainResource(SERVER)));
        assertCode(duplicateHash, "DUPLICATE_PROFILE_HASH");

        CertificateProfileDefinition server =
                CertificateProfileDocumentCodec.parse(mainResource(SERVER));
        CertificateProfileDefinition changed = new CertificateProfileDefinition(
                server.profileId(), server.profileVersion(), server.formatId(),
                "Changed display", server.leafPolicy());
        Map<String, List<byte[]>> duplicateIdentity = baseResources();
        duplicateIdentity.put(VPN_SERVER, List.of(
                CertificateProfileDocumentCodec.writeCanonical(changed)));
        assertCode(duplicateIdentity, "DUPLICATE_PROFILE_IDENTITY");

        byte[] unexpected = replace(mainResource(SERVER), "\"server-tls\"",
                "\"unexpected\"");
        Map<String, List<byte[]>> wrongSet = baseResources();
        wrongSet.put(SERVER, List.of(unexpected));
        assertCode(wrongSet, "BUILT_IN_PROFILE_SET_INVALID");
    }

    private static void assertOptionalCommonName(LeafCertificatePolicy leaf) {
        assertEquals(1, leaf.subjectPolicy().rules().size());
        SubjectRdnRule commonName = leaf.subjectPolicy().rules().get(0);
        assertEquals(SubjectRdnType.COMMON_NAME, commonName.type());
        assertEquals(0, commonName.minimumOccurrences());
        assertEquals(1, commonName.maximumOccurrences());
        assertEquals(253, commonName.maximumUtf8Bytes());
        assertTrue(commonName.requesterSupplied());
        assertTrue(commonName.fixedValue().isEmpty());
    }

    private static void assertLeafPolicy(LeafCertificatePolicy leaf,
            Set<ExtendedKeyUsageId> expectedExtendedUsages) {
        assertEquals(Set.of(LeafKeyUsage.DIGITAL_SIGNATURE), leaf.keyUsages());
        assertTrue(leaf.keyUsageCritical());
        assertEquals(expectedExtendedUsages, leaf.extendedKeyUsages());
        assertFalse(leaf.extendedKeyUsageCritical());
        assertTrue(leaf.basicConstraintsCritical());
        assertEquals(EXPECTED_ALGORITHMS, leaf.allowedSubjectKeyAlgorithmIds());
        assertEquals(Duration.ofDays(365), leaf.maximumValidity());
    }

    private static SubjectAlternativeNameRule rule(SubjectAlternativeNamePolicy policy,
            SubjectAlternativeNameType type) {
        return policy.rules().stream().filter(candidate -> candidate.type() == type)
                .findFirst().orElseThrow();
    }

    private static Map<String, CertificateProfileDefinition> productionDefinitions() {
        Map<String, CertificateProfileDefinition> result = new LinkedHashMap<>();
        for (BuiltInCertificateProfileTemplate template :
                BuiltInCertificateProfileCatalog.load(
                        BuiltInCertificateProfileCatalogTest.class.getClassLoader())) {
            result.put(template.definition().profileId(), template.definition());
        }
        return Map.copyOf(result);
    }

    private static Map<String, List<byte[]>> baseResources() {
        Map<String, List<byte[]>> resources = new LinkedHashMap<>();
        resources.put(BuiltInCertificateProfileCatalog.MANIFEST_RESOURCE,
                List.of(mainResource(BuiltInCertificateProfileCatalog.MANIFEST_RESOURCE)));
        for (String resourceName : PROFILE_RESOURCES) {
            resources.put(resourceName, List.of(mainResource(resourceName)));
        }
        return resources;
    }

    private static byte[] mainResource(String resourceName) {
        try (InputStream input = BuiltInCertificateProfileCatalogTest.class.getClassLoader()
                .getResourceAsStream(resourceName)) {
            if (input == null) {
                throw new AssertionError("Missing test resource");
            }
            return input.readAllBytes();
        } catch (IOException ex) {
            throw new AssertionError("Unable to read test resource", ex);
        }
    }

    private static String manifest(List<String> resourceNames) {
        StringBuilder result = new StringBuilder("{\"schemaVersion\":1,\"profiles\":[");
        for (int index = 0; index < resourceNames.size(); index++) {
            if (index > 0) {
                result.append(',');
            }
            result.append("{\"resource\":\"").append(resourceNames.get(index)).append("\"}");
        }
        return result.append("]}").toString();
    }

    private static byte[] replace(byte[] input, String target, String replacement) {
        String value = new String(input, StandardCharsets.UTF_8);
        if (!value.contains(target)) {
            throw new AssertionError("Replacement target absent");
        }
        return bytes(value.replace(target, replacement));
    }

    private static byte[] malformedUtf8(byte[] input) {
        byte[] result = input.clone();
        int index = new String(result, StandardCharsets.UTF_8).indexOf("Server TLS");
        result[index] = (byte) 0xc3;
        result[index + 1] = (byte) 0x28;
        return result;
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static void assertCode(Map<String, List<byte[]>> resources, String code) {
        PkiException exception = assertThrows(PkiException.class,
                () -> BuiltInCertificateProfileCatalog.load(
                        new MemoryResourceClassLoader(resources)));
        assertTrue(exception.getMessage().contains("code=" + code));
        assertNull(exception.getCause());
        assertEquals(0, exception.getSuppressed().length);
    }

    private static final class MemoryResourceClassLoader extends ClassLoader {

        private final Map<String, List<byte[]>> resources;

        private MemoryResourceClassLoader(Map<String, List<byte[]>> resources) {
            super(null);
            Map<String, List<byte[]>> copied = new LinkedHashMap<>();
            resources.forEach((name, values) -> copied.put(name,
                    values.stream().map(byte[]::clone).toList()));
            this.resources = Map.copyOf(copied);
        }

        @Override
        public Enumeration<URL> getResources(String name) throws IOException {
            List<URL> urls = new ArrayList<>();
            List<byte[]> values = resources.getOrDefault(name, List.of());
            for (int index = 0; index < values.size(); index++) {
                urls.add(memoryUrl(name, index, values.get(index)));
            }
            return Collections.enumeration(urls);
        }

        private static URL memoryUrl(String name, int index, byte[] value) throws IOException {
            return URL.of(URI.create("memory:/" + index + "/" + name),
                    new URLStreamHandler() {
                        @Override
                        protected URLConnection openConnection(URL url) {
                            return new URLConnection(url) {
                                @Override
                                public void connect() {
                                    connected = true;
                                }

                                @Override
                                public InputStream getInputStream() {
                                    return new ByteArrayInputStream(value);
                                }
                            };
                        }
                    });
        }
    }

    private static final class InitializationSentinel {
        private static final String CLASS_NAME =
                "zeroecho.pki.api.profile.BuiltInCertificateProfileCatalogTest"
                        + "$InitializationSentinel";

        static {
            sentinelInitialized = true;
        }

        private InitializationSentinel() {
        }
    }
}
