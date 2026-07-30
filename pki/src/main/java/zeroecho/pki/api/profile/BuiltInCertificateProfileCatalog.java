/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.exc.StreamConstraintsException;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.json.JsonFactoryBuilder;
import tools.jackson.core.json.JsonReadFeature;
import zeroecho.pki.api.PkiException;

/**
 * Loader for the fixed built-in certificate-profile resource catalogue.
 *
 * <p>
 * The catalogue is stateless and thread-safe. Every load reparses the packaged
 * manifest and profiles, verifies canonical resource bytes, and computes
 * SHA-256 over canonical JSON. Built-in templates are provisioning inputs, not
 * implicit runtime defaults; this loader performs no persistence or activation.
 * </p>
 *
 * <p>
 * Loading takes linear time in the total bounded resource size and retains one
 * immutable canonical copy per returned template.
 * </p>
 */
@SuppressWarnings({ "PMD.AvoidUncheckedExceptionsInSignatures", "PMD.PreserveStackTrace" })
public final class BuiltInCertificateProfileCatalog {

    /** Fixed packaged catalogue manifest resource. */
    public static final String MANIFEST_RESOURCE = "zeroecho/pki/profiles/v1/catalog.json";

    private static final String PROFILE_RESOURCE_ROOT = "zeroecho/pki/profiles/v1/";
    private static final int MAXIMUM_RESOURCE_BYTES = CertificateProfileDocumentCodec.MAXIMUM_DOCUMENT_BYTES;
    private static final int MAXIMUM_MANIFEST_ENTRIES = 128;
    private static final int MAXIMUM_MANIFEST_DEPTH = 16;
    private static final int MAXIMUM_MANIFEST_STRING_BYTES = 4_096;
    private static final int READ_BUFFER_BYTES = 8_192;
    private static final int CATALOGUE_SCHEMA_VERSION = 1;
    private static final int EXPECTED_PROFILE_VERSION = 1;
    private static final String FIELD_SCHEMA_VERSION = "schemaVersion";
    private static final String FIELD_PROFILES = "profiles";
    private static final String FIELD_RESOURCE = "resource";
    private static final String ERROR_PREFIX = "Built-in certificate profile catalogue rejected: code=";
    private static final Set<String> EXPECTED_PROFILE_IDS = Set.of("server-tls", "vpn-server", "vpn-client",
            "email-signing", "root-ca", "intermediate-ca");

    private BuiltInCertificateProfileCatalog() {
    }

    /**
     * Loads and validates the packaged built-in profile templates.
     *
     * @param classLoader explicit resource-loading boundary
     * @return immutable templates in manifest order
     * @throws PkiException if the manifest or any profile resource is missing,
     *                      duplicated, malformed, noncanonical, or inconsistent
     */
    public static List<BuiltInCertificateProfileTemplate> load(ClassLoader classLoader) {
        requireClassLoader(classLoader);
        byte[] manifestBytes = readUniqueResource(classLoader, MANIFEST_RESOURCE);
        List<String> resourceNames = ManifestParser.parse(manifestBytes);
        CatalogueAccumulator accumulator = new CatalogueAccumulator(resourceNames.size());
        for (String resourceName : resourceNames) {
            accumulator.add(loadTemplate(classLoader, resourceName));
        }
        return accumulator.finish();
    }

    private static void requireClassLoader(ClassLoader classLoader) {
        if (classLoader == null) {
            throw failure("RESOURCE_ACCESS_INVALID");
        }
    }

    private static BuiltInCertificateProfileTemplate loadTemplate(ClassLoader classLoader, String resourceName) {
        byte[] resourceBytes = readUniqueResource(classLoader, resourceName);
        CertificateProfileDefinition definition = parseProfile(resourceBytes);
        byte[] canonicalJson = canonicalize(definition);
        requireCanonicalResource(resourceBytes, canonicalJson);
        requireCanonicalRoundTrip(definition, canonicalJson);
        return new BuiltInCertificateProfileTemplate(definition, canonicalJson, sha256(canonicalJson), resourceName);
    }

    private static void requireCanonicalResource(byte[] resourceBytes, byte[] canonicalJson) {
        if (!Arrays.equals(resourceBytes, canonicalJson)) {
            throw failure("PROFILE_RESOURCE_NONCANONICAL");
        }
    }

    private static void requireCanonicalRoundTrip(CertificateProfileDefinition definition, byte[] canonicalJson) {
        if (!definition.equals(parseProfile(canonicalJson))) {
            throw failure("PROFILE_CANONICALIZATION_INVALID");
        }
    }

    private static void validateResourceName(String resourceName) {
        if (resourceName == null || resourceName.isEmpty() || resourceName.startsWith("/")
                || resourceName.contains("..") || resourceName.indexOf('\\') >= 0 || resourceName.indexOf(':') >= 0
                || !resourceName.startsWith(PROFILE_RESOURCE_ROOT)
                || resourceName.length() <= PROFILE_RESOURCE_ROOT.length()) {
            throw failure("MANIFEST_RESOURCE_INVALID");
        }
        for (int index = 0; index < resourceName.length(); index++) {
            if (Character.isISOControl(resourceName.charAt(index))) {
                throw failure("MANIFEST_RESOURCE_INVALID");
            }
        }
    }

    private static byte[] readUniqueResource(ClassLoader classLoader, String resourceName) {
        try {
            Enumeration<URL> matches = classLoader.getResources(resourceName);
            if (!matches.hasMoreElements()) {
                throw failure("RESOURCE_MISSING");
            }
            URL resource = matches.nextElement();
            if (matches.hasMoreElements()) {
                throw failure("RESOURCE_DUPLICATE");
            }
            try (InputStream input = resource.openStream()) {
                return readBounded(input);
            }
        } catch (IOException ex) {
            throw failure("RESOURCE_READ_FAILED");
        }
    }

    private static byte[] readBounded(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(READ_BUFFER_BYTES, MAXIMUM_RESOURCE_BYTES));
        byte[] buffer = new byte[READ_BUFFER_BYTES];
        int total = 0;
        while (true) {
            int remaining = MAXIMUM_RESOURCE_BYTES + 1 - total;
            int count = input.read(buffer, 0, Math.min(buffer.length, remaining));
            if (count < 0) {
                break;
            }
            if (count == 0) {
                int single = input.read();
                if (single < 0) {
                    break;
                }
                output.write(single);
                total++;
            } else {
                output.write(buffer, 0, count);
                total += count;
            }
            if (total > MAXIMUM_RESOURCE_BYTES) {
                throw failure("RESOURCE_TOO_LARGE");
            }
        }
        byte[] result = output.toByteArray();
        if (result.length == 0) {
            throw failure("RESOURCE_EMPTY");
        }
        return result;
    }

    private static CertificateProfileDefinition parseProfile(byte[] resourceBytes) {
        try {
            return CertificateProfileDocumentCodec.parse(resourceBytes);
        } catch (PkiException ex) {
            throw failure("PROFILE_RESOURCE_INVALID");
        }
    }

    private static byte[] canonicalize(CertificateProfileDefinition definition) {
        try {
            return CertificateProfileDocumentCodec.writeCanonical(definition);
        } catch (PkiException ex) {
            throw failure("PROFILE_CANONICALIZATION_INVALID");
        }
    }

    private static byte[] sha256(byte[] canonicalJson) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(canonicalJson);
        } catch (NoSuchAlgorithmException ex) {
            throw failure("PROFILE_HASH_UNAVAILABLE");
        }
    }

    private static PkiException failure(String code) {
        return new PkiException(ERROR_PREFIX + code);
    }

    /** Collects and validates one bounded catalogue load. */
    private static final class CatalogueAccumulator {

        private final List<BuiltInCertificateProfileTemplate> templates;
        private final Set<ProfileIdentity> identities = new HashSet<>();
        private final Set<ByteBuffer> hashes = new HashSet<>();
        private final Set<String> profileIds = new HashSet<>();
        private int endEntityCount;
        private int rootCount;
        private int intermediateCount;

        private CatalogueAccumulator(int expectedSize) {
            templates = new ArrayList<>(expectedSize);
        }

        private void add(BuiltInCertificateProfileTemplate template) {
            CertificateProfileDefinition definition = template.definition();
            if (!hashes.add(ByteBuffer.wrap(template.canonicalSha256()))) {
                throw failure("DUPLICATE_PROFILE_HASH");
            }
            if (!identities.add(new ProfileIdentity(definition.profileId(), definition.profileVersion()))) {
                throw failure("DUPLICATE_PROFILE_IDENTITY");
            }
            if (definition.profileVersion() != EXPECTED_PROFILE_VERSION || !profileIds.add(definition.profileId())) {
                throw failure("BUILT_IN_PROFILE_SET_INVALID");
            }
            switch (definition.certificateType()) {
                case END_ENTITY -> endEntityCount++;
                case ROOT_CA -> rootCount++;
                case INTERMEDIATE_CA -> intermediateCount++;
            }
            templates.add(template);
        }

        private List<BuiltInCertificateProfileTemplate> finish() {
            if (templates.size() != EXPECTED_PROFILE_IDS.size() || !profileIds.equals(EXPECTED_PROFILE_IDS)
                    || endEntityCount != 4 || rootCount != 1 || intermediateCount != 1) {
                throw failure("BUILT_IN_PROFILE_SET_INVALID");
            }
            return List.copyOf(templates);
        }
    }

    /** Strict Jackson Core streaming parser for the fixed catalogue manifest. */
    private static final class ManifestParser {

        private static final JsonFactory JSON_FACTORY = createJsonFactory();

        private static List<String> parse(byte[] encoded) {
            if (encoded.length == 0) {
                throw failure("MANIFEST_EMPTY");
            }
            try (JsonParser parser = JSON_FACTORY.createParser(ObjectReadContext.empty(), encoded, 0, encoded.length)) {
                ManifestDocument document = readDocument(parser);
                requireEndOfInput(parser);
                return validate(document);
            } catch (StreamConstraintsException ex) {
                throw failure("MANIFEST_LIMIT_EXCEEDED");
            } catch (JacksonException ex) {
                throw failure(isDuplicateFailure(ex) ? "MANIFEST_DUPLICATE_FIELD" : "MANIFEST_MALFORMED");
            }
        }

        private static JsonFactory createJsonFactory() {
            StreamReadConstraints constraints = StreamReadConstraints.builder().maxNestingDepth(MAXIMUM_MANIFEST_DEPTH)
                    .maxDocumentLength(MAXIMUM_RESOURCE_BYTES).maxTokenCount(1_024).maxNumberLength(10)
                    .maxStringLength(MAXIMUM_MANIFEST_STRING_BYTES).maxNameLength(32).build();
            JsonFactoryBuilder builder = JsonFactory.builder().streamReadConstraints(constraints)
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).disable(StreamReadFeature.AUTO_CLOSE_SOURCE);
            for (JsonReadFeature feature : JsonReadFeature.values()) {
                builder.disable(feature);
            }
            return builder.build();
        }

        private static ManifestDocument readDocument(JsonParser parser) throws JacksonException {
            requireToken(parser.nextToken(), JsonToken.START_OBJECT);
            boolean schemaSeen = false;
            boolean profilesSeen = false;
            int schemaVersion = 0;
            List<String> profiles = null;
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                requireToken(parser.currentToken(), JsonToken.PROPERTY_NAME);
                String field = parser.currentName();
                requireValue(parser);
                switch (field) {
                    case FIELD_SCHEMA_VERSION -> {
                        rejectDuplicate(schemaSeen);
                        schemaSeen = true;
                        schemaVersion = readSchemaVersion(parser);
                    }
                    case FIELD_PROFILES -> {
                        rejectDuplicate(profilesSeen);
                        profilesSeen = true;
                        profiles = readProfiles(parser);
                    }
                    default -> throw failure("MANIFEST_UNKNOWN_FIELD");
                }
            }
            if (!schemaSeen || !profilesSeen) {
                throw failure("MANIFEST_MISSING_FIELD");
            }
            return new ManifestDocument(schemaVersion, profiles);
        }

        private static List<String> validate(ManifestDocument document) {
            if (document.schemaVersion() != CATALOGUE_SCHEMA_VERSION) {
                throw failure("MANIFEST_VERSION_UNSUPPORTED");
            }
            return document.profiles();
        }

        private static int readSchemaVersion(JsonParser parser) throws JacksonException {
            requireToken(parser.currentToken(), JsonToken.VALUE_NUMBER_INT);
            try {
                return parser.getIntValue();
            } catch (JacksonException ex) {
                throw failure("MANIFEST_VERSION_UNSUPPORTED");
            }
        }

        private static List<String> readProfiles(JsonParser parser) throws JacksonException {
            requireToken(parser.currentToken(), JsonToken.START_ARRAY);
            List<String> resources = new ArrayList<>();
            Set<String> unique = new LinkedHashSet<>();
            while (parser.nextToken() != JsonToken.END_ARRAY) {
                checkEntryLimit(resources.size());
                String resourceName = readEntry(parser);
                validateResourceName(resourceName);
                if (!unique.add(resourceName)) {
                    throw failure("MANIFEST_DUPLICATE_RESOURCE");
                }
                resources.add(resourceName);
            }
            if (resources.isEmpty()) {
                throw failure("MANIFEST_EMPTY");
            }
            return List.copyOf(resources);
        }

        private static void checkEntryLimit(int currentSize) {
            if (currentSize >= MAXIMUM_MANIFEST_ENTRIES) {
                throw failure("MANIFEST_LIMIT_EXCEEDED");
            }
        }

        private static String readEntry(JsonParser parser) throws JacksonException {
            requireToken(parser.currentToken(), JsonToken.START_OBJECT);
            String resourceName = null;
            boolean resourceSeen = false;
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                requireToken(parser.currentToken(), JsonToken.PROPERTY_NAME);
                String field = parser.currentName();
                requireValue(parser);
                if (!FIELD_RESOURCE.equals(field)) {
                    throw failure("MANIFEST_UNKNOWN_FIELD");
                }
                rejectDuplicate(resourceSeen);
                resourceSeen = true;
                requireToken(parser.currentToken(), JsonToken.VALUE_STRING);
                resourceName = parser.getString();
            }
            if (!resourceSeen) {
                throw failure("MANIFEST_MISSING_FIELD");
            }
            return resourceName;
        }

        private static void rejectDuplicate(boolean alreadySeen) {
            if (alreadySeen) {
                throw failure("MANIFEST_DUPLICATE_FIELD");
            }
        }

        private static void requireEndOfInput(JsonParser parser) throws JacksonException {
            if (parser.nextToken() != null) {
                throw failure("MANIFEST_MALFORMED");
            }
        }

        private static void requireToken(JsonToken actual, JsonToken expected) {
            if (actual == null) {
                throw failure("MANIFEST_MALFORMED");
            }
            if (actual != expected) {
                throw failure("MANIFEST_WRONG_TYPE");
            }
        }

        private static void requireValue(JsonParser parser) throws JacksonException {
            JsonToken token = parser.nextToken();
            if (token == null) {
                throw failure("MANIFEST_MALFORMED");
            }
            if (token == JsonToken.VALUE_NULL) {
                throw failure("MANIFEST_WRONG_TYPE");
            }
        }

        private static boolean isDuplicateFailure(JacksonException exception) {
            String message = exception.getMessage();
            return message != null && message.contains("Duplicate");
        }

        private record ManifestDocument(int schemaVersion, List<String> profiles) {
        }
    }

    private record ProfileIdentity(String profileId, long profileVersion) {
    }
}
