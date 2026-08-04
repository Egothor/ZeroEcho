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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.ObjectWriteContext;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.exc.StreamConstraintsException;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.json.JsonFactoryBuilder;
import tools.jackson.core.json.JsonReadFeature;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiException;

/**
 * Strict JSON parser and canonical writer for version 2 certificate-profile
 * documents.
 *
 * <p>
 * The codec is stateless and thread-safe. It uses only Jackson Core streaming
 * tokens and creates the existing typed policy model directly.
 * </p>
 */
// The closed streaming grammar intentionally keeps all bounded field handlers in one codec.
@SuppressWarnings({ "PMD.AvoidDuplicateLiterals", "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.AvoidUncheckedExceptionsInSignatures", "PMD.CyclomaticComplexity", "PMD.PreserveStackTrace",
        "PMD.TooManyMethods" })
public final class CertificateProfileDocumentCodec {

    /** Maximum accepted encoded document size. */
    public static final int MAXIMUM_DOCUMENT_BYTES = 262_144;

    private static final int MAXIMUM_DEPTH = 16;
    private static final int MAXIMUM_ARRAY_ELEMENTS = 128;
    private static final int MAXIMUM_STRING_UTF8_BYTES = 4_096;
    private static final int MAXIMUM_PROFILE_ID_UTF8_BYTES = 128;
    private static final int MAXIMUM_DISPLAY_NAME_UTF8_BYTES = 256;
    private static final int MAXIMUM_FORMAT_ID_UTF8_BYTES = 128;
    private static final int MAXIMUM_URI_SCHEME_ASCII_BYTES = 32;
    private static final int READ_BUFFER_BYTES = 8_192;
    private static final int MAXIMUM_ASCII_VALUE = 127;

    private static final String PREFIX = "Certificate profile document rejected: code=";
    private static final String REQUESTER_SOURCE = "REQUESTER";
    private static final String PROFILE_FIXED_SOURCE = "PROFILE_FIXED";
    private static final JsonFactory JSON_FACTORY = createJsonFactory();

    private CertificateProfileDocumentCodec() {
    }

    /**
     * Parses an encoded certificate-profile document.
     *
     * @param encodedDocument exact UTF-8 JSON bytes
     * @return immutable profile definition
     * @throws PkiException if the document is malformed, exceeds a bound, or
     *                      violates the profile schema or policy invariants
     */
    public static CertificateProfileDefinition parse(byte[] encodedDocument) {
        if (encodedDocument == null) {
            throw failure("WRONG_TYPE", "$");
        }
        if (encodedDocument.length > MAXIMUM_DOCUMENT_BYTES) {
            throw failure("PROFILE_DOCUMENT_TOO_LARGE", "$");
        }
        if (encodedDocument.length == 0 || hasUtf8Bom(encodedDocument)) {
            throw failure("MALFORMED_JSON", "$");
        }
        preflight(encodedDocument);
        try (JsonParser parser = JSON_FACTORY.createParser(ObjectReadContext.empty(), encodedDocument, 0,
                encodedDocument.length)) {
            CertificateProfileDefinition definition = parseDocument(parser);
            if (parser.nextToken() != null) {
                throw failure("MALFORMED_JSON", "$");
            }
            return definition;
        } catch (StreamConstraintsException ex) {
            throw failure("LIMIT_EXCEEDED", "$");
        } catch (JacksonException ex) {
            throw failure(isDuplicateFailure(ex) ? "DUPLICATE_FIELD" : "MALFORMED_JSON", "$");
        }
    }

    /**
     * Reads and parses an encoded certificate-profile document.
     *
     * <p>
     * This method does not close {@code input}; ownership remains with the caller.
     * It reads at most one byte beyond the document limit in order to detect
     * oversize input without unbounded buffering.
     * </p>
     *
     * @param input caller-owned stream containing UTF-8 JSON
     * @return immutable profile definition
     * @throws PkiException if reading fails or the document is rejected
     */
    public static CertificateProfileDefinition parse(InputStream input) {
        if (input == null) {
            throw failure("WRONG_TYPE", "$");
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(READ_BUFFER_BYTES, MAXIMUM_DOCUMENT_BYTES));
        byte[] buffer = new byte[READ_BUFFER_BYTES];
        int total = 0;
        try {
            while (true) {
                int remaining = MAXIMUM_DOCUMENT_BYTES + 1 - total;
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
                if (total > MAXIMUM_DOCUMENT_BYTES) {
                    throw failure("PROFILE_DOCUMENT_TOO_LARGE", "$");
                }
            }
        } catch (IOException ex) {
            throw failure("PROFILE_DOCUMENT_READ_FAILED", "$");
        }
        return parse(output.toByteArray());
    }

    /**
     * Writes the canonical UTF-8 JSON representation.
     *
     * @param definition definition to encode
     * @return newly allocated canonical JSON bytes without a BOM or trailing
     *         whitespace
     * @throws PkiException if the definition cannot be represented by schema
     *                      version 2
     */
    public static byte[] writeCanonical(CertificateProfileDefinition definition) {
        validateDefinition(definition);
        ByteArrayOutputStream output = new ByteArrayOutputStream(2_048);
        try (JsonGenerator generator = JSON_FACTORY.createGenerator(ObjectWriteContext.empty(), output)) {
            writeDocument(generator, definition);
        } catch (JacksonException ex) {
            throw failure("CANONICALIZATION_FAILED", "$");
        }
        byte[] result = output.toByteArray();
        if (result.length > MAXIMUM_DOCUMENT_BYTES) {
            throw failure("CANONICALIZATION_FAILED", "$");
        }
        return result;
    }

    private static JsonFactory createJsonFactory() {
        StreamReadConstraints constraints = StreamReadConstraints.builder().maxNestingDepth(MAXIMUM_DEPTH)
                .maxDocumentLength(MAXIMUM_DOCUMENT_BYTES).maxTokenCount(8_192).maxNumberLength(20)
                .maxStringLength(MAXIMUM_STRING_UTF8_BYTES).maxNameLength(64).build();
        JsonFactoryBuilder builder = JsonFactory.builder().streamReadConstraints(constraints)
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).disable(StreamReadFeature.AUTO_CLOSE_SOURCE);
        for (JsonReadFeature feature : JsonReadFeature.values()) {
            builder.disable(feature);
        }
        return builder.build();
    }

    private static void preflight(byte[] encodedDocument) {
        try (JsonParser parser = JSON_FACTORY.createParser(ObjectReadContext.empty(), encodedDocument, 0,
                encodedDocument.length)) {
            while (parser.nextToken() != null) {
                parser.finishToken();
            }
        } catch (StreamConstraintsException ex) {
            throw failure("LIMIT_EXCEEDED", "$");
        } catch (JacksonException ex) {
            throw failure(isDuplicateFailure(ex) ? "DUPLICATE_FIELD" : "MALFORMED_JSON", "$");
        }
    }

    private static CertificateProfileDefinition parseDocument(JsonParser parser) throws JacksonException {
        requireToken(parser.nextToken(), JsonToken.START_OBJECT, "$");
        DocumentFields document = new DocumentFields();
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            requireToken(parser.currentToken(), JsonToken.PROPERTY_NAME, "$");
            String field = parser.currentName();
            requireValue(parser, "$." + field);
            readDocumentField(parser, field, document);
        }
        requireAll(document.seen, 9, "$");
        if (document.schemaVersion != CertificateProfileDefinition.SCHEMA_VERSION) {
            throw failure("SCHEMA_VERSION_UNSUPPORTED", "$.schemaVersion");
        }
        if (document.profileVersion <= 0) {
            throw failure("PROFILE_VERSION_INVALID", "$.profileVersion");
        }
        validateProfileString(document.profileId, MAXIMUM_PROFILE_ID_UTF8_BYTES, "$.profileId", "TOKEN_INVALID");
        validateProfileString(document.formatId, MAXIMUM_FORMAT_ID_UTF8_BYTES, "$.formatId", "TOKEN_INVALID");
        validateProfileString(document.displayName, MAXIMUM_DISPLAY_NAME_UTF8_BYTES, "$.displayName", "TOKEN_INVALID");
        requirePolicyFields(document.certificateType, document.seen);
        return constructDefinition(document);
    }

    private static void readDocumentField(JsonParser parser, String field, DocumentFields document)
            throws JacksonException {
        switch (field) {
            case "schemaVersion" -> {
                document.seen = mark(document.seen, 0, "$.schemaVersion");
                document.schemaVersion = readInt(parser, "$.schemaVersion");
            }
            case "certificateType" -> {
                document.seen = mark(document.seen, 1, "$.certificateType");
                document.certificateType = readCertificateType(parser, "$.certificateType");
            }
            case "profileId" -> {
                document.seen = mark(document.seen, 2, "$.profileId");
                document.profileId = readBoundedString(parser, "$.profileId", MAXIMUM_PROFILE_ID_UTF8_BYTES);
            }
            case "profileVersion" -> {
                document.seen = mark(document.seen, 3, "$.profileVersion");
                document.profileVersion = readLong(parser, "$.profileVersion");
            }
            case "formatId" -> {
                document.seen = mark(document.seen, 4, "$.formatId");
                document.formatId = readBoundedString(parser, "$.formatId", MAXIMUM_FORMAT_ID_UTF8_BYTES);
            }
            case "displayName" -> {
                document.seen = mark(document.seen, 5, "$.displayName");
                document.displayName = readBoundedString(parser, "$.displayName", MAXIMUM_DISPLAY_NAME_UTF8_BYTES);
            }
            case "maxValidity" -> {
                document.seen = mark(document.seen, 6, "$.maxValidity");
                document.maximumValidity = readDuration(parser, "$.maxValidity");
            }
            case "subject" -> {
                document.seen = mark(document.seen, 7, "$.subject");
                document.subject = readSubject(parser, "$.subject");
            }
            case "algorithmBindings" -> {
                document.seen = mark(document.seen, 8, "$.algorithmBindings");
                document.algorithmBindings = readAlgorithmBindings(parser, "$.algorithmBindings");
            }
            case "subjectAlternativeNames" -> readDocumentSan(parser, document);
            case "leafCertificate" -> readDocumentLeaf(parser, document);
            case "caCertificate" -> readDocumentCa(parser, document);
            default -> throw failure("UNKNOWN_FIELD", "$.?");
        }
    }

    private static void readDocumentSan(JsonParser parser, DocumentFields document) throws JacksonException {
        if (document.certificateType != null && document.certificateType != CertificateProfileKind.END_ENTITY) {
            throw failure("FIELD_FORBIDDEN_FOR_CERTIFICATE_TYPE", "$.subjectAlternativeNames");
        }
        document.seen = mark(document.seen, 9, "$.subjectAlternativeNames");
        document.san = readSan(parser, "$.subjectAlternativeNames");
    }

    private static void readDocumentLeaf(JsonParser parser, DocumentFields document) throws JacksonException {
        if (document.certificateType != null && document.certificateType != CertificateProfileKind.END_ENTITY) {
            throw failure("FIELD_FORBIDDEN_FOR_CERTIFICATE_TYPE", "$.leafCertificate");
        }
        document.seen = mark(document.seen, 10, "$.leafCertificate");
        document.leaf = readLeaf(parser, "$.leafCertificate");
    }

    private static void readDocumentCa(JsonParser parser, DocumentFields document) throws JacksonException {
        if (document.certificateType == CertificateProfileKind.END_ENTITY) {
            throw failure("FIELD_FORBIDDEN_FOR_CERTIFICATE_TYPE", "$.caCertificate");
        }
        document.seen = mark(document.seen, 11, "$.caCertificate");
        document.ca = readCa(parser, "$.caCertificate");
    }

    private static void requirePolicyFields(CertificateProfileKind certificateType, long seen) {
        boolean hasSan = isSeen(seen, 9);
        boolean hasLeaf = isSeen(seen, 10);
        boolean hasCa = isSeen(seen, 11);
        if (certificateType == CertificateProfileKind.END_ENTITY) {
            if (hasCa) {
                throw failure("FIELD_FORBIDDEN_FOR_CERTIFICATE_TYPE", "$.caCertificate");
            }
            if (!hasSan || !hasLeaf) {
                throw failure("MISSING_FIELD", "$");
            }
        } else {
            if (hasSan || hasLeaf) {
                throw failure("FIELD_FORBIDDEN_FOR_CERTIFICATE_TYPE", "$");
            }
            if (!hasCa) {
                throw failure("MISSING_FIELD", "$.caCertificate");
            }
        }
    }

    /*
     * Typed policy constructors are the authoritative semantic validators, so their
     * validation exceptions are deliberately normalized at this boundary.
     */
    @SuppressWarnings("PMD.ExceptionAsFlowControl")
    private static CertificateProfileDefinition constructDefinition(DocumentFields document) {
        try {
            SubjectPolicy subjectPolicy = new SubjectPolicy(document.subject.allowEmpty(), document.subject.rules());
            CertificatePolicy policy;
            if (document.certificateType == CertificateProfileKind.END_ENTITY) {
                SubjectAlternativeNamePolicy sanPolicy = new SubjectAlternativeNamePolicy(document.san.minimumTotal(),
                        document.san.maximumTotal(), document.san.rules(), document.san.wildcardAllowed(),
                        document.san.allowedSchemes(), document.san.criticalWhenSubjectNonEmpty(),
                        document.san.serviceIdentityRequired(), document.san.emailIdentityRequired());
                if (document.subject.allowEmpty() && document.san.minimumTotal() < 1) {
                    throw new IllegalArgumentException("An empty subject requires at least one SAN");
                }
                policy = new LeafCertificatePolicy(sanPolicy, document.leaf.keyUsage(),
                        document.leaf.extendedKeyUsage(), document.leaf.keyUsageCritical(),
                        document.leaf.extendedKeyUsageCritical(), document.leaf.basicConstraintsCritical(),
                        document.leaf.allowedKeyAlgorithms());
            } else {
                policy = new CaCertificatePolicy(document.ca.basicConstraintsCritical(),
                        document.ca.pathLengthConstraint(), document.ca.keyUsageCritical(), document.ca.keyUsages(),
                        document.ca.allowedKeyAlgorithms());
            }
            return new CertificateProfileDefinition(document.certificateType, document.profileId,
                    document.profileVersion, new FormatId(document.formatId), document.displayName,
                    document.maximumValidity, subjectPolicy, policy, document.algorithmBindings);
        } catch (IllegalArgumentException | ArithmeticException ex) {
            throw failure("SEMANTIC_INVALID", "$");
        }
    }

    private static SubjectSection readSubject(JsonParser parser, String path) throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_OBJECT, path);
        long seen = 0;
        boolean allowEmpty = false;
        List<SubjectRdnRule> rules = null;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            requireToken(parser.currentToken(), JsonToken.PROPERTY_NAME, path);
            String field = parser.currentName();
            requireValue(parser, path + "." + field);
            switch (field) {
                case "allowEmpty" -> {
                    seen = mark(seen, 0, path + ".allowEmpty");
                    allowEmpty = readBoolean(parser, path + ".allowEmpty");
                }
                case "rules" -> {
                    seen = mark(seen, 1, path + ".rules");
                    rules = readSubjectRules(parser, path + ".rules");
                }
                default -> throw failure("UNKNOWN_FIELD", path + ".?");
            }
        }
        requireAll(seen, 2, path);
        return new SubjectSection(allowEmpty, rules);
    }

    private static X509AlgorithmBindingPolicy readAlgorithmBindings(JsonParser parser, String path)
            throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_OBJECT, path);
        long seen = 0;
        X509AlgorithmBindingPolicy.Mode mode = null;
        Optional<X509AlgorithmBindingPolicy.BindingReference> subject = Optional.empty();
        Optional<X509AlgorithmBindingPolicy.BindingReference> csr = Optional.empty();
        Optional<X509AlgorithmBindingPolicy.BindingReference> certificate = Optional.empty();
        Optional<X509AlgorithmBindingPolicy.BindingReference> crl = Optional.empty();
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            requireToken(parser.currentToken(), JsonToken.PROPERTY_NAME, path);
            String field = parser.currentName();
            requireValue(parser, path + "." + field);
            switch (field) {
                case "mode" -> {
                    seen = mark(seen, 0, path + ".mode");
                    mode = readEnum(parser, X509AlgorithmBindingPolicy.Mode.class, path + ".mode");
                }
                case "subjectPublicKey" -> {
                    seen = mark(seen, 1, path + ".subjectPublicKey");
                    subject = Optional.of(readBindingReference(parser, path + ".subjectPublicKey"));
                }
                case "csrSignature" -> {
                    seen = mark(seen, 2, path + ".csrSignature");
                    csr = Optional.of(readBindingReference(parser, path + ".csrSignature"));
                }
                case "certificateSignature" -> {
                    seen = mark(seen, 3, path + ".certificateSignature");
                    certificate = Optional.of(readBindingReference(parser, path + ".certificateSignature"));
                }
                case "crlSignature" -> {
                    seen = mark(seen, 4, path + ".crlSignature");
                    crl = Optional.of(readBindingReference(parser, path + ".crlSignature"));
                }
                default -> throw failure("UNKNOWN_FIELD", path + ".?");
            }
        }
        if (!isSeen(seen, 0)) {
            throw failure("MISSING_FIELD", path + ".mode");
        }
        try {
            return new X509AlgorithmBindingPolicy(mode, subject, csr, certificate, crl);
        } catch (IllegalArgumentException exception) {
            throw failure("SEMANTIC_INVALID", path);
        }
    }

    private static X509AlgorithmBindingPolicy.BindingReference readBindingReference(JsonParser parser, String path)
            throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_OBJECT, path);
        long seen = 0;
        String bindingId = null;
        String commitment = null;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            requireToken(parser.currentToken(), JsonToken.PROPERTY_NAME, path);
            String field = parser.currentName();
            requireValue(parser, path + "." + field);
            switch (field) {
                case "bindingId" -> {
                    seen = mark(seen, 0, path + ".bindingId");
                    bindingId = readBoundedString(parser, path + ".bindingId", 512);
                }
                case "semanticCommitment" -> {
                    seen = mark(seen, 1, path + ".semanticCommitment");
                    commitment = readBoundedString(parser, path + ".semanticCommitment", 1024);
                }
                default -> throw failure("UNKNOWN_FIELD", path + ".?");
            }
        }
        requireAll(seen, 2, path);
        return new X509AlgorithmBindingPolicy.BindingReference(bindingId, commitment);
    }

    private static <E extends Enum<E>> E readEnum(JsonParser parser, Class<E> type, String path)
            throws JacksonException {
        String value = readString(parser, path);
        try {
            return Enum.valueOf(type, value);
        } catch (IllegalArgumentException exception) {
            throw failure("TOKEN_INVALID", path);
        }
    }

    private static List<SubjectRdnRule> readSubjectRules(JsonParser parser, String path) throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_ARRAY, path);
        List<SubjectRdnRule> rules = new ArrayList<>();
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            checkArrayBound(rules.size(), path);
            rules.add(readSubjectRule(parser, path + "[" + rules.size() + "]"));
        }
        return List.copyOf(rules);
    }

    private static SubjectRdnRule readSubjectRule(JsonParser parser, String path) throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_OBJECT, path);
        long seen = 0;
        String oid = null;
        String source = null;
        int minimum = 0;
        int maximum = 0;
        int maximumUtf8 = 0;
        String fixedValue = null;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            requireToken(parser.currentToken(), JsonToken.PROPERTY_NAME, path);
            String field = parser.currentName();
            requireValue(parser, path + "." + field);
            switch (field) {
                case "oid" -> {
                    seen = mark(seen, 0, path + ".oid");
                    oid = readString(parser, path + ".oid");
                }
                case "source" -> {
                    seen = mark(seen, 1, path + ".source");
                    source = readString(parser, path + ".source");
                }
                case "minimumOccurrences" -> {
                    seen = mark(seen, 2, path + ".minimumOccurrences");
                    minimum = readInt(parser, path + ".minimumOccurrences");
                }
                case "maximumOccurrences" -> {
                    seen = mark(seen, 3, path + ".maximumOccurrences");
                    maximum = readInt(parser, path + ".maximumOccurrences");
                }
                case "maximumUtf8Bytes" -> {
                    seen = mark(seen, 4, path + ".maximumUtf8Bytes");
                    maximumUtf8 = readInt(parser, path + ".maximumUtf8Bytes");
                }
                case "fixedValue" -> {
                    seen = mark(seen, 5, path + ".fixedValue");
                    fixedValue = readString(parser, path + ".fixedValue");
                }
                default -> throw failure("UNKNOWN_FIELD", path + ".?");
            }
        }
        requireAll(seen, 5, path);
        SubjectRdnType type = parseRdnType(oid, path + ".oid");
        boolean fixed = parseSubjectSource(source, path + ".source");
        if (fixed != isSeen(seen, 5)) {
            throw failure(fixed ? "MISSING_FIELD" : "UNKNOWN_FIELD", path + ".fixedValue");
        }
        try {
            SubjectRdnRule rule = new SubjectRdnRule(type, minimum, maximum, maximumUtf8,
                    fixed ? Optional.of(fixedValue) : Optional.empty(), !fixed);
            if (fixed && !fixedValue.equals(rule.fixedValue().orElseThrow())) {
                throw failure("TOKEN_INVALID", path + ".fixedValue");
            }
            return rule;
        } catch (IllegalArgumentException ex) {
            throw failure("SEMANTIC_INVALID", path);
        }
    }

    private static SanSection readSan(JsonParser parser, String path) throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_OBJECT, path);
        long seen = 0;
        int minimum = 0;
        int maximum = 0;
        boolean serviceRequired = false;
        boolean emailRequired = false;
        boolean critical = false;
        SanRules rules = null;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            requireToken(parser.currentToken(), JsonToken.PROPERTY_NAME, path);
            String field = parser.currentName();
            requireValue(parser, path + "." + field);
            switch (field) {
                case "minimumTotal" -> {
                    seen = mark(seen, 0, path + ".minimumTotal");
                    minimum = readInt(parser, path + ".minimumTotal");
                }
                case "maximumTotal" -> {
                    seen = mark(seen, 1, path + ".maximumTotal");
                    maximum = readInt(parser, path + ".maximumTotal");
                }
                case "serviceIdentityRequired" -> {
                    seen = mark(seen, 2, path + ".serviceIdentityRequired");
                    serviceRequired = readBoolean(parser, path + ".serviceIdentityRequired");
                }
                case "emailIdentityRequired" -> {
                    seen = mark(seen, 3, path + ".emailIdentityRequired");
                    emailRequired = readBoolean(parser, path + ".emailIdentityRequired");
                }
                case "criticalWhenSubjectNonEmpty" -> {
                    seen = mark(seen, 4, path + ".criticalWhenSubjectNonEmpty");
                    critical = readBoolean(parser, path + ".criticalWhenSubjectNonEmpty");
                }
                case "rules" -> {
                    seen = mark(seen, 5, path + ".rules");
                    rules = readSanRules(parser, path + ".rules");
                }
                default -> throw failure("UNKNOWN_FIELD", path + ".?");
            }
        }
        requireAll(seen, 6, path);
        return new SanSection(minimum, maximum, serviceRequired, emailRequired, critical, rules.rules(),
                rules.wildcardAllowed(), rules.allowedSchemes());
    }

    private static SanRules readSanRules(JsonParser parser, String path) throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_ARRAY, path);
        List<SubjectAlternativeNameRule> rules = new ArrayList<>();
        boolean wildcardAllowed = false;
        Set<String> schemes = Set.of();
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            checkArrayBound(rules.size(), path);
            ParsedSanRule rule = readSanRule(parser, path + "[" + rules.size() + "]");
            rules.add(rule.rule());
            if (rule.rule().type() == SubjectAlternativeNameType.DNS_NAME) {
                wildcardAllowed = rule.wildcardAllowed();
            } else if (rule.rule().type() == SubjectAlternativeNameType.URI) {
                schemes = rule.allowedSchemes();
            }
        }
        return new SanRules(List.copyOf(rules), wildcardAllowed, schemes);
    }

    private static ParsedSanRule readSanRule(JsonParser parser, String path) throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_OBJECT, path);
        long seen = 0;
        String typeValue = null;
        int minimum = 0;
        int maximum = 0;
        boolean wildcard = false;
        boolean ipv4 = false;
        boolean ipv6 = false;
        Set<String> schemes = null;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            requireToken(parser.currentToken(), JsonToken.PROPERTY_NAME, path);
            String field = parser.currentName();
            requireValue(parser, path + "." + field);
            switch (field) {
                case "type" -> {
                    seen = mark(seen, 0, path + ".type");
                    typeValue = readString(parser, path + ".type");
                }
                case "minimumOccurrences" -> {
                    seen = mark(seen, 1, path + ".minimumOccurrences");
                    minimum = readInt(parser, path + ".minimumOccurrences");
                }
                case "maximumOccurrences" -> {
                    seen = mark(seen, 2, path + ".maximumOccurrences");
                    maximum = readInt(parser, path + ".maximumOccurrences");
                }
                case "wildcardAllowed" -> {
                    seen = mark(seen, 3, path + ".wildcardAllowed");
                    wildcard = readBoolean(parser, path + ".wildcardAllowed");
                }
                case "ipv4Allowed" -> {
                    seen = mark(seen, 4, path + ".ipv4Allowed");
                    ipv4 = readBoolean(parser, path + ".ipv4Allowed");
                }
                case "ipv6Allowed" -> {
                    seen = mark(seen, 5, path + ".ipv6Allowed");
                    ipv6 = readBoolean(parser, path + ".ipv6Allowed");
                }
                case "allowedSchemes" -> {
                    seen = mark(seen, 6, path + ".allowedSchemes");
                    schemes = readUriSchemes(parser, path + ".allowedSchemes");
                }
                default -> throw failure("UNKNOWN_FIELD", path + ".?");
            }
        }
        requireAll(seen, 3, path);
        SubjectAlternativeNameType type = parseSanType(typeValue, path + ".type");
        validateSanShape(type, seen, path);
        try {
            SubjectAlternativeNameRule rule = new SubjectAlternativeNameRule(type, minimum, maximum, ipv4, ipv6);
            return new ParsedSanRule(rule, wildcard, schemes == null ? Set.of() : schemes);
        } catch (IllegalArgumentException ex) {
            throw failure("SEMANTIC_INVALID", path);
        }
    }

    private static void validateSanShape(SubjectAlternativeNameType type, long seen, String path) {
        long optionalShape = seen & (bit(3) | bit(4) | bit(5) | bit(6));
        long requiredShape = switch (type) {
            case DNS_NAME -> bit(3);
            case IP_ADDRESS -> bit(4) | bit(5);
            case URI -> bit(6);
            case RFC822_NAME -> 0;
        };
        if ((optionalShape & requiredShape) != requiredShape) {
            throw failure("MISSING_FIELD", path);
        }
        if ((optionalShape & ~requiredShape) != 0) {
            throw failure("UNKNOWN_FIELD", path);
        }
    }

    private static Set<String> readUriSchemes(JsonParser parser, String path) throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_ARRAY, path);
        Set<String> values = new LinkedHashSet<>();
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            checkArrayBound(values.size(), path);
            String value = readBoundedString(parser, path + "[" + values.size() + "]", MAXIMUM_URI_SCHEME_ASCII_BYTES);
            if (!isAscii(value) || !value.equals(value.toLowerCase(java.util.Locale.ROOT)) || !values.add(value)) {
                throw failure("TOKEN_INVALID", path);
            }
        }
        return Set.copyOf(values);
    }

    private static LeafSection readLeaf(JsonParser parser, String path) throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_OBJECT, path);
        long seen = 0;
        boolean basicCritical = false;
        boolean keyCritical = false;
        Set<LeafKeyUsage> keyUsage = null;
        boolean extendedCritical = false;
        Set<ExtendedKeyUsageId> extended = null;
        Set<String> algorithms = null;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            requireToken(parser.currentToken(), JsonToken.PROPERTY_NAME, path);
            String field = parser.currentName();
            requireValue(parser, path + "." + field);
            switch (field) {
                case "basicConstraintsCritical" -> {
                    seen = mark(seen, 0, path + ".basicConstraintsCritical");
                    basicCritical = readBoolean(parser, path + ".basicConstraintsCritical");
                }
                case "keyUsageCritical" -> {
                    seen = mark(seen, 1, path + ".keyUsageCritical");
                    keyCritical = readBoolean(parser, path + ".keyUsageCritical");
                }
                case "keyUsage" -> {
                    seen = mark(seen, 2, path + ".keyUsage");
                    keyUsage = readKeyUsages(parser, path + ".keyUsage");
                }
                case "extendedKeyUsageCritical" -> {
                    seen = mark(seen, 3, path + ".extendedKeyUsageCritical");
                    extendedCritical = readBoolean(parser, path + ".extendedKeyUsageCritical");
                }
                case "extendedKeyUsage" -> {
                    seen = mark(seen, 4, path + ".extendedKeyUsage");
                    extended = readExtendedKeyUsages(parser, path + ".extendedKeyUsage");
                }
                case "allowedKeyAlgorithms" -> {
                    seen = mark(seen, 5, path + ".allowedKeyAlgorithms");
                    algorithms = readAlgorithms(parser, path + ".allowedKeyAlgorithms");
                }
                default -> throw failure("UNKNOWN_FIELD", path + ".?");
            }
        }
        requireAll(seen, 6, path);
        return new LeafSection(basicCritical, keyCritical, keyUsage, extendedCritical, extended, algorithms);
    }

    private static Set<LeafKeyUsage> readKeyUsages(JsonParser parser, String path) throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_ARRAY, path);
        Set<LeafKeyUsage> values = EnumSet.noneOf(LeafKeyUsage.class);
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            checkArrayBound(values.size(), path);
            String token = readString(parser, path + "[" + values.size() + "]");
            LeafKeyUsage value;
            try {
                value = LeafKeyUsage.valueOf(token);
            } catch (IllegalArgumentException ex) {
                throw failure("TOKEN_INVALID", path);
            }
            if (!values.add(value)) {
                throw failure("SEMANTIC_INVALID", path);
            }
        }
        return Set.copyOf(values);
    }

    private static CaSection readCa(JsonParser parser, String path) throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_OBJECT, path);
        long seen = 0;
        boolean basicCritical = false;
        int pathLength = -1;
        boolean keyCritical = false;
        Set<CaKeyUsage> keyUsages = null;
        Set<String> algorithms = null;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            requireToken(parser.currentToken(), JsonToken.PROPERTY_NAME, path);
            String field = parser.currentName();
            requireValue(parser, path + "." + field);
            switch (field) {
                case "basicConstraintsCritical" -> {
                    seen = mark(seen, 0, path + ".basicConstraintsCritical");
                    basicCritical = readBoolean(parser, path + ".basicConstraintsCritical");
                }
                case "pathLengthConstraint" -> {
                    seen = mark(seen, 1, path + ".pathLengthConstraint");
                    pathLength = readInt(parser, path + ".pathLengthConstraint");
                }
                case "keyUsageCritical" -> {
                    seen = mark(seen, 2, path + ".keyUsageCritical");
                    keyCritical = readBoolean(parser, path + ".keyUsageCritical");
                }
                case "keyUsages" -> {
                    seen = mark(seen, 3, path + ".keyUsages");
                    keyUsages = readCaKeyUsages(parser, path + ".keyUsages");
                }
                case "allowedSubjectKeyAlgorithms" -> {
                    seen = mark(seen, 4, path + ".allowedSubjectKeyAlgorithms");
                    algorithms = readAlgorithms(parser, path + ".allowedSubjectKeyAlgorithms");
                }
                default -> throw failure("UNKNOWN_FIELD", path + ".?");
            }
        }
        requireAll(seen, 5, path);
        return new CaSection(basicCritical, pathLength, keyCritical, keyUsages, algorithms);
    }

    private static Set<CaKeyUsage> readCaKeyUsages(JsonParser parser, String path) throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_ARRAY, path);
        Set<CaKeyUsage> values = EnumSet.noneOf(CaKeyUsage.class);
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            checkArrayBound(values.size(), path);
            String token = readString(parser, path + "[" + values.size() + "]");
            CaKeyUsage value;
            try {
                value = CaKeyUsage.valueOf(token);
            } catch (IllegalArgumentException ex) {
                throw failure("TOKEN_INVALID", path);
            }
            if (!values.add(value)) {
                throw failure("SEMANTIC_INVALID", path);
            }
        }
        return Set.copyOf(values);
    }

    private static Set<ExtendedKeyUsageId> readExtendedKeyUsages(JsonParser parser, String path)
            throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_ARRAY, path);
        Set<ExtendedKeyUsageId> values = new LinkedHashSet<>();
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            checkArrayBound(values.size(), path);
            String oid = readString(parser, path + "[" + values.size() + "]");
            ExtendedKeyUsageId value;
            try {
                value = new ExtendedKeyUsageId(oid);
            } catch (IllegalArgumentException ex) {
                throw failure("TOKEN_INVALID", path);
            }
            if (!oid.equals(value.oid()) || !values.add(value)) {
                throw failure("SEMANTIC_INVALID", path);
            }
        }
        return Set.copyOf(values);
    }

    private static Set<String> readAlgorithms(JsonParser parser, String path) throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.START_ARRAY, path);
        Set<String> values = new LinkedHashSet<>();
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            checkArrayBound(values.size(), path);
            String token = readString(parser, path + "[" + values.size() + "]");
            if (!isAllowedAlgorithm(token)) {
                throw failure("TOKEN_INVALID", path);
            }
            if (!values.add(token)) {
                throw failure("SEMANTIC_INVALID", path);
            }
        }
        return Set.copyOf(values);
    }

    private static void writeDocument(JsonGenerator generator, CertificateProfileDefinition definition)
            throws JacksonException {
        generator.writeStartObject();
        generator.writeNumberProperty("schemaVersion", CertificateProfileDefinition.SCHEMA_VERSION);
        generator.writeStringProperty("certificateType", definition.certificateType().name());
        generator.writeStringProperty("profileId", definition.profileId());
        generator.writeNumberProperty("profileVersion", definition.profileVersion());
        generator.writeStringProperty("formatId", definition.formatId().value());
        generator.writeStringProperty("displayName", definition.displayName());
        generator.writeStringProperty("maxValidity", definition.maximumValidity().toString());
        writeAlgorithmBindings(generator, definition.algorithmBindingPolicy());
        writeSubject(generator, definition.subjectPolicy());
        if (definition.certificateType() == CertificateProfileKind.END_ENTITY) {
            LeafCertificatePolicy leaf = definition.leafPolicy();
            writeSan(generator, leaf.subjectAlternativeNamePolicy());
            writeLeaf(generator, leaf);
        } else {
            writeCa(generator, definition.caPolicy());
        }
        generator.writeEndObject();
    }

    private static void writeSubject(JsonGenerator generator, SubjectPolicy policy) throws JacksonException {
        generator.writeObjectPropertyStart("subject");
        generator.writeBooleanProperty("allowEmpty", policy.allowEmpty());
        generator.writeArrayPropertyStart("rules");
        for (SubjectRdnRule rule : policy.rules()) {
            generator.writeStartObject();
            generator.writeStringProperty("oid", rule.type().oid());
            generator.writeStringProperty("source", rule.requesterSupplied() ? REQUESTER_SOURCE : PROFILE_FIXED_SOURCE);
            generator.writeNumberProperty("minimumOccurrences", rule.minimumOccurrences());
            generator.writeNumberProperty("maximumOccurrences", rule.maximumOccurrences());
            generator.writeNumberProperty("maximumUtf8Bytes", rule.maximumUtf8Bytes());
            if (rule.fixedValue().isPresent()) {
                generator.writeStringProperty("fixedValue", rule.fixedValue().orElseThrow());
            }
            generator.writeEndObject();
        }
        generator.writeEndArray();
        generator.writeEndObject();
    }

    private static void writeAlgorithmBindings(JsonGenerator generator, X509AlgorithmBindingPolicy policy)
            throws JacksonException {
        generator.writeObjectPropertyStart("algorithmBindings");
        generator.writeStringProperty("mode", policy.mode().name());
        writeBindingReference(generator, "subjectPublicKey", policy.subjectPublicKey());
        writeBindingReference(generator, "csrSignature", policy.csrSignature());
        writeBindingReference(generator, "certificateSignature", policy.certificateSignature());
        writeBindingReference(generator, "crlSignature", policy.crlSignature());
        generator.writeEndObject();
    }

    private static void writeBindingReference(JsonGenerator generator, String field,
            Optional<X509AlgorithmBindingPolicy.BindingReference> reference) throws JacksonException {
        if (reference.isEmpty()) {
            return;
        }
        X509AlgorithmBindingPolicy.BindingReference value = reference.orElseThrow();
        generator.writeObjectPropertyStart(field);
        generator.writeStringProperty("bindingId", value.bindingId());
        generator.writeStringProperty("semanticCommitment", value.semanticCommitment());
        generator.writeEndObject();
    }

    private static void writeSan(JsonGenerator generator, SubjectAlternativeNamePolicy policy) throws JacksonException {
        generator.writeObjectPropertyStart("subjectAlternativeNames");
        generator.writeNumberProperty("minimumTotal", policy.minimumTotal());
        generator.writeNumberProperty("maximumTotal", policy.maximumTotal());
        generator.writeBooleanProperty("serviceIdentityRequired", policy.requireServiceIdentity());
        generator.writeBooleanProperty("emailIdentityRequired", policy.requireEmailIdentity());
        generator.writeBooleanProperty("criticalWhenSubjectNonEmpty", policy.criticalWithNonemptySubject());
        generator.writeArrayPropertyStart("rules");
        List<SubjectAlternativeNameRule> rules = policy.rules().stream()
                .sorted(Comparator.comparing(rule -> rule.type().name())).toList();
        for (SubjectAlternativeNameRule rule : rules) {
            generator.writeStartObject();
            generator.writeStringProperty("type", rule.type().name());
            generator.writeNumberProperty("minimumOccurrences", rule.minimum());
            generator.writeNumberProperty("maximumOccurrences", rule.maximum());
            switch (rule.type()) {
                case DNS_NAME -> generator.writeBooleanProperty("wildcardAllowed", policy.allowDnsWildcard());
                case IP_ADDRESS -> {
                    generator.writeBooleanProperty("ipv4Allowed", rule.allowIpv4());
                    generator.writeBooleanProperty("ipv6Allowed", rule.allowIpv6());
                }
                case URI -> writeSortedStrings(generator, "allowedSchemes", policy.allowedUriSchemes());
                case RFC822_NAME -> {
                    // No type-specific fields.
                }
            }
            generator.writeEndObject();
        }
        generator.writeEndArray();
        generator.writeEndObject();
    }

    private static void writeLeaf(JsonGenerator generator, LeafCertificatePolicy policy) throws JacksonException {
        generator.writeObjectPropertyStart("leafCertificate");
        generator.writeBooleanProperty("basicConstraintsCritical", policy.basicConstraintsCritical());
        generator.writeBooleanProperty("keyUsageCritical", policy.keyUsageCritical());
        writeSortedStrings(generator, "keyUsage", policy.keyUsages().stream().map(Enum::name).toList());
        generator.writeBooleanProperty("extendedKeyUsageCritical", policy.extendedKeyUsageCritical());
        writeSortedStrings(generator, "extendedKeyUsage",
                policy.extendedKeyUsages().stream().map(ExtendedKeyUsageId::oid).toList());
        writeSortedStrings(generator, "allowedKeyAlgorithms", policy.allowedSubjectKeyAlgorithmIds());
        generator.writeEndObject();
    }

    private static void writeCa(JsonGenerator generator, CaCertificatePolicy policy) throws JacksonException {
        generator.writeObjectPropertyStart("caCertificate");
        generator.writeBooleanProperty("basicConstraintsCritical", policy.basicConstraintsCritical());
        generator.writeNumberProperty("pathLengthConstraint", policy.pathLengthConstraint());
        generator.writeBooleanProperty("keyUsageCritical", policy.keyUsageCritical());
        writeSortedStrings(generator, "keyUsages", policy.keyUsages().stream().map(Enum::name).toList());
        writeSortedStrings(generator, "allowedSubjectKeyAlgorithms", policy.allowedSubjectKeyAlgorithmIds());
        generator.writeEndObject();
    }

    private static void writeSortedStrings(JsonGenerator generator, String field, java.util.Collection<String> values)
            throws JacksonException {
        generator.writeArrayPropertyStart(field);
        for (String value : values.stream().sorted().toList()) {
            generator.writeString(value);
        }
        generator.writeEndArray();
    }

    private static void validateDefinition(CertificateProfileDefinition definition) {
        if (definition == null) {
            throw failure("CANONICALIZATION_FAILED", "$");
        }
        validateProfileString(definition.profileId(), MAXIMUM_PROFILE_ID_UTF8_BYTES, "$.profileId",
                "CANONICALIZATION_FAILED");
        validateProfileString(definition.formatId().value(), MAXIMUM_FORMAT_ID_UTF8_BYTES, "$.formatId",
                "CANONICALIZATION_FAILED");
        validateProfileString(definition.displayName(), MAXIMUM_DISPLAY_NAME_UTF8_BYTES, "$.displayName",
                "CANONICALIZATION_FAILED");
        validateWritableString(definition.maximumValidity().toString(), MAXIMUM_STRING_UTF8_BYTES, "$.maxValidity");
        if (definition.subjectPolicy().rules().size() > MAXIMUM_ARRAY_ELEMENTS) {
            throw failure("CANONICALIZATION_FAILED", "$");
        }
        for (SubjectRdnRule rule : definition.subjectPolicy().rules()) {
            rule.fixedValue().ifPresent(
                    value -> validateWritableString(value, MAXIMUM_STRING_UTF8_BYTES, "$.subject.rules.fixedValue"));
        }
        if (definition.certificateType() != CertificateProfileKind.END_ENTITY) {
            CaCertificatePolicy ca = definition.caPolicy();
            if (ca.keyUsages().size() > MAXIMUM_ARRAY_ELEMENTS
                    || ca.allowedSubjectKeyAlgorithmIds().size() > MAXIMUM_ARRAY_ELEMENTS) {
                throw failure("CANONICALIZATION_FAILED", "$");
            }
            return;
        }
        LeafCertificatePolicy leaf = definition.leafPolicy();
        if (leaf.subjectAlternativeNamePolicy().rules().size() > MAXIMUM_ARRAY_ELEMENTS
                || leaf.subjectAlternativeNamePolicy().allowedUriSchemes().size() > MAXIMUM_ARRAY_ELEMENTS
                || leaf.keyUsages().size() > MAXIMUM_ARRAY_ELEMENTS
                || leaf.extendedKeyUsages().size() > MAXIMUM_ARRAY_ELEMENTS
                || leaf.allowedSubjectKeyAlgorithmIds().size() > MAXIMUM_ARRAY_ELEMENTS) {
            throw failure("CANONICALIZATION_FAILED", "$");
        }
        for (String scheme : leaf.subjectAlternativeNamePolicy().allowedUriSchemes()) {
            validateWritableString(scheme, MAXIMUM_URI_SCHEME_ASCII_BYTES,
                    "$.subjectAlternativeNames.rules.allowedSchemes");
            if (!isAscii(scheme)) {
                throw failure("CANONICALIZATION_FAILED", "$.subjectAlternativeNames.rules.allowedSchemes");
            }
        }
        for (ExtendedKeyUsageId usage : leaf.extendedKeyUsages()) {
            validateWritableString(usage.oid(), MAXIMUM_STRING_UTF8_BYTES, "$.leafCertificate.extendedKeyUsage");
        }
    }

    private static void validateWritableString(String value, int maximum, String path) {
        if (value == null || utf8Length(value) > maximum || hasUnpairedSurrogate(value)) {
            throw failure("CANONICALIZATION_FAILED", path);
        }
    }

    private static void validateProfileString(String value, int maximum, String path, String failureCode) {
        if (value == null || value.isBlank() || !value.equals(value.strip()) || hasUnpairedSurrogate(value)
                || utf8Length(value) > maximum) {
            throw failure(failureCode, path);
        }
    }

    private static String readString(JsonParser parser, String path) throws JacksonException {
        return readBoundedString(parser, path, MAXIMUM_STRING_UTF8_BYTES);
    }

    private static String readBoundedString(JsonParser parser, String path, int maximumUtf8Bytes)
            throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.VALUE_STRING, path);
        String value = parser.getString();
        if (hasUnpairedSurrogate(value)) {
            throw failure("TOKEN_INVALID", path);
        }
        if (utf8Length(value) > maximumUtf8Bytes) {
            throw failure("LIMIT_EXCEEDED", path);
        }
        return value;
    }

    private static boolean readBoolean(JsonParser parser, String path) {
        if (parser.currentToken() == JsonToken.VALUE_TRUE) {
            return true;
        }
        if (parser.currentToken() == JsonToken.VALUE_FALSE) {
            return false;
        }
        throw failure("WRONG_TYPE", path);
    }

    private static int readInt(JsonParser parser, String path) throws JacksonException {
        long value = readLong(parser, path);
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
            throw failure("LIMIT_EXCEEDED", path);
        }
        return (int) value;
    }

    private static long readLong(JsonParser parser, String path) throws JacksonException {
        requireToken(parser.currentToken(), JsonToken.VALUE_NUMBER_INT, path);
        try {
            return parser.getLongValue();
        } catch (JacksonException ex) {
            throw failure("LIMIT_EXCEEDED", path);
        }
    }

    private static Duration readDuration(JsonParser parser, String path) throws JacksonException {
        String value = readString(parser, path);
        Duration duration;
        try {
            duration = Duration.parse(value);
        } catch (DateTimeException ex) {
            throw failure("TOKEN_INVALID", path);
        }
        if (duration.isZero() || duration.isNegative() || !value.equals(duration.toString())) {
            throw failure("TOKEN_INVALID", path);
        }
        return duration;
    }

    private static SubjectRdnType parseRdnType(String oid, String path) {
        try {
            return SubjectRdnType.fromOid(oid);
        } catch (IllegalArgumentException ex) {
            throw failure("TOKEN_INVALID", path);
        }
    }

    private static CertificateProfileKind readCertificateType(JsonParser parser, String path) throws JacksonException {
        String token = readString(parser, path);
        try {
            return CertificateProfileKind.valueOf(token);
        } catch (IllegalArgumentException ex) {
            throw failure("CERTIFICATE_TYPE_UNSUPPORTED", path);
        }
    }

    private static boolean parseSubjectSource(String source, String path) {
        if (REQUESTER_SOURCE.equals(source)) {
            return false;
        }
        if (PROFILE_FIXED_SOURCE.equals(source)) {
            return true;
        }
        throw failure("TOKEN_INVALID", path);
    }

    private static SubjectAlternativeNameType parseSanType(String type, String path) {
        try {
            return SubjectAlternativeNameType.valueOf(type);
        } catch (IllegalArgumentException ex) {
            throw failure("TOKEN_INVALID", path);
        }
    }

    private static void requireToken(JsonToken actual, JsonToken expected, String path) {
        if (actual == null) {
            throw failure("MALFORMED_JSON", path);
        }
        if (actual != expected) {
            throw failure("WRONG_TYPE", path);
        }
    }

    private static void requireValue(JsonParser parser, String path) throws JacksonException {
        JsonToken token = parser.nextToken();
        if (token == null) {
            throw failure("MALFORMED_JSON", path);
        }
        if (token == JsonToken.VALUE_NULL) {
            throw failure("WRONG_TYPE", path);
        }
    }

    private static long mark(long seen, int field, String path) {
        long mask = bit(field);
        if ((seen & mask) != 0) {
            throw failure("DUPLICATE_FIELD", path);
        }
        return seen | mask;
    }

    private static long bit(int field) {
        return 1L << field;
    }

    private static boolean isSeen(long seen, int field) {
        return (seen & bit(field)) != 0;
    }

    private static void requireAll(long seen, int fieldCount, String path) {
        long expected = bit(fieldCount) - 1;
        if ((seen & expected) != expected) {
            throw failure("MISSING_FIELD", path);
        }
    }

    private static void checkArrayBound(int currentSize, String path) {
        if (currentSize >= MAXIMUM_ARRAY_ELEMENTS) {
            throw failure("LIMIT_EXCEEDED", path);
        }
    }

    private static int utf8Length(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private static boolean hasUnpairedSurrogate(String value) {
        return value.codePoints()
                .anyMatch(codePoint -> codePoint >= Character.MIN_SURROGATE && codePoint <= Character.MAX_SURROGATE);
    }

    private static boolean isAscii(String value) {
        for (int index = 0; index < value.length(); index++) {
            if (value.charAt(index) > MAXIMUM_ASCII_VALUE) {
                return false;
            }
        }
        return true;
    }

    private static boolean isAllowedAlgorithm(String value) {
        return "RSA".equals(value) || "ECDSA".equals(value) || "Ed25519".equals(value) || "Ed448".equals(value)
                || "SPHINCS+".equals(value);
    }

    private static boolean hasUtf8Bom(byte[] value) {
        return value.length >= 3 && value[0] == (byte) 0xef && value[1] == (byte) 0xbb && value[2] == (byte) 0xbf;
    }

    private static boolean isDuplicateFailure(JacksonException exception) {
        String message = exception.getMessage();
        return message != null && message.contains("Duplicate");
    }

    private static PkiException failure(String code, String path) {
        return new PkiException(PREFIX + code + " path=" + path);
    }

    /** Mutable state confined to one streaming top-level document parse. */
    private static final class DocumentFields {
        private long seen;
        private int schemaVersion;
        private CertificateProfileKind certificateType;
        private String profileId;
        private long profileVersion;
        private String formatId;
        private String displayName;
        private Duration maximumValidity;
        private X509AlgorithmBindingPolicy algorithmBindings;
        private SubjectSection subject;
        private SanSection san;
        private LeafSection leaf;
        private CaSection ca;
    }

    private record SubjectSection(boolean allowEmpty, List<SubjectRdnRule> rules) {
    }

    private record SanSection(int minimumTotal, int maximumTotal, boolean serviceIdentityRequired,
            boolean emailIdentityRequired, boolean criticalWhenSubjectNonEmpty, List<SubjectAlternativeNameRule> rules,
            boolean wildcardAllowed, Set<String> allowedSchemes) {
    }

    private record SanRules(List<SubjectAlternativeNameRule> rules, boolean wildcardAllowed,
            Set<String> allowedSchemes) {
    }

    private record ParsedSanRule(SubjectAlternativeNameRule rule, boolean wildcardAllowed, Set<String> allowedSchemes) {
    }

    private record LeafSection(boolean basicConstraintsCritical, boolean keyUsageCritical, Set<LeafKeyUsage> keyUsage,
            boolean extendedKeyUsageCritical, Set<ExtendedKeyUsageId> extendedKeyUsage,
            Set<String> allowedKeyAlgorithms) {
    }

    private record CaSection(boolean basicConstraintsCritical, int pathLengthConstraint, boolean keyUsageCritical,
            Set<CaKeyUsage> keyUsages, Set<String> allowedKeyAlgorithms) {
    }
}
