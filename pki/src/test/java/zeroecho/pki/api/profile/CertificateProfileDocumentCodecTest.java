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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;

final class CertificateProfileDocumentCodecTest {

    private static boolean initializationProbe;

    private static final String VALID_DOCUMENT = """
            {
              "schemaVersion": 5,
              "certificateType": "END_ENTITY",
              "profileId": "tls-service",
              "profileVersion": 7,
              "formatId": "x509",
              "displayName": "TLS service",
              "maxValidity": "PT24H",
              "approvalRequirement": "NONE",
              "algorithmBindings": {"mode":"STANDARD_ONLY"},
              "confirmationPolicy": {
                "disclosurePolicy": "OWNER_ONLY",
                "confirmationWindow": "PT24H",
                "proofSuiteId": "zeroecho.signature-pop.v1",
                "proofSuiteCommitment": "5ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11",
                "policyCommitment": "4933b3d9a9dd31b972d5835884ed8ef9218f8d331928e6ac0feb802d28ab9a30"
              },
              "subject": {
                "allowEmpty": false,
                "rules": [
                  {
                    "oid": "2.5.4.3",
                    "source": "REQUESTER",
                    "minimumOccurrences": 1,
                    "maximumOccurrences": 1,
                    "maximumUtf8Bytes": 128
                  },
                  {
                    "oid": "2.5.4.10",
                    "source": "PROFILE_FIXED",
                    "minimumOccurrences": 1,
                    "maximumOccurrences": 1,
                    "maximumUtf8Bytes": 64,
                    "fixedValue": "ZeroEcho"
                  }
                ]
              },
              "subjectAlternativeNames": {
                "minimumTotal": 1,
                "maximumTotal": 4,
                "serviceIdentityRequired": true,
                "emailIdentityRequired": true,
                "criticalWhenSubjectNonEmpty": false,
                "rules": [
                  {
                    "type": "URI",
                    "minimumOccurrences": 0,
                    "maximumOccurrences": 1,
                    "allowedSchemes": ["spiffe", "https"]
                  },
                  {
                    "type": "DNS_NAME",
                    "minimumOccurrences": 0,
                    "maximumOccurrences": 1,
                    "wildcardAllowed": true
                  },
                  {
                    "type": "IP_ADDRESS",
                    "minimumOccurrences": 0,
                    "maximumOccurrences": 1,
                    "ipv4Allowed": true,
                    "ipv6Allowed": true
                  },
                  {
                    "type": "RFC822_NAME",
                    "minimumOccurrences": 1,
                    "maximumOccurrences": 1
                  }
                ]
              },
              "leafCertificate": {
                "basicConstraintsCritical": true,
                "keyUsageCritical": true,
                "keyUsage": ["KEY_AGREEMENT", "ENCIPHER_ONLY", "DIGITAL_SIGNATURE"],
                "extendedKeyUsageCritical": false,
                "extendedKeyUsage": ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"],
                "allowedKeyAlgorithms": ["RSA", "Ed25519", "ECDSA", "Ed448"]
              }
            }
            """;

    @Test
    void parsesEverySupportedRuleShapeIntoAuthoritativeTypedPolicies() {
        CertificateProfileDefinition definition = parse(VALID_DOCUMENT);

        assertEquals(5, CertificateProfileDefinition.SCHEMA_VERSION);
        assertEquals(CertificateProfileKind.END_ENTITY, definition.certificateType());
        assertEquals("tls-service", definition.profileId());
        assertEquals(7, definition.profileVersion());
        assertEquals("x509", definition.formatId().value());
        assertEquals("TLS service", definition.displayName());
        LeafCertificatePolicy leaf = definition.leafPolicy();
        assertEquals(Duration.ofDays(1), definition.maximumValidity());
        assertEquals(List.of(SubjectRdnType.COMMON_NAME, SubjectRdnType.ORGANIZATION_NAME),
                definition.subjectPolicy().rules().stream().map(SubjectRdnRule::type).toList());
        assertEquals("ZeroEcho", definition.subjectPolicy().rules().get(1).fixedValue().orElseThrow());
        assertFalse(definition.subjectPolicy().allowEmpty());
        assertTrue(leaf.subjectAlternativeNamePolicy().allowDnsWildcard());
        assertEquals(Set.of("https", "spiffe"), leaf.subjectAlternativeNamePolicy().allowedUriSchemes());
        assertEquals(Set.of(LeafKeyUsage.DIGITAL_SIGNATURE, LeafKeyUsage.KEY_AGREEMENT, LeafKeyUsage.ENCIPHER_ONLY),
                leaf.keyUsages());
        assertEquals(Set.of("RSA", "ECDSA", "Ed25519", "Ed448"), leaf.allowedSubjectKeyAlgorithmIds());
        assertEquals(Set.of(new ExtendedKeyUsageId("1.3.6.1.5.5.7.3.1"), new ExtendedKeyUsageId("1.3.6.1.5.5.7.3.2")),
                leaf.extendedKeyUsages());
    }

    @Test
    void roundTripsEveryRequiredTypedProfileCategoryWithoutActivationState() {
        List<CertificateProfileDefinition> definitions = List.of(
                definition("cn-only", requesterCn(), noSan(), Set.of(), Set.of("RSA")),
                definition("dns", requesterCn(), dnsSan(false, false), eku(), Set.of("RSA")),
                definition("wildcard-dns", requesterCn(), dnsSan(true, false), eku(), Set.of("RSA")),
                definition("ipv4", requesterCn(), ipSan(true, false), eku(), Set.of("ECDSA")),
                definition("ipv6", requesterCn(), ipSan(false, true), eku(), Set.of("Ed25519")),
                definition("uri", requesterCn(), uriSan(), eku(), Set.of("Ed448")),
                definition("email", requesterCn(), emailSan(), eku(), Set.of("RSA")),
                definition("mixed", requesterCn(), mixedSan(), eku(), Set.of("RSA", "ECDSA")),
                definition("empty-subject", new SubjectPolicy(true, List.of()), dnsSan(false, true), eku(),
                        Set.of("RSA")),
                definition("fixed-rdn", fixedOrganization(), noSan(), eku(), Set.of("RSA")),
                definition("multiple-algorithms", requesterCn(), noSan(), Set.of(),
                        Set.of("RSA", "ECDSA", "Ed25519", "Ed448")));

        for (CertificateProfileDefinition expected : definitions) {
            byte[] encoded = CertificateProfileDocumentCodec.writeCanonical(expected);
            CertificateProfileDefinition actual = CertificateProfileDocumentCodec.parse(encoded);
            String json = new String(encoded, StandardCharsets.UTF_8);

            assertEquals(expected, actual, expected.profileId());
            assertFalse(json.contains("\"active\""), expected.profileId());
            assertArrayEquals(encoded, CertificateProfileDocumentCodec.writeCanonical(actual), expected.profileId());
        }

        CertificateProfileDefinition immutable = CertificateProfileDocumentCodec
                .parse(CertificateProfileDocumentCodec.writeCanonical(definitions.get(7)));
        assertThrows(UnsupportedOperationException.class, () -> immutable.subjectPolicy().rules()
                .add(new SubjectRdnRule(SubjectRdnType.PSEUDONYM, 0, 0, 32, Optional.empty(), true)));
        assertThrows(UnsupportedOperationException.class,
                () -> immutable.leafPolicy().keyUsages().add(LeafKeyUsage.CONTENT_COMMITMENT));
        assertThrows(UnsupportedOperationException.class,
                () -> immutable.leafPolicy().subjectAlternativeNamePolicy().allowedUriSchemes().add("ssh"));
    }

    @Test
    void roundTripsRootAndIntermediateCaPoliciesAndRejectsWrongKindShapes() {
        CertificateProfileDefinition root = caDefinition("root-test", CertificateProfileKind.ROOT_CA, 1);
        CertificateProfileDefinition intermediate = caDefinition("intermediate-test",
                CertificateProfileKind.INTERMEDIATE_CA, 0);
        CertificateProfileDefinition delegatedIntermediate = caDefinition("delegated-intermediate-test",
                CertificateProfileKind.INTERMEDIATE_CA, 1);
        for (CertificateProfileDefinition expected : List.of(root, intermediate, delegatedIntermediate)) {
            byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(expected);
            CertificateProfileDefinition actual = CertificateProfileDocumentCodec.parse(canonical);
            assertEquals(expected, actual);
            assertArrayEquals(canonical, CertificateProfileDocumentCodec.writeCanonical(actual));
        }

        String rootJson = canonical(root);
        assertCode(rootJson.replace("\"certificateType\":\"ROOT_CA\"", "\"certificateType\":\"END_ENTITY\""),
                "FIELD_FORBIDDEN_FOR_CERTIFICATE_TYPE");
        assertCode(rootJson.replace("\"caCertificate\":", "\"leafCertificate\":"),
                "FIELD_FORBIDDEN_FOR_CERTIFICATE_TYPE");
        assertCode(rootJson.replace("\"caCertificate\":", "\"subjectAlternativeNames\":"),
                "FIELD_FORBIDDEN_FOR_CERTIFICATE_TYPE");
        assertCode(rootJson.replace(",\"caCertificate\":{", ",\"leafCertificate\":{}" + ",\"caCertificate\":{"),
                "FIELD_FORBIDDEN_FOR_CERTIFICATE_TYPE");
        assertCode(rootJson.replace("\"allowEmpty\":false", "\"allowEmpty\":true"), "SEMANTIC_INVALID");
        assertCode(rootJson.replace("\"pathLengthConstraint\":1", "\"pathLengthConstraint\":-1"), "SEMANTIC_INVALID");
        assertCode(rootJson.replace("\"pathLengthConstraint\":1", "\"pathLengthConstraint\":33"), "SEMANTIC_INVALID");
        assertCode(rootJson.replace("\"basicConstraintsCritical\":true", "\"basicConstraintsCritical\":false"),
                "SEMANTIC_INVALID");
        assertCode(rootJson.replace("\"keyUsageCritical\":true", "\"keyUsageCritical\":false"), "SEMANTIC_INVALID");
        assertCode(rootJson.replace("[\"CRL_SIGN\",\"KEY_CERT_SIGN\"]", "[\"KEY_CERT_SIGN\"]"), "SEMANTIC_INVALID");
        assertCode(rootJson.replace("[\"CRL_SIGN\",\"KEY_CERT_SIGN\"]", "[\"CRL_SIGN\"]"), "SEMANTIC_INVALID");
        assertCode(
                rootJson.replace("[\"CRL_SIGN\",\"KEY_CERT_SIGN\"]", "[\"CRL_SIGN\",\"CRL_SIGN\",\"KEY_CERT_SIGN\"]"),
                "SEMANTIC_INVALID");
        assertCode(rootJson.replace("\"allowedSubjectKeyAlgorithms\":[\"RSA\"]", "\"allowedSubjectKeyAlgorithms\":[]"),
                "SEMANTIC_INVALID");
        assertCode(rootJson.replace("\"allowedSubjectKeyAlgorithms\":",
                "\"extendedKeyUsage\":[],\"allowedSubjectKeyAlgorithms\":"), "UNKNOWN_FIELD");
    }

    @Test
    void canonicalOutputHasFixedOrderSortedSetsAndIsIdempotent() {
        byte[] first = CertificateProfileDocumentCodec.writeCanonical(parse(VALID_DOCUMENT));
        byte[] second = CertificateProfileDocumentCodec.writeCanonical(CertificateProfileDocumentCodec.parse(first));
        String json = new String(first, StandardCharsets.UTF_8);

        assertArrayEquals(first, second);
        assertFalse(json.startsWith("\ufeff"));
        assertFalse(json.endsWith("\n"));
        assertFalse(json.contains("\n"));
        assertFalse(json.contains(": "));
        assertFalse(json.contains(", "));
        assertTrue(json.indexOf("\"schemaVersion\"") < json.indexOf("\"certificateType\""));
        assertTrue(json.indexOf("\"certificateType\"") < json.indexOf("\"profileId\""));
        assertTrue(json.indexOf("\"DNS_NAME\"") < json.indexOf("\"IP_ADDRESS\""));
        assertTrue(json.indexOf("\"IP_ADDRESS\"") < json.indexOf("\"RFC822_NAME\""));
        assertTrue(json.indexOf("\"RFC822_NAME\"") < json.indexOf("\"URI\""));
        assertTrue(json.contains("\"allowedSchemes\":[\"https\",\"spiffe\"]"));
        assertTrue(json.contains("\"source\":\"REQUESTER\""));
        assertTrue(json.contains("\"source\":\"PROFILE_FIXED\""));
        assertTrue(json.contains("\"keyUsage\":[\"DIGITAL_SIGNATURE\",\"ENCIPHER_ONLY\"," + "\"KEY_AGREEMENT\"]"));
        assertTrue(json.contains("\"allowedKeyAlgorithms\":[\"ECDSA\",\"Ed25519\",\"Ed448\",\"RSA\"]"));
    }

    @Test
    void writerRejectsProfileStringsThatItsParserWouldReject() {
        CertificateProfileDefinition valid = definition("valid", requesterCn(), noSan(), Set.of(), Set.of("RSA"));
        List<CertificateProfileDefinition> invalid = List.of(
                new CertificateProfileDefinition(valid.certificateType(), " padded", valid.profileVersion(),
                        valid.formatId(), valid.displayName(), valid.maximumValidity(), valid.subjectPolicy(),
                        valid.certificatePolicy(), valid.algorithmBindingPolicy(), valid.confirmationPolicy()),
                new CertificateProfileDefinition(valid.certificateType(), valid.profileId(), valid.profileVersion(),
                        new FormatId("x509 "), valid.displayName(), valid.maximumValidity(), valid.subjectPolicy(),
                        valid.certificatePolicy(), valid.algorithmBindingPolicy(), valid.confirmationPolicy()),
                new CertificateProfileDefinition(valid.certificateType(), valid.profileId(), valid.profileVersion(),
                        valid.formatId(), " padded ", valid.maximumValidity(), valid.subjectPolicy(),
                        valid.certificatePolicy(), valid.algorithmBindingPolicy(), valid.confirmationPolicy()));

        for (CertificateProfileDefinition definition : invalid) {
            assertWriteCode(definition, "CANONICALIZATION_FAILED");
        }
    }

    @Test
    void inputStreamRemainsCallerOwned() {
        TrackingInputStream input = new TrackingInputStream(bytes(VALID_DOCUMENT));

        CertificateProfileDefinition definition = CertificateProfileDocumentCodec.parse(input);

        assertEquals("tls-service", definition.profileId());
        assertFalse(input.closed);
    }

    @Test
    void rejectsMalformedJsonExtensionsTrailingContentBomAndMalformedUtf8() {
        assertCode(VALID_DOCUMENT.replace("{", "{/*comment*/"), "MALFORMED_JSON");
        assertCode(VALID_DOCUMENT + "{}", "MALFORMED_JSON");
        assertCode(VALID_DOCUMENT.substring(0, VALID_DOCUMENT.length() - 4), "MALFORMED_JSON");

        byte[] bom = new byte[bytes(VALID_DOCUMENT).length + 3];
        bom[0] = (byte) 0xef;
        bom[1] = (byte) 0xbb;
        bom[2] = (byte) 0xbf;
        System.arraycopy(bytes(VALID_DOCUMENT), 0, bom, 3, bytes(VALID_DOCUMENT).length);
        assertCode(bom, "MALFORMED_JSON");

        byte[] malformed = bytes(VALID_DOCUMENT);
        int display = indexOf(malformed, bytes("TLS service"));
        malformed[display] = (byte) 0xc3;
        malformed[display + 1] = (byte) 0x28;
        assertCode(malformed, "MALFORMED_JSON");
    }

    @Test
    void rejectsDuplicateUnknownMissingNullWrongAndNonintegralFields() {
        assertCode(VALID_DOCUMENT.replace("\"schemaVersion\": 5,", "\"schemaVersion\": 5,\"schemaVersion\": 5,"),
                "DUPLICATE_FIELD");
        for (String document : List.of(
                VALID_DOCUMENT.replace("\"schemaVersion\": 5,", "\"secret-field\": true,\"schemaVersion\": 5,"),
                VALID_DOCUMENT.replace("\"allowEmpty\": false,", "\"unknown\": true,\"allowEmpty\": false,"),
                VALID_DOCUMENT.replace("\"oid\": \"2.5.4.3\",", "\"unknown\": true,\"oid\": \"2.5.4.3\","),
                VALID_DOCUMENT.replace("\"minimumTotal\": 1,", "\"unknown\": true,\"minimumTotal\": 1,"),
                VALID_DOCUMENT.replace("\"type\": \"URI\",", "\"unknown\": true,\"type\": \"URI\","),
                VALID_DOCUMENT.replace("\"basicConstraintsCritical\": true,",
                        "\"unknown\": true,\"basicConstraintsCritical\": true,"))) {
            assertCode(document, "UNKNOWN_FIELD");
        }
        for (String document : List.of(
                VALID_DOCUMENT.replace("\"allowEmpty\": false,", "\"allowEmpty\": false,\"allowEmpty\": false,"),
                VALID_DOCUMENT.replace("\"type\": \"URI\",", "\"type\": \"URI\",\"type\": \"URI\","),
                VALID_DOCUMENT.replace("\"keyUsageCritical\": true,",
                        "\"keyUsageCritical\": true,\"keyUsageCritical\": true,"))) {
            assertCode(document, "DUPLICATE_FIELD");
        }
        for (String document : List.of(VALID_DOCUMENT.replace("\"schemaVersion\": 5,\n", ""),
                VALID_DOCUMENT.replace("\"allowEmpty\": false,\n", ""),
                VALID_DOCUMENT.replace("\"oid\": \"2.5.4.3\",\n", ""),
                VALID_DOCUMENT.replace("\"minimumTotal\": 1,\n", ""),
                VALID_DOCUMENT.replace("\"type\": \"URI\",\n", ""),
                VALID_DOCUMENT.replace("\"basicConstraintsCritical\": true,\n", ""))) {
            assertCode(document, "MISSING_FIELD");
        }
        assertCode(VALID_DOCUMENT.replace("\"displayName\": \"TLS service\"", "\"displayName\": null"), "WRONG_TYPE");
        assertCode(VALID_DOCUMENT.replace("\"allowEmpty\": false", "\"allowEmpty\": \"false\""), "WRONG_TYPE");
        assertCode(VALID_DOCUMENT.replace("\"minimumTotal\": 1", "\"minimumTotal\": \"1\""), "WRONG_TYPE");
        assertCode(VALID_DOCUMENT.replace(
                "\"keyUsage\": [\"KEY_AGREEMENT\", " + "\"ENCIPHER_ONLY\", \"DIGITAL_SIGNATURE\"]",
                "\"keyUsage\": true"), "WRONG_TYPE");
        assertCode(VALID_DOCUMENT.replace("\"profileVersion\": 7", "\"profileVersion\": \"7\""), "WRONG_TYPE");
        assertCode(VALID_DOCUMENT.replace("\"profileVersion\": 7", "\"profileVersion\": -1"),
                "PROFILE_VERSION_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"profileVersion\": 7", "\"profileVersion\": 9223372036854775808"),
                "LIMIT_EXCEEDED");
        assertCode(VALID_DOCUMENT.replace("\"profileVersion\": 7", "\"profileVersion\": 7.0"), "WRONG_TYPE");
        assertCode(VALID_DOCUMENT.replace("\"profileVersion\": 7", "\"profileVersion\": 7e0"), "WRONG_TYPE");
    }

    @Test
    void rejectsMissingLeafAndForbiddenCaConfirmationPolicies() {
        String leaf = canonical(parse(VALID_DOCUMENT));
        String confirmationPolicy = canonicalConfirmationPolicy();
        assertTrue(leaf.contains(confirmationPolicy));
        assertCode(leaf.replace(confirmationPolicy + ",", ""), "MISSING_FIELD");

        String ca = canonical(caDefinition("confirmation-ca", CertificateProfileKind.ROOT_CA, 1));
        assertCode(ca.replace("\"subject\":", confirmationPolicy + ",\"subject\":"),
                "FIELD_FORBIDDEN_FOR_CERTIFICATE_TYPE");
    }

    @Test
    void rejectsMalformedOrUncommittedConfirmationPolicyFields() {
        String document = canonical(parse(VALID_DOCUMENT));
        assertCode(document.replace("\"confirmationPolicy\":{",
                "\"confirmationPolicy\":{\"unknown\":true,"), "UNKNOWN_FIELD");
        assertCode(document.replace("\"disclosurePolicy\":\"OWNER_ONLY\",",
                "\"disclosurePolicy\":\"OWNER_ONLY\",\"disclosurePolicy\":\"OWNER_ONLY\","),
                "DUPLICATE_FIELD");
        assertCode(document.replace("\"proofSuiteId\":\"zeroecho.signature-pop.v1\",", ""),
                "MISSING_FIELD");
        assertCode(document.replace("\"confirmationWindow\":\"PT24H\"",
                "\"confirmationWindow\":true"), "WRONG_TYPE");
        assertCode(document.replace("zeroecho.signature-pop.v1", "ZeroEcho.signature-pop.v1"),
                "SEMANTIC_INVALID");
        assertCode(document.replace(
                "5ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11",
                "A322be16ba20d5be93e2e08c90716a87361dab4abc474e5643948199a9d129e7"),
                "SEMANTIC_INVALID");
        assertCode(document.replace(
                "4933b3d9a9dd31b972d5835884ed8ef9218f8d331928e6ac0feb802d28ab9a30",
                "0000000000000000000000000000000000000000000000000000000000000000"),
                "SEMANTIC_INVALID");
    }

    @Test
    void rejectsUnsupportedVersionsTokensCaseWhitespaceAndNoncanonicalDuration() {
        assertCode(VALID_DOCUMENT.replace("\"schemaVersion\": 5", "\"schemaVersion\": 1"),
                "SCHEMA_VERSION_UNSUPPORTED");
        assertCode(VALID_DOCUMENT.replace("\"certificateType\": \"END_ENTITY\"", "\"certificateType\": \"end_entity\""),
                "CERTIFICATE_TYPE_UNSUPPORTED");
        assertCode(VALID_DOCUMENT.replace("\"profileVersion\": 7", "\"profileVersion\": 0"), "PROFILE_VERSION_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"type\": \"DNS_NAME\"", "\"type\": \"dns_name\""), "TOKEN_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"source\": \"REQUESTER\"", "\"source\": \" REQUESTER\""), "TOKEN_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"profileId\": \"tls-service\"", "\"profileId\": \" tls-service\""),
                "TOKEN_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"formatId\": \"x509\"", "\"formatId\": \"x509 \""), "TOKEN_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"displayName\": \"TLS service\"", "\"displayName\": \" TLS service\""),
                "TOKEN_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"oid\": \"2.5.4.3\"", "\"oid\": \"2.5.4.999\""), "TOKEN_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"type\": \"DNS_NAME\"", "\"type\": \"OTHER_NAME\""), "TOKEN_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"DIGITAL_SIGNATURE\"", "\"CERTIFICATE_SIGN\""), "TOKEN_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"Ed448\"", "\"ed448\""), "TOKEN_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"1.3.6.1.5.5.7.3.2\"", "\"not-an-oid\""), "TOKEN_INVALID");
        for (String duration : List.of("P1D", "PT0S", "PT-1S", "one-day")) {
            assertCode(VALID_DOCUMENT.replace("\"maxValidity\": \"PT24H\"", "\"maxValidity\": \"" + duration + "\""),
                    "TOKEN_INVALID");
        }
    }

    @Test
    void rejectsTypeSpecificShapeViolationsAndSemanticInvariants() {
        assertCode(VALID_DOCUMENT.replace("\"wildcardAllowed\": true", "\"ipv4Allowed\": true"), "MISSING_FIELD");
        assertCode(VALID_DOCUMENT.replace("\"type\": \"RFC822_NAME\",",
                "\"type\": \"RFC822_NAME\",\"wildcardAllowed\": false,"), "UNKNOWN_FIELD");
        assertCode(VALID_DOCUMENT.replace("\"source\": \"REQUESTER\",",
                "\"source\": \"REQUESTER\",\"fixedValue\": \"forbidden\","), "UNKNOWN_FIELD");
        assertCode(VALID_DOCUMENT.replace(",\n        \"fixedValue\": \"ZeroEcho\"", ""), "MISSING_FIELD");
        assertCode(VALID_DOCUMENT.replace("\"allowEmpty\": false", "\"allowEmpty\": true")
                .replace("\"minimumTotal\": 1", "\"minimumTotal\": 0"), "SEMANTIC_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"ipv4Allowed\": true", "\"ipv4Allowed\": false")
                .replace("\"ipv6Allowed\": true", "\"ipv6Allowed\": false"), "SEMANTIC_INVALID");
        assertCode(VALID_DOCUMENT.replace(
                "\"keyUsage\": [\"KEY_AGREEMENT\", " + "\"ENCIPHER_ONLY\", \"DIGITAL_SIGNATURE\"]",
                "\"keyUsage\": [\"ENCIPHER_ONLY\"]"), "SEMANTIC_INVALID");

        String rich = canonical(parse(VALID_DOCUMENT));
        assertCode(rich.replace("\"oid\":\"2.5.4.10\"", "\"oid\":\"2.5.4.3\""), "SEMANTIC_INVALID");
        assertCode(replaceFirst(rich, "\"minimumOccurrences\":1", "\"minimumOccurrences\":2"), "SEMANTIC_INVALID");
        assertCode(replaceFirst(rich, "\"maximumOccurrences\":1", "\"maximumOccurrences\":33"), "SEMANTIC_INVALID");
        assertCode(rich.replace("\"minimumTotal\":1,\"maximumTotal\":4", "\"minimumTotal\":5,\"maximumTotal\":4"),
                "SEMANTIC_INVALID");
        assertCode(replaceFirst(rich, "\"minimumOccurrences\":0", "\"minimumOccurrences\":2"), "SEMANTIC_INVALID");
        String dnsRule = "{\"type\":\"DNS_NAME\",\"minimumOccurrences\":0,"
                + "\"maximumOccurrences\":1,\"wildcardAllowed\":true}";
        assertCode(rich.replace(dnsRule, dnsRule + "," + dnsRule), "SEMANTIC_INVALID");

        String uri = canonical(definition("uri-invalid", requesterCn(), uriSan(), eku(), Set.of("RSA")));
        assertCode(uri.replace("\"allowedSchemes\":[\"https\"]", "\"allowedSchemes\":[\"not a scheme\"]"),
                "SEMANTIC_INVALID");
        assertCode(uri.replace("\"allowedSchemes\":[\"https\"]", "\"allowedSchemes\":[\"https\",\"https\"]"),
                "TOKEN_INVALID");

        String dns = canonical(definition("dns-identity", requesterCn(), dnsSan(false, false), eku(), Set.of("RSA")));
        assertCode(dns.replace("\"emailIdentityRequired\":false", "\"emailIdentityRequired\":true"),
                "SEMANTIC_INVALID");
        String email = canonical(definition("service-identity", requesterCn(), emailSan(), eku(), Set.of("RSA")));
        assertCode(email.replace("\"serviceIdentityRequired\":false", "\"serviceIdentityRequired\":true"),
                "SEMANTIC_INVALID");
        String empty = canonical(definition("empty-invalid", new SubjectPolicy(true, List.of()), dnsSan(false, true),
                eku(), Set.of("RSA")));
        assertCode(empty.replace("\"minimumTotal\":1", "\"minimumTotal\":0"), "SEMANTIC_INVALID");
    }

    @Test
    void rejectsDuplicateSetLikeValues() {
        assertCode(VALID_DOCUMENT.replace("\"DIGITAL_SIGNATURE\"]", "\"DIGITAL_SIGNATURE\",\"DIGITAL_SIGNATURE\"]"),
                "SEMANTIC_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"1.3.6.1.5.5.7.3.1\"]", "\"1.3.6.1.5.5.7.3.1\",\"1.3.6.1.5.5.7.3.1\"]"),
                "SEMANTIC_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"Ed448\"]", "\"Ed448\",\"Ed448\"]"), "SEMANTIC_INVALID");
        assertCode(VALID_DOCUMENT.replace("\"spiffe\", \"https\"", "\"spiffe\", \"https\", \"https\""),
                "TOKEN_INVALID");
    }

    @Test
    void enforcesDocumentArrayAndUtf8StringBounds() {
        byte[] oversized = new byte[CertificateProfileDocumentCodec.MAXIMUM_DOCUMENT_BYTES + 1];
        assertCode(oversized, "PROFILE_DOCUMENT_TOO_LARGE");
        assertCode(new ByteArrayInputStream(oversized), "PROFILE_DOCUMENT_TOO_LARGE");

        String longProfileId = "a".repeat(129);
        assertCode(VALID_DOCUMENT.replace("tls-service", longProfileId), "LIMIT_EXCEEDED");
        assertEquals("a".repeat(128), parse(VALID_DOCUMENT.replace("tls-service", "a".repeat(128))).profileId());
        assertCode(VALID_DOCUMENT.replace("\"displayName\": \"TLS service\"",
                "\"displayName\": \"" + "d".repeat(257) + "\""), "LIMIT_EXCEEDED");
        assertEquals("d".repeat(256), parse(VALID_DOCUMENT.replace("\"displayName\": \"TLS service\"",
                "\"displayName\": \"" + "d".repeat(256) + "\"")).displayName());
        assertCode(VALID_DOCUMENT.replace("\"formatId\": \"x509\"", "\"formatId\": \"" + "f".repeat(129) + "\""),
                "LIMIT_EXCEEDED");
        assertEquals("f".repeat(128),
                parse(VALID_DOCUMENT.replace("\"formatId\": \"x509\"", "\"formatId\": \"" + "f".repeat(128) + "\""))
                        .formatId().value());
        assertCode(VALID_DOCUMENT.replace("\"spiffe\"", "\"" + "s".repeat(33) + "\""), "LIMIT_EXCEEDED");
        assertTrue(parse(VALID_DOCUMENT.replace("\"spiffe\"", "\"" + "s".repeat(32) + "\"")).leafPolicy()
                .subjectAlternativeNamePolicy().allowedUriSchemes().contains("s".repeat(32)));
        assertCode(
                VALID_DOCUMENT.replace("\"fixedValue\": \"ZeroEcho\"", "\"fixedValue\": \"" + "v".repeat(4_097) + "\""),
                "LIMIT_EXCEEDED");

        String schemes = IntStream.range(0, 129).mapToObj(index -> "\"a" + index + "\"")
                .reduce((left, right) -> left + "," + right).orElseThrow();
        assertCode(VALID_DOCUMENT.replace("\"spiffe\", \"https\"", schemes), "LIMIT_EXCEEDED");
    }

    @Test
    void enforcesDepthBeforeSchemaDispatch() {
        String document = "{\"unknown\":" + "[".repeat(17) + "0" + "]".repeat(17) + "}";

        assertCode(document, "LIMIT_EXCEEDED");
    }

    @Test
    void redactsHostileInputAndParserDetailsFromFailures() {
        String secret = "do-not-disclose-credential";
        String hostile = VALID_DOCUMENT.replace("\"schemaVersion\": 5,",
                "\"" + secret + "\": true,\"schemaVersion\": 5,");

        PkiException exception = assertThrows(PkiException.class, () -> parse(hostile));

        assertFalse(exception.getMessage().contains(secret));
        assertNull(exception.getCause());
        assertEquals(0, exception.getSuppressed().length);
        assertTrue(exception.getMessage()
                .startsWith("Certificate profile document rejected: code=UNKNOWN_FIELD path=$.?"));
    }

    @Test
    void rejectsPolymorphicMetadataWithoutLoadingClassesOrLoggingInput() {
        String probeName = "zeroecho.pki.api.profile.CertificateProfileDocumentCodecTest" + "$InitializationProbe";
        List<String> hostileFields = List.of("@class", "class", "typeName", "java.lang.Runtime");
        Logger logger = Logger.getLogger(CertificateProfileDocumentCodec.class.getName());
        List<LogRecord> records = new ArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                records.add(record);
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        logger.addHandler(handler);
        try {
            for (String field : hostileFields) {
                String document = VALID_DOCUMENT.replace("\"schemaVersion\": 5,",
                        "\"" + field + "\":\"" + probeName + "\",\"schemaVersion\": 5,");
                PkiException exception = assertThrows(PkiException.class, () -> parse(document));
                assertTrue(exception.getMessage().contains("code=UNKNOWN_FIELD "));
                assertFalse(exception.getMessage().contains(field));
                assertNull(exception.getCause());
                assertEquals(0, exception.getSuppressed().length);
            }
        } finally {
            logger.removeHandler(handler);
        }
        assertFalse(initializationProbe);
        assertTrue(records.isEmpty());
    }

    private static CertificateProfileDefinition parse(String document) {
        return CertificateProfileDocumentCodec.parse(bytes(document));
    }

    private static String canonical(CertificateProfileDefinition definition) {
        return new String(CertificateProfileDocumentCodec.writeCanonical(definition), StandardCharsets.UTF_8);
    }

    private static String canonicalConfirmationPolicy() {
        return "\"confirmationPolicy\":{\"disclosurePolicy\":\"OWNER_ONLY\","
                + "\"confirmationWindow\":\"PT24H\",\"proofSuiteId\":\"zeroecho.signature-pop.v1\","
                + "\"proofSuiteCommitment\":"
                + "\"5ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11\","
                + "\"policyCommitment\":"
                + "\"4933b3d9a9dd31b972d5835884ed8ef9218f8d331928e6ac0feb802d28ab9a30\"}";
    }

    private static CertificateProfileDefinition definition(String id, SubjectPolicy subject,
            SubjectAlternativeNamePolicy san, Set<ExtendedKeyUsageId> extendedKeyUsages, Set<String> algorithms) {
        LeafCertificatePolicy leaf = new LeafCertificatePolicy(san, Set.of(LeafKeyUsage.DIGITAL_SIGNATURE),
                extendedKeyUsages, true, false, true, algorithms);
        return new CertificateProfileDefinition(CertificateProfileKind.END_ENTITY, id, 1, new FormatId("x509"), id,
                Duration.ofDays(1), subject, leaf, X509AlgorithmBindingPolicy.standardOnly(),
                Optional.of(confirmationPolicy()));
    }

    private static CredentialConfirmationPolicy confirmationPolicy() {
        return new CredentialConfirmationPolicy(ConfirmationDisclosurePolicy.OWNER_ONLY,
                Duration.ofHours(24L), new ConfirmationProofSuiteRef("zeroecho.signature-pop.v1",
                        "5ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11"));
    }

    private static CertificateProfileDefinition caDefinition(String id, CertificateProfileKind kind, int pathLength) {
        SubjectPolicy subject = new SubjectPolicy(false,
                List.of(new SubjectRdnRule(SubjectRdnType.COMMON_NAME, 1, 1, 253, Optional.empty(), true)));
        CaCertificatePolicy ca = new CaCertificatePolicy(true, pathLength, true,
                Set.of(CaKeyUsage.KEY_CERT_SIGN, CaKeyUsage.CRL_SIGN), Set.of("RSA"));
        return new CertificateProfileDefinition(kind, id, 1, new FormatId("x509"), id, Duration.ofDays(365), subject,
                ca);
    }

    private static SubjectPolicy requesterCn() {
        return new SubjectPolicy(false,
                List.of(new SubjectRdnRule(SubjectRdnType.COMMON_NAME, 1, 1, 128, Optional.empty(), true)));
    }

    private static SubjectPolicy fixedOrganization() {
        return new SubjectPolicy(false, List
                .of(new SubjectRdnRule(SubjectRdnType.ORGANIZATION_NAME, 1, 1, 64, Optional.of("ZeroEcho"), false)));
    }

    private static SubjectAlternativeNamePolicy noSan() {
        return new SubjectAlternativeNamePolicy(0, 0, List.of(), false, Set.of(), false, false, false);
    }

    private static SubjectAlternativeNamePolicy dnsSan(boolean wildcard, boolean emptySubject) {
        return new SubjectAlternativeNamePolicy(1, 1,
                List.of(new SubjectAlternativeNameRule(SubjectAlternativeNameType.DNS_NAME, 1, 1, false, false)),
                wildcard, Set.of(), emptySubject, true, false);
    }

    private static SubjectAlternativeNamePolicy ipSan(boolean ipv4, boolean ipv6) {
        return new SubjectAlternativeNamePolicy(1, 1,
                List.of(new SubjectAlternativeNameRule(SubjectAlternativeNameType.IP_ADDRESS, 1, 1, ipv4, ipv6)), false,
                Set.of(), false, true, false);
    }

    private static SubjectAlternativeNamePolicy uriSan() {
        return new SubjectAlternativeNamePolicy(1, 1,
                List.of(new SubjectAlternativeNameRule(SubjectAlternativeNameType.URI, 1, 1, false, false)), false,
                Set.of("https"), false, true, false);
    }

    private static SubjectAlternativeNamePolicy emailSan() {
        return new SubjectAlternativeNamePolicy(1, 1,
                List.of(new SubjectAlternativeNameRule(SubjectAlternativeNameType.RFC822_NAME, 1, 1, false, false)),
                false, Set.of(), false, false, true);
    }

    private static SubjectAlternativeNamePolicy mixedSan() {
        return new SubjectAlternativeNamePolicy(0, 4,
                List.of(new SubjectAlternativeNameRule(SubjectAlternativeNameType.DNS_NAME, 0, 1, false, false),
                        new SubjectAlternativeNameRule(SubjectAlternativeNameType.IP_ADDRESS, 0, 1, true, true),
                        new SubjectAlternativeNameRule(SubjectAlternativeNameType.RFC822_NAME, 0, 1, false, false),
                        new SubjectAlternativeNameRule(SubjectAlternativeNameType.URI, 0, 1, false, false)),
                false, Set.of("https"), false, false, false);
    }

    private static Set<ExtendedKeyUsageId> eku() {
        return Set.of(new ExtendedKeyUsageId("1.3.6.1.5.5.7.3.1"));
    }

    private static String replaceFirst(String value, String target, String replacement) {
        int index = value.indexOf(target);
        if (index < 0) {
            throw new AssertionError("Test fixture value not found: " + target);
        }
        return value.substring(0, index) + replacement + value.substring(index + target.length());
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static void assertCode(String document, String code) {
        assertCode(bytes(document), code);
    }

    private static void assertCode(byte[] document, String code) {
        PkiException exception = assertThrows(PkiException.class,
                () -> CertificateProfileDocumentCodec.parse(document));
        assertTrue(exception.getMessage().contains("code=" + code + " "), exception.getMessage());
        assertNull(exception.getCause());
    }

    private static void assertCode(ByteArrayInputStream input, String code) {
        PkiException exception = assertThrows(PkiException.class, () -> CertificateProfileDocumentCodec.parse(input));
        assertTrue(exception.getMessage().contains("code=" + code + " "), exception.getMessage());
    }

    private static void assertWriteCode(CertificateProfileDefinition definition, String code) {
        PkiException exception = assertThrows(PkiException.class,
                () -> CertificateProfileDocumentCodec.writeCanonical(definition));
        assertTrue(exception.getMessage().contains("code=" + code + " "), exception.getMessage());
        assertNull(exception.getCause());
        assertEquals(0, exception.getSuppressed().length);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int start = 0; start <= haystack.length - needle.length; start++) {
            boolean matches = true;
            for (int offset = 0; offset < needle.length; offset++) {
                matches &= haystack[start + offset] == needle[offset];
            }
            if (matches) {
                return start;
            }
        }
        throw new AssertionError("Test fixture value not found");
    }

    private static final class TrackingInputStream extends ByteArrayInputStream {
        private boolean closed;

        private TrackingInputStream(byte[] buffer) {
            super(buffer);
        }

        @Override
        public void close() {
            closed = true;
        }
    }

    private static final class InitializationProbe {
        static {
            initializationProbe = true;
        }

        private InitializationProbe() {
        }
    }
}
