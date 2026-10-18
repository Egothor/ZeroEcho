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
package zeroecho.pki.server.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import zeroecho.pki.server.AdministrativeOperation;
import zeroecho.pki.server.OperationSecurityDescriptors;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.ServerControlOperation;
import zeroecho.pki.application.PkiOperation;

/** Strict HTTPS decoding coverage for the closed server-control operation family. */
class HttpServerControlOperationCodecTest {
    private static final RealmId REALM = new RealmId("production");
    private static final OperationSecurityDescriptors DESCRIPTORS = new OperationSecurityDescriptors();

    @Test void enrollmentDecisionsRequireExactReviewedCommitmentAndClosedArguments() {
        for (String name : java.util.List.of("enrollment.request.approve", "enrollment.request.reject")) {
            String json = "{\"version\":1,\"arguments\":{\"id\":\"enrollment:fixture\",\"expectedCommitment\":\""
                    + "a".repeat(64) + "\",\"justification\":\"Reviewed identity\"}}";
            ServerControlOperation.DecideEnrollmentRequest decision = assertInstanceOf(ServerControlOperation.DecideEnrollmentRequest.class,
                    assertInstanceOf(AdministrativeOperation.Control.class, decode(name, json).operation()).operation());
            assertEquals(name.endsWith("approve") ? zeroecho.pki.server.ApprovalService.Choice.APPROVE : zeroecho.pki.server.ApprovalService.Choice.REJECT, decision.choice());
            assertEquals(zeroecho.pki.server.Permission.ResourceType.ENROLLMENT_REQUEST, DESCRIPTORS.require(name).resourceType());
            assertThrows(IllegalArgumentException.class, () -> decode(name, json.replace("\"expectedCommitment\"", "\"ignoredCommitment\"")));
            assertThrows(IllegalArgumentException.class, () -> decode(name, json.replace("Reviewed identity", "x".repeat(2049))));
            assertThrows(IllegalArgumentException.class, () -> decode(name, json.replace("\"id\":", "\"requester\":\"admin\",\"id\":")));
        }
        assertInstanceOf(ServerControlOperation.InspectEnrollmentRequest.class, assertInstanceOf(AdministrativeOperation.Control.class,
                decode("enrollment.request.inspect", "{\"version\":1,\"arguments\":{\"id\":\"enrollment:fixture\"}}").operation()).operation());
        assertInstanceOf(ServerControlOperation.ListEnrollmentRequests.class, assertInstanceOf(AdministrativeOperation.Control.class,
                decode("enrollment.request.list", "{\"version\":1,\"arguments\":{\"offset\":0,\"limit\":10}}").operation()).operation());
    }

    @Test void legacyArchiveLimitIsCheckedBeforeDecodingAndForNestedApproval() {
        String payload = "A".repeat(4 * ((zeroecho.pki.api.backup.BackupLimits.defaults().legacyBytes() + 2) / 3) + 4);
        String arguments = "{\"backupId\":\"fixture\",\"payload\":\"" + payload + "\"}";
        String direct = "{\"version\":1,\"arguments\":" + arguments + "}";
        assertThrows(HttpOperationCodec.LegacyBackupLimitException.class, () -> HttpOperationCodec.decode(
                "backup.verify", direct.getBytes(StandardCharsets.UTF_8), direct.length(), REALM, DESCRIPTORS::require));
        String nested = "{\"version\":1,\"arguments\":{\"approvalId\":\"fixture\","
                + "\"targetOperation\":\"backup.verify\",\"targetArguments\":" + arguments + "}}";
        IllegalArgumentException approvalLimit = assertThrows(IllegalArgumentException.class, () -> HttpOperationCodec.decode(
                "security.approval.request", nested.getBytes(StandardCharsets.UTF_8), nested.length(), REALM, DESCRIPTORS::require));
        assertEquals(IllegalArgumentException.class, approvalLimit.getClass());
        IllegalArgumentException otherLimit = assertThrows(IllegalArgumentException.class, () -> HttpOperationCodec.decode(
                "profile.validate", direct.getBytes(StandardCharsets.UTF_8), direct.length(), REALM, DESCRIPTORS::require));
        assertEquals(IllegalArgumentException.class, otherLimit.getClass());
    }

    @Test
    void selectionControlQueriesUseBoundedRealmInputAndExactPermissionDescriptors() {
        HttpOperationCodec.Decoded configuration = decode(ServerControlOperation.ConfigurationChoices.NAME,
                "{\"version\":1,\"arguments\":{\"limit\":10,\"after\":\"local:key.prv\"}}");
        assertInstanceOf(ServerControlOperation.ConfigurationChoices.class,
                ((zeroecho.pki.server.AdministrativeOperation.Control) configuration.operation()).operation());
        HttpOperationCodec.Decoded capability = decode(ServerControlOperation.ListCapabilities.NAME,
                "{\"version\":1,\"arguments\":{\"objectId\":\"credential-a\",\"limit\":10,\"after\":\"cap-a\"}}");
        assertInstanceOf(ServerControlOperation.ListCapabilities.class,
                ((zeroecho.pki.server.AdministrativeOperation.Control) capability.operation()).operation());
        assertEquals(zeroecho.pki.server.Permission.Action.SERVER_CONFIGURATION_READ,
                DESCRIPTORS.require(ServerControlOperation.ConfigurationChoices.NAME).action());
        assertEquals(zeroecho.pki.server.Permission.Action.DISCLOSURE_READ,
                DESCRIPTORS.require(ServerControlOperation.ListCapabilities.NAME).action());
        for (int limit : new int[] {0, 1001}) {
            assertThrows(IllegalArgumentException.class, () -> decode(ServerControlOperation.ConfigurationChoices.NAME,
                    "{\"version\":1,\"arguments\":{\"limit\":" + limit + "}}"));
        }
        assertThrows(IllegalArgumentException.class, () -> decode(ServerControlOperation.ConfigurationChoices.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"limit\":1}}"));
        assertThrows(IllegalArgumentException.class, () -> decode(ServerControlOperation.ListCapabilities.NAME,
                "{\"version\":1,\"arguments\":{\"objectId\":\"credential-a\",\"limit\":1,\"after\":\"bad cursor\"}}"));
        assertThrows(IllegalArgumentException.class, () -> decode(ServerControlOperation.ConfigurationChoices.NAME,
                "{\"version\":1,\"arguments\":{\"limit\":1,\"providerOptions\":{}}}"));
    }

    @Test
    void decodesPrincipalRegistrationIntoClosedControlType() {
        System.out.println("decodesPrincipalRegistrationIntoClosedControlType");
        String json = "{\"version\":1,\"arguments\":{\"principalId\":\"operator-a\","
                + "\"type\":\"USER\",\"displayName\":\"Operator A\",\"enabled\":true}}";
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.RegisterPrincipal.NAME, json);
        AdministrativeOperation.Control family = assertInstanceOf(AdministrativeOperation.Control.class,
                decoded.operation());
        ServerControlOperation.RegisterPrincipal operation = assertInstanceOf(
                ServerControlOperation.RegisterPrincipal.class, family.operation());
        assertEquals("operator-a", operation.principal().principalId());
        System.out.println("...family=SERVER_CONTROL_OPERATION");
        System.out.println("...ok");
    }

    @Test
    void rejectsUnknownControlArgumentBeforeGatewayInvocation() {
        System.out.println("rejectsUnknownControlArgumentBeforeGatewayInvocation");
        String json = "{\"version\":1,\"arguments\":{\"principalId\":\"operator-a\","
                + "\"unexpected\":true}}";
        assertThrows(IllegalArgumentException.class,
                () -> decode(ServerControlOperation.InspectPrincipal.NAME, json));
        System.out.println("...unknown-field=rejected");
        System.out.println("...ok");
    }

    @Test
    void capabilityIssuanceDecodesWithoutBinaryOrTokenInput() {
        System.out.println("capabilityIssuanceDecodesWithoutBinaryOrTokenInput");
        String json = "{\"version\":1,\"arguments\":{\"objectId\":\"credential-a\","
                + "\"expiresAt\":\"2026-08-04T12:10:00Z\"}}";
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.IssueCapability.NAME, json);
        ServerControlOperation.IssueCapability operation = assertInstanceOf(
                ServerControlOperation.IssueCapability.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());
        assertEquals("credential-a", operation.objectId().value());
        System.out.println("...request-token-fields=0");
        System.out.println("...ok");
    }

    @Test
    void decodesExplicitCredentialPublicationEnrollmentWithoutPolicyInputs() {
        String json = "{\"version\":1,\"arguments\":{\"credentialId\":\"credential-a\","
                + "\"ownerPrincipalId\":\"owner-a\"}}";

        HttpOperationCodec.Decoded decoded = decode(
                ServerControlOperation.EnrollCredentialPublication.NAME, json);
        ServerControlOperation.EnrollCredentialPublication operation = assertInstanceOf(
                ServerControlOperation.EnrollCredentialPublication.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());

        assertEquals("credential-a", operation.credentialId().value());
        assertEquals("owner-a", operation.ownerPrincipalId().orElseThrow());
        assertEquals("credential-a", decoded.resource().objectId().orElseThrow().value());
        assertEquals(java.util.Optional.empty(), decoded.resource().scope().authorityId());
        assertThrows(IllegalArgumentException.class, () -> decode(
                ServerControlOperation.EnrollCredentialPublication.NAME,
                "{\"version\":1,\"arguments\":{\"credentialId\":\"credential-a\","
                        + "\"policy\":\"PUBLIC\"}}"));
        assertThrows(IllegalArgumentException.class, () -> decode(
                ServerControlOperation.EnrollCredentialPublication.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{"
                        + "\"credentialId\":\"credential-a\"}}"));
    }

    @Test
    void decodesDirectoryRegistrationWithoutClientSelectedConfirmationPolicy() {
        System.out.println("decodesDirectoryRegistrationWithoutClientSelectedConfirmationPolicy");
        String json = "{\"version\":1,\"authorityId\":\"ca:internal\",\"arguments\":{"
                + "\"alias\":\"internal\",\"authorityId\":\"ca:internal\",\"profileId\":\"tls\",\"enrollmentProfileId\":\"enrollment-tls\","
                + "\"dnsNamespaces\":[\"example.test\"],\"maximumValidityMillis\":86400000,"
                + "\"publicKeyAlgorithms\":[\"ECDSA\"],\"x509BindingPolicies\":[\"STANDARD_ONLY\"],"
                + "\"challengeTypes\":[\"DNS_01\"],\"challengeProviderIds\":[\"zeroecho.dns-01.jndi.v1\"],"
                + "\"eabRequired\":false}}";
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.RegisterAcmeDirectory.NAME, json);
        ServerControlOperation.RegisterAcmeDirectory operation = assertInstanceOf(
                ServerControlOperation.RegisterAcmeDirectory.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());
        assertEquals("internal", operation.registration().alias());
        assertEquals("tls", operation.registration().profileId());
        assertThrows(IllegalArgumentException.class, () -> decode(
                ServerControlOperation.RegisterAcmeDirectory.NAME,
                json.replace("\"eabRequired\":false", "\"eabRequired\":false,"
                        + "\"disclosurePolicy\":\"OWNER_ONLY\"")));
        assertThrows(IllegalArgumentException.class, () -> decode(
                ServerControlOperation.RegisterAcmeDirectory.NAME,
                json.replace("\"eabRequired\":false", "\"eabRequired\":false,"
                        + "\"expectedProfileVersion\":1,\"expectedPolicyCommitment\":\""
                        + "1".repeat(64) + "\"")));
        System.out.println("...directory-policy=profile-owned");
        System.out.println("...ok");
    }

    @Test
    void decodesBoundedAuthorityScopedPendingConfirmationQuery() {
        String json = "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{"
                + "\"profileId\":\"server-tls\","
                + "\"cutoffInclusive\":\"2026-08-30T12:00:00Z\",\"limit\":100}}";
        HttpOperationCodec.Decoded decoded = decode(
                PkiOperation.ListPendingCredentialConfirmations.NAME, json);
        PkiOperation.ListPendingCredentialConfirmations operation = assertInstanceOf(
                PkiOperation.ListPendingCredentialConfirmations.class,
                ((AdministrativeOperation.Pki) decoded.operation()).operation());
        assertEquals("ca-a", operation.authorityId().value());
        assertEquals("server-tls", operation.profileId().orElseThrow());
        assertEquals(java.util.Optional.empty(), operation.afterExclusive());
        assertEquals(java.util.Optional.of("server-tls"), decoded.resource().scope().profileId());
        assertEquals(java.util.Optional.empty(), decoded.resource().objectId());
        OperationSecurityDescriptors.Descriptor descriptor = DESCRIPTORS.require(operation.name());
        assertEquals(zeroecho.pki.server.Permission.Action.CERTIFICATE_SEARCH, descriptor.action());
        assertEquals(zeroecho.pki.server.Permission.DataView.METADATA_REDACTED, descriptor.dataView());
        assertEquals(OperationSecurityDescriptors.ApprovalCategory.NONE, descriptor.approvalCategory());

        assertThrows(IllegalArgumentException.class, () -> decode(
                PkiOperation.ListPendingCredentialConfirmations.NAME,
                "{\"version\":1,\"arguments\":{\"cutoffInclusive\":"
                        + "\"2026-08-30T12:00:00Z\",\"limit\":100}}"));
        assertThrows(IllegalArgumentException.class, () -> decode(
                PkiOperation.ListPendingCredentialConfirmations.NAME,
                json.replace("\"limit\":100", "\"limit\":1001")));
        assertThrows(IllegalArgumentException.class, () -> decode(
                PkiOperation.ListPendingCredentialConfirmations.NAME,
                json.replace("\"limit\":100", "\"afterExclusive\":\"bad!\",\"limit\":100")));
    }

    @Test
    void decodesChallengeIssuanceWithOnlyCredentialAndMandatoryOuterAuthority() {
        String json = "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{"
                + "\"credentialId\":\"credential-a\"}}";
        HttpOperationCodec.Decoded decoded = decode(
                PkiOperation.IssueCredentialConfirmationChallenge.NAME, json);
        PkiOperation.IssueCredentialConfirmationChallenge operation = assertInstanceOf(
                PkiOperation.IssueCredentialConfirmationChallenge.class,
                ((AdministrativeOperation.Pki) decoded.operation()).operation());
        assertEquals("credential-a", operation.credentialId().value());
        assertEquals("ca-a", decoded.resource().scope().authorityId().orElseThrow().value());
        assertEquals(java.util.Optional.empty(), decoded.resource().scope().profileId());
        assertEquals("credential-a", decoded.resource().objectId().orElseThrow().value());
        OperationSecurityDescriptors.Descriptor descriptor = DESCRIPTORS.require(operation.name());
        assertEquals(zeroecho.pki.server.Permission.Action.CERTIFICATE_PUBLICATION_CHANGE,
                descriptor.action());
        assertEquals(zeroecho.pki.server.Permission.DataView.METADATA_REDACTED,
                descriptor.dataView());
        assertEquals(true, descriptor.mutating());
        assertEquals(OperationSecurityDescriptors.ApprovalCategory.NONE,
                descriptor.approvalCategory());

        assertThrows(IllegalArgumentException.class, () -> decode(
                PkiOperation.IssueCredentialConfirmationChallenge.NAME,
                "{\"version\":1,\"arguments\":{\"credentialId\":\"credential-a\"}}"));
        assertThrows(IllegalArgumentException.class, () -> decode(
                PkiOperation.IssueCredentialConfirmationChallenge.NAME,
                json.replace("\"credentialId\":\"credential-a\"",
                        "\"credentialId\":\"credential-a\",\"nonce\":\"forbidden\"")));
    }

    @Test
    void decodesOnlyCanonicalBoundedProofCompletionResponse() {
        byte[] maximum = new byte[zeroecho.pki.spi.confirmation.KeyPossessionProofResponse.MAXIMUM_BYTES];
        Arrays.fill(maximum, (byte) 0xa5);
        String canonical = Base64.getUrlEncoder().withoutPadding().encodeToString(maximum);
        assertEquals(PkiServerConfiguration.Listener.MAXIMUM_PROOF_RESPONSE_BASE64URL_CHARACTERS,
                canonical.length());

        HttpOperationCodec.Decoded decoded = decode(
                PkiOperation.CompleteCredentialConfirmationProof.NAME, completionJson(canonical));
        PkiOperation.CompleteCredentialConfirmationProof operation = assertInstanceOf(
                PkiOperation.CompleteCredentialConfirmationProof.class,
                ((AdministrativeOperation.Pki) decoded.operation()).operation());
        assertArrayEquals(maximum, operation.submission().response());
        assertEquals("credential-a", operation.submission().proofCas().credentialId().value());
        assertEquals(java.util.Optional.of("ca-a"), decoded.resource().scope().authorityId()
                .map(zeroecho.pki.api.PkiId::value));

        byte[] over = new byte[maximum.length + 1];
        assertThrows(IllegalArgumentException.class, () -> decode(
                PkiOperation.CompleteCredentialConfirmationProof.NAME,
                completionJson(Base64.getUrlEncoder().withoutPadding().encodeToString(over))));
        for (String invalid : java.util.List.of("", "AQ==", "AQ ", "+A", "AR",
                "A".repeat(PkiServerConfiguration.Listener.MAXIMUM_PROOF_RESPONSE_BASE64URL_CHARACTERS + 1))) {
            assertThrows(IllegalArgumentException.class, () -> decode(
                    PkiOperation.CompleteCredentialConfirmationProof.NAME, completionJson(invalid)));
        }
        assertThrows(IllegalArgumentException.class, () -> decode(
                PkiOperation.CompleteCredentialConfirmationProof.NAME,
                completionJson("AQ").replace("\"response\":\"AQ\"",
                        "\"response\":\"AQ\",\"nonce\":\"forbidden\"")));
    }

    @Test
    void decodesApprovalObjectWithPreviouslyOmittedCaState() {
        String json = """
                {"version":1,"arguments":{"approvalId":"approval-a","targetOperation":"ca.transition",
                "targetAuthorityId":"ca-a","targetArguments":{"caId":"ca-a","state":"DISABLED","reason":"fixture"}}}
                """;
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.RequestApproval.NAME, json);
        assertInstanceOf(ServerControlOperation.RequestApproval.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());
        assertThrows(IllegalArgumentException.class, () -> decode(ServerControlOperation.RequestApproval.NAME,
                json.replace("\"targetArguments\":{", "\"targetArguments\":{\"unknown\":true,")));
        assertEquals(zeroecho.pki.server.schema.OperationParameterSchema.FieldType.OBJECT,
                zeroecho.pki.server.schema.OperationDescriptorCatalog.current()
                        .require(ServerControlOperation.RequestApproval.NAME).parameters().fields().stream()
                        .filter(field -> field.name().equals("targetArguments")).findFirst().orElseThrow().type());
    }

    @Test
    void decodesOcspRequesterPolicyObjectWithoutFlatteningAuthorityScope() {
        String json = """
                {"version":1,"arguments":{
                "responderId":"responder-a","alias":"responder-a","authorityId":"ca-a","issuerId":"issuer-a",
                "signingMode":"ISSUER_SIGNED","responderCredentialId":"credential-a","signingKeyRef":"key-a",
                "chainPathId":"chain-a","signatureAlgorithm":"SHA256withRSA","signatureBindingCommitment":"%s",
                "responderIdForm":"BY_NAME","responseValidityMillis":60000,"noncePolicy":"OPTIONAL_ECHO",
                "maximumNonceBytes":32,"acceptedHashes":["SHA256"],"maximumRequestBytes":65536,
                "maximumEntries":10,"cacheLifetimeMillis":1000,"requestAuthenticationMode":"AUTHORIZED_SIGNED_REQUIRED",
                "requesterTrustPolicy":{
                "trustSelectors":[{"type":"CONFIGURED_TRUST_ANCHORS","identities":["anchor-a"]}],
                "principalMappings":[{"mappingId":"mapping-a","principalId":"requester-a",
                "type":"SHA256_CERTIFICATE_COMMITMENT","commitment":"%s"}],
                "signatureBindings":[{"bindingId":"binding-a","commitment":"%s"}],
                "revocationPolicy":"VALIDITY_AND_TRUST_ONLY","maximumSignerCertificates":4,
                "maximumSignerChainBytes":65536}}}
                """.formatted("a".repeat(64), "b".repeat(64), "c".repeat(64));
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.RegisterOcspResponder.NAME, json);
        assertInstanceOf(ServerControlOperation.RegisterOcspResponder.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());
        assertEquals(java.util.Optional.of(new zeroecho.pki.api.PkiId("ca-a")), decoded.resource().scope().authorityId());
        assertEquals("realm", zeroecho.pki.server.schema.OperationDescriptorCatalog.current()
                .require(ServerControlOperation.RegisterOcspResponder.NAME).presentation().transport().scope());
        assertThrows(IllegalArgumentException.class, () -> decode(ServerControlOperation.RegisterOcspResponder.NAME,
                json.replace("\"requesterTrustPolicy\":{", "\"requesterTrustPolicy\":{\"unknown\":true,")));
        assertEquals(zeroecho.pki.server.schema.OperationParameterSchema.FieldType.OBJECT,
                zeroecho.pki.server.schema.OperationDescriptorCatalog.current()
                        .require(ServerControlOperation.RegisterOcspResponder.NAME).parameters().fields().stream()
                        .filter(field -> field.name().equals("requesterTrustPolicy")).findFirst().orElseThrow().type());
    }

    private static String completionJson(String response) {
        return "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{"
                + "\"credentialId\":\"credential-a\",\"expectedLifecycleRevision\":1,"
                + "\"expectedLifecycleRecordCommitment\":\"" + "a".repeat(64) + "\","
                + "\"expectedChallengeRecordCommitment\":\"" + "b".repeat(64) + "\","
                + "\"response\":\"" + response + "\"}}";
    }

    private static HttpOperationCodec.Decoded decode(String operation, String json) {
        return HttpOperationCodec.decode(operation, json.getBytes(StandardCharsets.UTF_8),
                PkiServerConfiguration.Listener.MINIMUM_BODY_BYTES,
                REALM, DESCRIPTORS::require);
    }
}
