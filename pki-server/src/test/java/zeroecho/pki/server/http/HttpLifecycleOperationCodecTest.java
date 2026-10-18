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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiSigningOperation;
import zeroecho.pki.server.AdministrativeOperation;
import zeroecho.pki.server.OperationSecurityDescriptors;
import zeroecho.pki.server.Permission;
import zeroecho.pki.server.RealmId;

/** Strict HTTP decoding coverage for the credential and CA lifecycle operations. */
class HttpLifecycleOperationCodecTest {
    private static final RealmId REALM = new RealmId("production");
    private static final OperationSecurityDescriptors DESCRIPTORS = new OperationSecurityDescriptors();

    @Test
    void decodesRenewAsAuthorityScopedCredentialOperation() {
        HttpOperationCodec.Decoded decoded = decode(PkiSigningOperation.RenewCredential.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"credentialId\":\"credential-a\"}}");
        PkiSigningOperation.RenewCredential operation = assertInstanceOf(PkiSigningOperation.RenewCredential.class, pki(decoded));
        assertEquals(new PkiId("credential-a"), operation.credentialId());
        assertEquals(Optional.of(new PkiId("credential-a")), decoded.resource().objectId());
        assertEquals(Optional.of(new PkiId("ca-a")), decoded.resource().scope().authorityId());
        assertEquals(Permission.ResourceType.CERTIFICATE, decoded.resource().type());
    }

    @Test
    void decodesReplaceWithProfileScope() {
        HttpOperationCodec.Decoded decoded = decode(PkiSigningOperation.ReplaceCredential.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"existingCredentialId\":\"credential-a\","
                        + "\"requestId\":\"request-a\",\"profileId\":\"leaf\"}}");
        PkiSigningOperation.ReplaceCredential operation =
                assertInstanceOf(PkiSigningOperation.ReplaceCredential.class, pki(decoded));
        assertEquals(new PkiId("credential-a"), operation.existingCredentialId());
        assertEquals(new PkiId("request-a"), operation.requestId());
        assertEquals("leaf", operation.profileId());
        assertEquals(Optional.of(new PkiId("credential-a")), decoded.resource().objectId());
        assertEquals(Optional.of("leaf"), decoded.resource().scope().profileId());
    }

    @Test
    void decodesReissue() {
        HttpOperationCodec.Decoded decoded = decode(PkiSigningOperation.ReissueCredential.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"credentialId\":\"credential-a\"}}");
        PkiSigningOperation.ReissueCredential operation =
                assertInstanceOf(PkiSigningOperation.ReissueCredential.class, pki(decoded));
        assertEquals(new PkiId("credential-a"), operation.credentialId());
        assertEquals(Optional.of(new PkiId("credential-a")), decoded.resource().objectId());
    }

    @Test
    void decodesRolloverAsSelfScopedAuthorityAndObject() {
        HttpOperationCodec.Decoded decoded = decode(PkiSigningOperation.RolloverCaCertificate.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"caId\":\"ca-a\"}}");
        PkiSigningOperation.RolloverCaCertificate operation =
                assertInstanceOf(PkiSigningOperation.RolloverCaCertificate.class, pki(decoded));
        assertEquals(new PkiId("ca-a"), operation.caId());
        assertEquals(Optional.empty(), operation.issuerCaId());
        assertEquals(Optional.of(new PkiId("ca-a")), decoded.resource().objectId());
        assertEquals(Optional.of(new PkiId("ca-a")), decoded.resource().scope().authorityId());
        assertEquals(Permission.ResourceType.AUTHORITY, decoded.resource().type());
    }

    @Test
    void decodesRotateWithNewKey() {
        HttpOperationCodec.Decoded decoded = decode(PkiSigningOperation.RotateCaKey.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"caId\":\"ca-a\","
                        + "\"newKeyRef\":\"kref:v1:keyring:test:rotated\"}}");
        PkiSigningOperation.RotateCaKey operation = assertInstanceOf(PkiSigningOperation.RotateCaKey.class, pki(decoded));
        assertEquals(new PkiId("ca-a"), operation.caId());
        assertEquals(Optional.of(new zeroecho.pki.api.KeyRef("kref:v1:keyring:test:rotated")), operation.newKeyRef());
        assertEquals(Optional.empty(), operation.issuerCaId());
    }

    @Test
    void rejectsRolloverWhenEnvelopeAuthorityDiffersFromCaId() {
        assertThrows(IllegalArgumentException.class, () -> decode(PkiSigningOperation.RolloverCaCertificate.NAME,
                "{\"version\":1,\"authorityId\":\"ca-b\",\"arguments\":{\"caId\":\"ca-a\"}}"));
    }

    @Test
    void decodesInspectRequestAsRealmWideRequestRead() {
        HttpOperationCodec.Decoded decoded = decode(PkiOperation.InspectRequest.NAME,
                "{\"version\":1,\"arguments\":{\"requestId\":\"request-a\"}}");
        PkiOperation.InspectRequest operation = assertInstanceOf(PkiOperation.InspectRequest.class, pki(decoded));
        assertEquals(new PkiId("request-a"), operation.requestId());
        assertEquals(Optional.of(new PkiId("request-a")), decoded.resource().objectId());
        assertEquals(Optional.empty(), decoded.resource().scope().authorityId());
        assertEquals(Permission.ResourceType.REQUEST, decoded.resource().type());
    }

    @Test
    void decodesImportRequestBase64Encoded() {
        HttpOperationCodec.Decoded decoded = decode(PkiOperation.ImportRequest.NAME,
                "{\"version\":1,\"arguments\":{\"formatId\":\"x509\",\"encoded\":\"AQID\"}}");
        PkiOperation.ImportRequest operation = assertInstanceOf(PkiOperation.ImportRequest.class, pki(decoded));
        assertEquals("x509", operation.formatId().value());
        assertEquals(3, operation.encoded().bytes().length);
        assertEquals(Optional.empty(), decoded.resource().objectId());
        assertEquals(Optional.empty(), decoded.resource().scope().authorityId());
    }

    @Test
    void rejectsImportRequestWithAuthorityId() {
        assertThrows(IllegalArgumentException.class, () -> decode(PkiOperation.ImportRequest.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"formatId\":\"x509\",\"encoded\":\"AQID\"}}"));
    }

    @Test
    void decodesRegisterProfileBase64Document() {
        HttpOperationCodec.Decoded decoded = decode(PkiOperation.RegisterProfile.NAME,
                "{\"version\":1,\"arguments\":{\"document\":\"AQID\"}}");
        PkiOperation.RegisterProfile operation = assertInstanceOf(PkiOperation.RegisterProfile.class, pki(decoded));
        assertEquals(3, operation.document().length);
        assertEquals(Permission.ResourceType.PROFILE, decoded.resource().type());
        assertEquals(Optional.empty(), decoded.resource().scope().authorityId());
    }

    @Test
    void decodesValidateConfigurationWithNoArguments() {
        HttpOperationCodec.Decoded decoded = decode(PkiOperation.ValidateConfiguration.NAME,
                "{\"version\":1,\"arguments\":{}}");
        assertInstanceOf(PkiOperation.ValidateConfiguration.class, pki(decoded));
        assertEquals(Permission.ResourceType.SERVER_CONFIGURATION, decoded.resource().type());
    }

    @Test
    void decodesValidateProfileDocumentAndRejectsAuthorityScope() {
        HttpOperationCodec.Decoded decoded = decode(PkiOperation.ValidateProfile.NAME,
                "{\"version\":1,\"arguments\":{\"document\":\"AQID\"}}");
        assertInstanceOf(PkiOperation.ValidateProfile.class, pki(decoded));
        assertThrows(IllegalArgumentException.class, () -> decode(PkiOperation.ValidateProfile.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"document\":\"AQID\"}}"));
    }

    @Test
    void decodesInspectRevocationAsAuthorityScopedCredentialObject() {
        HttpOperationCodec.Decoded decoded = decode(PkiOperation.InspectRevocation.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"credentialId\":\"credential-a\"}}");
        PkiOperation.InspectRevocation operation =
                assertInstanceOf(PkiOperation.InspectRevocation.class, pki(decoded));
        assertEquals(new PkiId("credential-a"), operation.credentialId());
        assertEquals(Optional.of(new PkiId("credential-a")), decoded.resource().objectId());
        assertEquals(Optional.of(new PkiId("ca-a")), decoded.resource().scope().authorityId());
        assertEquals(Permission.ResourceType.REVOCATION, decoded.resource().type());
    }

    @Test
    void decodesSnapshotRevocationsAsRealmWideLimit() {
        HttpOperationCodec.Decoded decoded = decode(PkiOperation.SnapshotRevocations.NAME,
                "{\"version\":1,\"arguments\":{\"limit\":50}}");
        PkiOperation.SnapshotRevocations operation =
                assertInstanceOf(PkiOperation.SnapshotRevocations.class, pki(decoded));
        assertEquals(50, operation.limit());
        assertEquals(Optional.empty(), decoded.resource().objectId());
        assertEquals(Optional.empty(), decoded.resource().scope().authorityId());
        assertThrows(IllegalArgumentException.class, () -> decode(PkiOperation.SnapshotRevocations.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"limit\":50}}"));
    }

    @Test
    void decodesInspectStatusAsRealmWideStatusObject() {
        HttpOperationCodec.Decoded decoded = decode(PkiOperation.InspectStatus.NAME,
                "{\"version\":1,\"arguments\":{\"statusObjectId\":\"status-a\"}}");
        PkiOperation.InspectStatus operation = assertInstanceOf(PkiOperation.InspectStatus.class, pki(decoded));
        assertEquals(new PkiId("status-a"), operation.statusObjectId());
        assertEquals(Optional.of(new PkiId("status-a")), decoded.resource().objectId());
        assertEquals(Optional.empty(), decoded.resource().scope().authorityId());
        assertEquals(Permission.ResourceType.STATUS_OBJECT, decoded.resource().type());
    }

    @Test
    void decodesListStatusAsAuthorityScopedIssuer() {
        HttpOperationCodec.Decoded decoded = decode(PkiOperation.ListStatus.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"issuerCaId\":\"ca-a\",\"limit\":25}}");
        PkiOperation.ListStatus operation = assertInstanceOf(PkiOperation.ListStatus.class, pki(decoded));
        assertEquals(new PkiId("ca-a"), operation.issuerCaId());
        assertEquals(25, operation.limit());
        assertEquals(Optional.empty(), decoded.resource().objectId());
        assertEquals(Optional.of(new PkiId("ca-a")), decoded.resource().scope().authorityId());
        assertThrows(IllegalArgumentException.class, () -> decode(PkiOperation.ListStatus.NAME,
                "{\"version\":1,\"authorityId\":\"ca-b\",\"arguments\":{\"issuerCaId\":\"ca-a\",\"limit\":25}}"));
    }

    @Test
    void decodesListPublicationsAsRealmWideLimit() {
        HttpOperationCodec.Decoded decoded = decode(PkiOperation.ListPublications.NAME,
                "{\"version\":1,\"arguments\":{\"limit\":100}}");
        PkiOperation.ListPublications operation =
                assertInstanceOf(PkiOperation.ListPublications.class, pki(decoded));
        assertEquals(100, operation.limit());
        assertEquals(Optional.empty(), decoded.resource().objectId());
        assertEquals(Optional.empty(), decoded.resource().scope().authorityId());
        assertEquals(Permission.ResourceType.PUBLICATION, decoded.resource().type());
    }

    @Test
    void decodesRegisterPublicationWithNestedTarget() {
        HttpOperationCodec.Decoded decoded = decode(PkiOperation.RegisterPublication.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"publicationId\":\"pub-a\","
                        + "\"sourceType\":\"CREDENTIAL\",\"sourceId\":\"credential-a\","
                        + "\"targetType\":\"FILESYSTEM\",\"targetId\":\"repo-a\"}}");
        PkiOperation.RegisterPublication operation =
                assertInstanceOf(PkiOperation.RegisterPublication.class, pki(decoded));
        assertEquals(new PkiId("pub-a"), operation.publicationId());
        assertEquals(zeroecho.pki.api.publication.PublicationSourceType.CREDENTIAL, operation.sourceType());
        assertEquals(new PkiId("credential-a"), operation.sourceId());
        assertEquals(zeroecho.pki.api.publication.PublicationTargetType.FILESYSTEM, operation.target().type());
        assertEquals("repo-a", operation.target().targetId());
        assertEquals(Optional.of(new PkiId("pub-a")), decoded.resource().objectId());
        assertEquals(Optional.of(new PkiId("ca-a")), decoded.resource().scope().authorityId());
    }

    @Test
    void decodesRetryAndReconcilePublicationAsAuthorityScopedObject() {
        HttpOperationCodec.Decoded retry = decode(PkiOperation.RetryPublication.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"publicationId\":\"pub-a\"}}");
        assertEquals(new PkiId("pub-a"),
                assertInstanceOf(PkiOperation.RetryPublication.class, pki(retry)).publicationId());
        assertEquals(Optional.of(new PkiId("pub-a")), retry.resource().objectId());
        assertEquals(Optional.of(new PkiId("ca-a")), retry.resource().scope().authorityId());
        HttpOperationCodec.Decoded reconcile = decode(PkiOperation.ReconcilePublication.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"publicationId\":\"pub-a\"}}");
        assertEquals(new PkiId("pub-a"),
                assertInstanceOf(PkiOperation.ReconcilePublication.class, pki(reconcile)).publicationId());
        assertEquals(Optional.of(new PkiId("pub-a")), reconcile.resource().objectId());
    }

    @Test
    void decodesCreateIntermediateAsAuthorityAndProfileScoped() {
        HttpOperationCodec.Decoded decoded = decode(PkiSigningOperation.CreateIntermediate.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"formatId\":\"x509\","
                        + "\"issuerCaId\":\"ca-a\",\"subjectRef\":\"CN=Intermediate\",\"profileId\":\"intermediate\","
                        + "\"keyRef\":\"kref:v1:keyring:test:im\"}}");
        PkiSigningOperation.CreateIntermediate operation =
                assertInstanceOf(PkiSigningOperation.CreateIntermediate.class, pki(decoded));
        assertEquals(new PkiId("ca-a"), operation.issuerCaId());
        assertEquals("intermediate", operation.profileId());
        assertEquals(Optional.of(new zeroecho.pki.api.KeyRef("kref:v1:keyring:test:im")), operation.keyRef());
        assertEquals(Optional.empty(), decoded.resource().objectId());
        assertEquals(Optional.of(new PkiId("ca-a")), decoded.resource().scope().authorityId());
        assertEquals(Optional.of("intermediate"), decoded.resource().scope().profileId());
        assertEquals(Permission.ResourceType.AUTHORITY, decoded.resource().type());
    }

    @Test
    void rejectsCreateIntermediateWithoutManagedKey() {
        assertThrows(IllegalArgumentException.class, () -> decode(PkiSigningOperation.CreateIntermediate.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"formatId\":\"x509\","
                        + "\"issuerCaId\":\"ca-a\",\"subjectRef\":\"CN=Intermediate\",\"profileId\":\"intermediate\"}}"));
    }

    @Test
    void decodesIssueIntermediateCertificateWithRequestedValidity() {
        HttpOperationCodec.Decoded decoded = decode(PkiSigningOperation.IssueIntermediateCertificate.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"formatId\":\"x509\","
                        + "\"issuerCaId\":\"ca-a\",\"subjectCaId\":\"ca-b\",\"profileId\":\"intermediate\","
                        + "\"notBefore\":\"2026-01-01T00:00:00Z\",\"notAfter\":\"2031-01-01T00:00:00Z\"}}");
        PkiSigningOperation.IssueIntermediateCertificate operation =
                assertInstanceOf(PkiSigningOperation.IssueIntermediateCertificate.class, pki(decoded));
        assertEquals(new PkiId("ca-a"), operation.issuerCaId());
        assertEquals(new PkiId("ca-b"), operation.subjectCaId());
        assertEquals(Optional.of(new zeroecho.pki.api.Validity(
                java.time.Instant.parse("2026-01-01T00:00:00Z"),
                java.time.Instant.parse("2031-01-01T00:00:00Z"))), operation.requestedValidity());
        assertEquals(Optional.of(new PkiId("ca-b")), decoded.resource().objectId());
        assertEquals(Optional.of(new PkiId("ca-a")), decoded.resource().scope().authorityId());
    }

    @Test
    void rejectsIssueIntermediateCertificateWithPartialValidity() {
        assertThrows(IllegalArgumentException.class, () -> decode(PkiSigningOperation.IssueIntermediateCertificate.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"formatId\":\"x509\","
                        + "\"issuerCaId\":\"ca-a\",\"subjectCaId\":\"ca-b\",\"profileId\":\"intermediate\","
                        + "\"notBefore\":\"2026-01-01T00:00:00Z\"}}"));
    }

    @Test
    void decodesInspectIssuerGenerationAsRealmWide() {
        HttpOperationCodec.Decoded decoded = decode(PkiOperation.InspectIssuerGeneration.NAME,
                "{\"version\":1,\"arguments\":{\"issuerId\":\"issuer:abc\"}}");
        PkiOperation.InspectIssuerGeneration operation =
                assertInstanceOf(PkiOperation.InspectIssuerGeneration.class, pki(decoded));
        assertEquals(new PkiId("issuer:abc"), operation.issuerId());
        assertEquals(Optional.of(new PkiId("issuer:abc")), decoded.resource().objectId());
        assertEquals(Optional.empty(), decoded.resource().scope().authorityId());
        assertEquals(Permission.ResourceType.ISSUER, decoded.resource().type());
    }

    @Test
    void decodesInspectAndListIssuerChainPaths() {
        HttpOperationCodec.Decoded inspect = decode(PkiOperation.InspectIssuerChainPath.NAME,
                "{\"version\":1,\"arguments\":{\"pathId\":\"path:abc\"}}");
        assertEquals(new PkiId("path:abc"),
                assertInstanceOf(PkiOperation.InspectIssuerChainPath.class, pki(inspect)).pathId());
        assertEquals(Optional.of(new PkiId("path:abc")), inspect.resource().objectId());
        HttpOperationCodec.Decoded list = decode(PkiOperation.ListIssuerChainPaths.NAME,
                "{\"version\":1,\"arguments\":{\"issuerId\":\"issuer:abc\"}}");
        assertEquals(new PkiId("issuer:abc"),
                assertInstanceOf(PkiOperation.ListIssuerChainPaths.class, pki(list)).issuerId());
        assertEquals(Optional.empty(), list.resource().scope().authorityId());
    }

    @Test
    void decodesSelectAndRegisterIssuancePathAsSelfScopedAuthority() {
        HttpOperationCodec.Decoded select = decode(PkiOperation.SelectIssuancePath.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"caId\":\"ca-a\","
                        + "\"issuerId\":\"issuer:abc\",\"pathId\":\"path:abc\",\"reason\":\"rotation\"}}");
        PkiOperation.SelectIssuancePath selectOp =
                assertInstanceOf(PkiOperation.SelectIssuancePath.class, pki(select));
        assertEquals(new PkiId("ca-a"), selectOp.caId());
        assertEquals("rotation", selectOp.reason());
        assertEquals(Optional.of(new PkiId("ca-a")), select.resource().objectId());
        assertEquals(Optional.of(new PkiId("ca-a")), select.resource().scope().authorityId());
        HttpOperationCodec.Decoded register = decode(PkiOperation.RegisterIssuerChainPath.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"caId\":\"ca-a\","
                        + "\"issuerId\":\"issuer:abc\",\"parentPathId\":\"path:parent\"}}");
        PkiOperation.RegisterIssuerChainPath registerOp =
                assertInstanceOf(PkiOperation.RegisterIssuerChainPath.class, pki(register));
        assertEquals(new PkiId("path:parent"), registerOp.parentPathId());
        assertEquals(Optional.of(new PkiId("ca-a")), register.resource().scope().authorityId());
    }

    @Test
    void rejectsCreateIntermediateWhenEnvelopeAuthorityDiffersFromIssuer() {
        assertThrows(IllegalArgumentException.class, () -> decode(PkiSigningOperation.CreateIntermediate.NAME,
                "{\"version\":1,\"authorityId\":\"ca-b\",\"arguments\":{\"formatId\":\"x509\","
                        + "\"issuerCaId\":\"ca-a\",\"subjectRef\":\"CN=Intermediate\",\"profileId\":\"intermediate\"}}"));
    }

    @Test
    void rejectsUnknownArgumentForRenew() {
        assertThrows(IllegalArgumentException.class, () -> decode(PkiSigningOperation.RenewCredential.NAME,
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"credentialId\":\"credential-a\","
                        + "\"unexpected\":true}}"));
    }

    private static Object pki(HttpOperationCodec.Decoded decoded) {
        return switch (decoded.operation()) {
            case AdministrativeOperation.Pki pki -> pki.operation();
            case AdministrativeOperation.Signing signing -> signing.operation();
            case AdministrativeOperation.Control ignored -> throw new AssertionError("Unexpected control operation");
        };
    }

    private static HttpOperationCodec.Decoded decode(String name, String json) {
        return HttpOperationCodec.decode(name, json.getBytes(StandardCharsets.UTF_8), 16_384, REALM,
                DESCRIPTORS::require);
    }
}
