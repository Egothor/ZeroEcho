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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import zeroecho.pki.server.AdministrativeOperation;
import zeroecho.pki.server.OperationSecurityDescriptors;
import zeroecho.pki.server.Permission;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.ServerControlOperation;
import zeroecho.pki.server.est.EstEndpoint;
import zeroecho.pki.server.est.KeygenPolicy;

/** Strict HTTPS decoding coverage for the EST endpoint admin operation family. */
class HttpEstEndpointCodecTest {
    private static final RealmId REALM = new RealmId("production");
    private static final OperationSecurityDescriptors DESCRIPTORS = new OperationSecurityDescriptors();

    @Test
    void registersEstEndpointWithoutKeygen() {
        String json = "{\"version\":1,\"arguments\":{"
                + "\"label\":\"internal-devices\","
                + "\"authorityId\":\"ca:device-issuer\","
                + "\"enrollmentProfileId\":\"enrollment-test\","
                + "\"profileId\":\"device-tls\"}}";
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.RegisterEstEndpoint.NAME, json);
        ServerControlOperation.RegisterEstEndpoint operation = assertInstanceOf(
                ServerControlOperation.RegisterEstEndpoint.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());
        EstEndpoint endpoint = operation.endpoint();
        assertEquals("enrollment-test", endpoint.enrollmentProfileId());
        assertEquals("internal-devices", endpoint.label());
        assertEquals("ca:device-issuer", endpoint.authorityId());
        assertEquals("device-tls", endpoint.profileId());
        assertFalse(endpoint.keygen().enabled(), "keygen must default to DISABLED");
        assertEquals(KeygenPolicy.DISABLED, endpoint.keygen());
        assertEquals(Permission.Action.EST_ENDPOINT_ADMINISTER,
                DESCRIPTORS.require(ServerControlOperation.RegisterEstEndpoint.NAME).action());
        assertTrue(DESCRIPTORS.require(ServerControlOperation.RegisterEstEndpoint.NAME).mutating());
    }

    @Test
    void registersEstEndpointWithExplicitKeygenPolicy() {
        String json = "{\"version\":1,\"arguments\":{"
                + "\"label\":\"server-keygen\","
                + "\"authorityId\":\"ca:issuer\","
                + "\"enrollmentProfileId\":\"enrollment-test\","
                + "\"profileId\":\"tls\","
                + "\"keygen\":{"
                + "\"enabled\":true,"
                + "\"permittedAlgorithms\":[\"EC\",\"RSA\"],"
                + "\"maximumKeySizeBits\":4096,"
                + "\"storeGeneratedKeys\":false}}}";
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.RegisterEstEndpoint.NAME, json);
        ServerControlOperation.RegisterEstEndpoint operation = assertInstanceOf(
                ServerControlOperation.RegisterEstEndpoint.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());
        KeygenPolicy keygen = operation.endpoint().keygen();
        assertTrue(keygen.enabled());
        assertEquals(java.util.Set.of("EC", "RSA"), new java.util.HashSet<>(keygen.permittedAlgorithms()));
        assertEquals(4096, keygen.maximumKeySizeBits());
        assertFalse(keygen.storeGeneratedKeys());
    }

    @Test
    void rejectsRegistrationWithUnknownTopLevelField() {
        String json = "{\"version\":1,\"arguments\":{"
                + "\"label\":\"internal-devices\","
                + "\"authorityId\":\"ca:device-issuer\","
                + "\"enrollmentProfileId\":\"enrollment-test\","
                + "\"profileId\":\"device-tls\","
                + "\"unexpected\":true}}";
        assertThrows(IllegalArgumentException.class,
                () -> decode(ServerControlOperation.RegisterEstEndpoint.NAME, json));
    }

    @Test
    void rejectsRegistrationWithUnknownKeygenSubField() {
        String json = "{\"version\":1,\"arguments\":{"
                + "\"label\":\"internal-devices\","
                + "\"authorityId\":\"ca:issuer\","
                + "\"enrollmentProfileId\":\"enrollment-test\","
                + "\"profileId\":\"tls\","
                + "\"keygen\":{"
                + "\"enabled\":true,"
                + "\"permittedAlgorithms\":[\"EC\"],"
                + "\"maximumKeySizeBits\":256,"
                + "\"storeGeneratedKeys\":false,"
                + "\"unknownField\":\"bad\"}}}";
        assertThrows(IllegalArgumentException.class,
                () -> decode(ServerControlOperation.RegisterEstEndpoint.NAME, json));
    }

    @Test
    void rejectsRegistrationWithInvalidLabel() {
        String badLabel = "\"label\":\"bad label with spaces\"";
        String json = "{\"version\":1,\"arguments\":{"
                + badLabel + ","
                + "\"authorityId\":\"ca:issuer\","
                + "\"enrollmentProfileId\":\"enrollment-test\","
                + "\"profileId\":\"tls\"}}";
        assertThrows(IllegalArgumentException.class,
                () -> decode(ServerControlOperation.RegisterEstEndpoint.NAME, json));
    }

    @Test
    void deregistersEndpointByLabel() {
        String json = "{\"version\":1,\"arguments\":{\"label\":\"internal-devices\"}}";
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.DeregisterEstEndpoint.NAME, json);
        ServerControlOperation.DeregisterEstEndpoint operation = assertInstanceOf(
                ServerControlOperation.DeregisterEstEndpoint.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());
        assertEquals("internal-devices", operation.label());
        assertEquals(Permission.Action.EST_ENDPOINT_ADMINISTER,
                DESCRIPTORS.require(ServerControlOperation.DeregisterEstEndpoint.NAME).action());
    }

    @Test
    void rejectsDeregistrationWithExtraField() {
        String json = "{\"version\":1,\"arguments\":{"
                + "\"label\":\"internal-devices\","
                + "\"authorityId\":\"ca:issuer\"}}";
        assertThrows(IllegalArgumentException.class,
                () -> decode(ServerControlOperation.DeregisterEstEndpoint.NAME, json));
    }

    @Test
    void inspectsEndpointByLabel() {
        String json = "{\"version\":1,\"arguments\":{\"label\":\"internal-devices\"}}";
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.InspectEstEndpoint.NAME, json);
        ServerControlOperation.InspectEstEndpoint operation = assertInstanceOf(
                ServerControlOperation.InspectEstEndpoint.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());
        assertEquals("internal-devices", operation.label());
        assertEquals(Permission.Action.EST_ENDPOINT_READ,
                DESCRIPTORS.require(ServerControlOperation.InspectEstEndpoint.NAME).action());
        assertFalse(DESCRIPTORS.require(ServerControlOperation.InspectEstEndpoint.NAME).mutating());
    }

    @Test
    void listsEndpointsWithBoundedPagination() {
        String json = "{\"version\":1,\"arguments\":{\"offset\":0,\"limit\":50}}";
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.ListEstEndpoints.NAME, json);
        ServerControlOperation.ListEstEndpoints operation = assertInstanceOf(
                ServerControlOperation.ListEstEndpoints.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());
        assertEquals(0, operation.offset());
        assertEquals(50, operation.limit());
        assertEquals(Permission.Action.EST_ENDPOINT_READ,
                DESCRIPTORS.require(ServerControlOperation.ListEstEndpoints.NAME).action());
    }

    @Test
    void rejectsListWithInvalidPaginationBounds() {
        assertThrows(IllegalArgumentException.class, () -> decode(
                ServerControlOperation.ListEstEndpoints.NAME,
                "{\"version\":1,\"arguments\":{\"offset\":-1,\"limit\":50}}"));
        assertThrows(IllegalArgumentException.class, () -> decode(
                ServerControlOperation.ListEstEndpoints.NAME,
                "{\"version\":1,\"arguments\":{\"offset\":0,\"limit\":0}}"));
        assertThrows(IllegalArgumentException.class, () -> decode(
                ServerControlOperation.ListEstEndpoints.NAME,
                "{\"version\":1,\"arguments\":{\"offset\":0,\"limit\":257}}"));
    }

    private static HttpOperationCodec.Decoded decode(String operation, String json) {
        return HttpOperationCodec.decode(operation, json.getBytes(StandardCharsets.UTF_8),
                PkiServerConfiguration.Listener.MINIMUM_BODY_BYTES,
                REALM, DESCRIPTORS::require);
    }

    @Test
    void rejectsRegistrationWithoutExplicitEnrollmentProfile() {
        String json = "{\"version\":1,\"arguments\":{\"label\":\"endpoint\",\"authorityId\":\"authority\","
                + "\"profileId\":\"certificate\"}}";
        assertThrows(IllegalArgumentException.class, () -> decode(ServerControlOperation.RegisterEstEndpoint.NAME, json));
    }
}
