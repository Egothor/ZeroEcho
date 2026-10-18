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
import zeroecho.pki.server.scep.ScepEndpoint;

/** Strict HTTPS decoding coverage for the SCEP endpoint admin operation family. */
class HttpScepEndpointCodecTest {
    private static final RealmId REALM = new RealmId("production");
    private static final OperationSecurityDescriptors DESCRIPTORS = new OperationSecurityDescriptors();
    private static final String VALID_HASH = "a".repeat(64);

    @Test
    void registersScepEndpoint() {
        String json = "{\"version\":1,\"arguments\":{"
                + "\"label\":\"devices\","
                + "\"authorityId\":\"ca:device-issuer\","
                + "\"enrollmentProfileId\":\"enrollment-test\","
                + "\"profileId\":\"device-cert\","
                + "\"challengePasswordHash\":\"" + VALID_HASH + "\"}}";
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.RegisterScepEndpoint.NAME, json);
        ServerControlOperation.RegisterScepEndpoint operation = assertInstanceOf(
                ServerControlOperation.RegisterScepEndpoint.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());
        ScepEndpoint endpoint = operation.endpoint();
        assertEquals("enrollment-test", endpoint.enrollmentProfileId());
        assertEquals("devices", endpoint.label());
        assertEquals("ca:device-issuer", endpoint.authorityId());
        assertEquals("device-cert", endpoint.profileId());
        assertEquals(VALID_HASH, endpoint.challengePasswordHash());
        assertEquals(Permission.Action.SCEP_ENDPOINT_ADMINISTER,
                DESCRIPTORS.require(ServerControlOperation.RegisterScepEndpoint.NAME).action());
        assertTrue(DESCRIPTORS.require(ServerControlOperation.RegisterScepEndpoint.NAME).mutating());
    }

    @Test
    void rejectsRegistrationWithUnknownField() {
        String json = "{\"version\":1,\"arguments\":{"
                + "\"label\":\"devices\","
                + "\"authorityId\":\"ca:issuer\","
                + "\"enrollmentProfileId\":\"enrollment-test\","
                + "\"profileId\":\"device\","
                + "\"challengePasswordHash\":\"" + VALID_HASH + "\","
                + "\"unexpected\":true}}";
        assertThrows(IllegalArgumentException.class,
                () -> decode(ServerControlOperation.RegisterScepEndpoint.NAME, json));
    }

    @Test
    void rejectsRegistrationWithInvalidLabel() {
        String json = "{\"version\":1,\"arguments\":{"
                + "\"label\":\"bad label with spaces\","
                + "\"authorityId\":\"ca:issuer\","
                + "\"enrollmentProfileId\":\"enrollment-test\","
                + "\"profileId\":\"device\","
                + "\"challengePasswordHash\":\"" + VALID_HASH + "\"}}";
        assertThrows(IllegalArgumentException.class,
                () -> decode(ServerControlOperation.RegisterScepEndpoint.NAME, json));
    }

    @Test
    void rejectsRegistrationWithInvalidHash() {
        String badHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        String json = "{\"version\":1,\"arguments\":{"
                + "\"label\":\"devices\","
                + "\"authorityId\":\"ca:issuer\","
                + "\"enrollmentProfileId\":\"enrollment-test\","
                + "\"profileId\":\"device\","
                + "\"challengePasswordHash\":\"" + badHash + "\"}}";
        assertThrows(IllegalArgumentException.class,
                () -> decode(ServerControlOperation.RegisterScepEndpoint.NAME, json));
    }

    @Test
    void deregistersEndpointByLabel() {
        String json = "{\"version\":1,\"arguments\":{\"label\":\"devices\"}}";
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.DeregisterScepEndpoint.NAME, json);
        ServerControlOperation.DeregisterScepEndpoint operation = assertInstanceOf(
                ServerControlOperation.DeregisterScepEndpoint.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());
        assertEquals("devices", operation.label());
        assertEquals(Permission.Action.SCEP_ENDPOINT_ADMINISTER,
                DESCRIPTORS.require(ServerControlOperation.DeregisterScepEndpoint.NAME).action());
    }

    @Test
    void rejectsDeregistrationWithExtraField() {
        String json = "{\"version\":1,\"arguments\":{"
                + "\"label\":\"devices\","
                + "\"authorityId\":\"ca:issuer\"}}";
        assertThrows(IllegalArgumentException.class,
                () -> decode(ServerControlOperation.DeregisterScepEndpoint.NAME, json));
    }

    @Test
    void inspectsEndpointByLabel() {
        String json = "{\"version\":1,\"arguments\":{\"label\":\"devices\"}}";
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.InspectScepEndpoint.NAME, json);
        ServerControlOperation.InspectScepEndpoint operation = assertInstanceOf(
                ServerControlOperation.InspectScepEndpoint.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());
        assertEquals("devices", operation.label());
        assertEquals(Permission.Action.SCEP_ENDPOINT_READ,
                DESCRIPTORS.require(ServerControlOperation.InspectScepEndpoint.NAME).action());
        assertFalse(DESCRIPTORS.require(ServerControlOperation.InspectScepEndpoint.NAME).mutating());
    }

    @Test
    void listsEndpointsWithBoundedPagination() {
        String json = "{\"version\":1,\"arguments\":{\"offset\":0,\"limit\":50}}";
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.ListScepEndpoints.NAME, json);
        ServerControlOperation.ListScepEndpoints operation = assertInstanceOf(
                ServerControlOperation.ListScepEndpoints.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());
        assertEquals(0, operation.offset());
        assertEquals(50, operation.limit());
        assertEquals(Permission.Action.SCEP_ENDPOINT_READ,
                DESCRIPTORS.require(ServerControlOperation.ListScepEndpoints.NAME).action());
    }

    @Test
    void rejectsListWithInvalidPaginationBounds() {
        assertThrows(IllegalArgumentException.class, () -> decode(
                ServerControlOperation.ListScepEndpoints.NAME,
                "{\"version\":1,\"arguments\":{\"offset\":-1,\"limit\":50}}"));
        assertThrows(IllegalArgumentException.class, () -> decode(
                ServerControlOperation.ListScepEndpoints.NAME,
                "{\"version\":1,\"arguments\":{\"offset\":0,\"limit\":0}}"));
        assertThrows(IllegalArgumentException.class, () -> decode(
                ServerControlOperation.ListScepEndpoints.NAME,
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
                + "\"profileId\":\"certificate\",\"challengePasswordHash\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}";
        assertThrows(IllegalArgumentException.class, () -> decode(ServerControlOperation.RegisterScepEndpoint.NAME, json));
    }
}
