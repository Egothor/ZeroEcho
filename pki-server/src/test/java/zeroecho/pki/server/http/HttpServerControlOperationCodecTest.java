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
package zeroecho.pki.server.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import zeroecho.pki.server.AdministrativeOperation;
import zeroecho.pki.server.OperationSecurityDescriptors;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.ServerControlOperation;

/** Strict HTTPS decoding coverage for the closed server-control operation family. */
class HttpServerControlOperationCodecTest {
    private static final RealmId REALM = new RealmId("production");
    private static final OperationSecurityDescriptors DESCRIPTORS = new OperationSecurityDescriptors();

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
    void decodesDirectoryRegistrationWithClosedPolicy() {
        System.out.println("decodesDirectoryRegistrationWithClosedPolicy");
        String json = "{\"version\":1,\"authorityId\":\"ca:internal\",\"arguments\":{"
                + "\"alias\":\"internal\",\"authorityId\":\"ca:internal\",\"profileId\":\"tls\","
                + "\"dnsNamespaces\":[\"example.test\"],\"maximumValidityMillis\":86400000,"
                + "\"publicKeyAlgorithms\":[\"ECDSA\"],\"x509BindingPolicies\":[\"STANDARD_ONLY\"],"
                + "\"challengeTypes\":[\"DNS_01\"],\"challengeProviderIds\":[\"zeroecho.dns-01.jndi.v1\"],"
                + "\"eabRequired\":false,\"disclosurePolicy\":\"OWNER_ONLY\"}}";
        HttpOperationCodec.Decoded decoded = decode(ServerControlOperation.RegisterAcmeDirectory.NAME, json);
        ServerControlOperation.RegisterAcmeDirectory operation = assertInstanceOf(
                ServerControlOperation.RegisterAcmeDirectory.class,
                ((AdministrativeOperation.Control) decoded.operation()).operation());
        assertEquals("internal", operation.registration().alias());
        assertEquals("tls", operation.registration().profileId());
        System.out.println("...directory-policy=closed");
        System.out.println("...ok");
    }

    private static HttpOperationCodec.Decoded decode(String operation, String json) {
        return HttpOperationCodec.decode(operation, json.getBytes(StandardCharsets.UTF_8), 16_384,
                REALM, DESCRIPTORS::require);
    }
}
