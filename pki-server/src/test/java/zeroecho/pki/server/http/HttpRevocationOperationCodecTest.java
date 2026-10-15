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
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.server.AdministrativeOperation;
import zeroecho.pki.server.OperationSecurityDescriptors;
import zeroecho.pki.server.Permission;
import zeroecho.pki.server.RealmId;

/** Strict HTTP credential-revocation decoding coverage. */
class HttpRevocationOperationCodecTest {
    private static final RealmId REALM = new RealmId("production");
    private static final OperationSecurityDescriptors DESCRIPTORS = new OperationSecurityDescriptors();

    @Test
    void decodesOptionalJustificationIntoOperationAndConditionContext() {
        HttpOperationCodec.Decoded reasonOnly = decode("{\"version\":1,\"authorityId\":\"ca-a\","
                + "\"arguments\":{\"credentialId\":\"credential-a\",\"reason\":\"KEY_COMPROMISE\"}}");
        HttpOperationCodec.Decoded justified = decode("{\"version\":1,\"authorityId\":\"ca-a\","
                + "\"arguments\":{\"credentialId\":\"credential-a\",\"reason\":\"KEY_COMPROMISE\","
                + "\"justification\":\"ticket-100\"}}");

        PkiOperation.RevokeCredential reasonOnlyOperation = operation(reasonOnly);
        PkiOperation.RevokeCredential justifiedOperation = operation(justified);
        assertEquals(Optional.empty(), reasonOnlyOperation.operatorJustification());
        assertEquals(Optional.empty(), reasonOnly.context().operatorJustification());
        assertEquals(Optional.of("ticket-100"), justifiedOperation.operatorJustification());
        assertEquals(Optional.of("ticket-100"), justified.context().operatorJustification());
        assertEquals(Permission.ResourceType.CERTIFICATE, justified.resource().type());
    }

    @Test
    void rejectsUnknownAndOversizedJustification() {
        assertThrows(IllegalArgumentException.class, () -> decode("{\"version\":1,"
                + "\"authorityId\":\"ca-a\",\"arguments\":{\"credentialId\":\"credential-a\","
                + "\"reason\":\"KEY_COMPROMISE\",\"unexpected\":true}}"));
        String oversized = "x".repeat(1025);
        assertThrows(IllegalArgumentException.class, () -> decode("{\"version\":1,"
                + "\"authorityId\":\"ca-a\",\"arguments\":{\"credentialId\":\"credential-a\","
                + "\"reason\":\"KEY_COMPROMISE\",\"justification\":\"" + oversized + "\"}}"));
    }

    @Test
    void decodesPendingConfirmationRevocationWithoutClientReasonOrCutoff() {
        HttpOperationCodec.Decoded decoded = decodePending("{\"version\":1,\"authorityId\":\"ca-a\","
                + "\"arguments\":{\"credentialId\":\"credential-a\","
                + "\"justification\":\"ticket-200\"}}");
        AdministrativeOperation.Pki family = assertInstanceOf(
                AdministrativeOperation.Pki.class, decoded.operation());
        PkiOperation.RevokePendingCredentialConfirmation operation = assertInstanceOf(
                PkiOperation.RevokePendingCredentialConfirmation.class, family.operation());
        assertEquals("credential-a", operation.credentialId().value());
        assertEquals(Optional.of("ticket-200"), operation.operatorJustification());
        assertEquals(operation.operatorJustification(), decoded.context().operatorJustification());

        assertThrows(IllegalArgumentException.class, () -> decodePending(
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{"
                        + "\"credentialId\":\"credential-a\",\"reason\":\"KEY_COMPROMISE\"}}"));
        assertThrows(IllegalArgumentException.class, () -> decodePending(
                "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{"
                        + "\"credentialId\":\"credential-a\","
                        + "\"cutoffInclusive\":\"2026-08-30T12:00:00Z\"}}"));
    }

    private static PkiOperation.RevokeCredential operation(HttpOperationCodec.Decoded decoded) {
        AdministrativeOperation.Pki family = assertInstanceOf(AdministrativeOperation.Pki.class,
                decoded.operation());
        return assertInstanceOf(PkiOperation.RevokeCredential.class, family.operation());
    }

    @Test
    void holdTransitionsDecodeStrictArgumentsAndPreserveJustification() {
        for (String name : java.util.List.of("credential.hold", "credential.unhold")) {
            String json = "{\"version\":1,\"authorityId\":\"ca-a\",\"arguments\":{\"credentialId\":\"credential-a\",\"justification\":\"ticket-300\"}}";
            HttpOperationCodec.Decoded decoded = HttpOperationCodec.decode(name, json.getBytes(StandardCharsets.UTF_8),
                    16_384, REALM, DESCRIPTORS::require);
            PkiOperation value = assertInstanceOf(AdministrativeOperation.Pki.class, decoded.operation()).operation();
            assertEquals(name, value.name());
            assertEquals(Optional.of("ticket-300"), decoded.context().operatorJustification());
            assertEquals("credential-a", decoded.resource().objectId().orElseThrow().value());
            for (String field : java.util.List.of("reason", "revocationDate", "evidence", "unexpected")) {
                String invalid = json.replace("\"justification\":\"ticket-300\"", "\"" + field + "\":\"invalid\"");
                assertThrows(IllegalArgumentException.class, () -> HttpOperationCodec.decode(name,
                        invalid.getBytes(StandardCharsets.UTF_8), 16_384, REALM, DESCRIPTORS::require));
            }
            for (String justification : java.util.List.of("", " ", "x".repeat(1025))) {
                String invalid = json.replace("ticket-300", justification);
                assertThrows(IllegalArgumentException.class, () -> HttpOperationCodec.decode(name,
                        invalid.getBytes(StandardCharsets.UTF_8), 16_384, REALM, DESCRIPTORS::require));
            }
        }
    }

    private static HttpOperationCodec.Decoded decode(String json) {
        return HttpOperationCodec.decode(PkiOperation.RevokeCredential.NAME,
                json.getBytes(StandardCharsets.UTF_8), 16_384, REALM, DESCRIPTORS::require);
    }

    private static HttpOperationCodec.Decoded decodePending(String json) {
        return HttpOperationCodec.decode(PkiOperation.RevokePendingCredentialConfirmation.NAME,
                json.getBytes(StandardCharsets.UTF_8), 16_384, REALM, DESCRIPTORS::require);
    }
}
