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
package zeroecho.pki.server.cmp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;

import java.util.Optional;
import java.lang.reflect.Method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pkix.cmp.CmpCodec;
import zeroecho.pkix.cmp.CmpPkiMessage;

/** Unit coverage for the CMP endpoint registry. */
class CmpServiceTest {

    @Test
    void interruptedSigningPollPreservesInterruptAndReturnsProtocolError() throws Exception {
        ServerRealmContext realm = mock(ServerRealmContext.class);
        PkiSession session = mock(PkiSession.class);
        SemanticSigningService signing = mock(SemanticSigningService.class);
        when(realm.session()).thenReturn(session);
        when(session.semanticSigning()).thenReturn(Optional.of(signing));
        SigningAcceptanceReceipt receipt = mock(SigningAcceptanceReceipt.class);
        PkiId operationId = new PkiId("operation:interrupted");
        when(receipt.operationId()).thenReturn(operationId);
        when(signing.accept(any())).thenReturn(new SigningAcceptanceResult(SigningAcceptanceDisposition.ACCEPTED, receipt));
        when(signing.find(operationId)).thenAnswer(call -> {
            Thread.currentThread().interrupt();
            return Optional.empty();
        });
        CmpService cmp = new CmpService(realm);
        CmpEndpoint endpoint = new CmpEndpoint("test", "ca:root", "profile", CmpProtectionPolicy.SIGNATURE_BASED);
        CmpPkiMessage request = new CmpPkiMessage(CmpCodec.BODY_IR, new byte[16], new byte[16],
                null, null, null, null, false);
        Method handler = CmpService.class.getDeclaredMethod("handleCertRequest", CmpEndpoint.class,
                CmpPkiMessage.class, boolean.class);
        handler.setAccessible(true);
        try {
            byte[] response = (byte[]) handler.invoke(cmp, endpoint, request, true);
            assertTrue(Thread.currentThread().isInterrupted());
            assertEquals(CmpCodec.BODY_ERROR, CmpCodec.parseMessage(response).bodyType());
        } finally {
            Thread.interrupted();
        }
    }

    private CmpService service;

    @BeforeEach
    void setUp() {
        service = new CmpService(mock(ServerRealmContext.class));
    }

    @Test
    void registersAndFindsEndpoint() {
        CmpEndpoint endpoint = new CmpEndpoint("enterprise-cmp", "ca:root", "cmp-enroll",
                CmpProtectionPolicy.SIGNATURE_BASED);
        service.register(endpoint);
        Optional<CmpEndpoint> found = service.find("enterprise-cmp");
        assertTrue(found.isPresent());
        assertEquals(endpoint, found.orElseThrow());
    }

    @Test
    void returnsEmptyForUnknownLabel() {
        assertTrue(service.find("unknown").isEmpty());
    }

    @Test
    void deregistersExistingEndpoint() {
        CmpEndpoint endpoint = new CmpEndpoint("enterprise-cmp", "ca:root", "cmp-enroll",
                CmpProtectionPolicy.SIGNATURE_BASED);
        service.register(endpoint);
        Optional<CmpEndpoint> removed = service.deregister("enterprise-cmp");
        assertTrue(removed.isPresent());
        assertEquals(endpoint, removed.orElseThrow());
        assertTrue(service.find("enterprise-cmp").isEmpty());
    }

    @Test
    void deregisterReturnsEmptyForAbsentLabel() {
        assertTrue(service.deregister("nonexistent").isEmpty());
    }

    @Test
    void registerReplacesExistingWithSameLabel() {
        CmpEndpoint first = new CmpEndpoint("iot-cmp", "ca:iot", "profile-v1",
                CmpProtectionPolicy.SHARED_SECRET_MAC);
        CmpEndpoint second = new CmpEndpoint("iot-cmp", "ca:iot", "profile-v2",
                CmpProtectionPolicy.SIGNATURE_BASED);
        service.register(first);
        service.register(second);
        Optional<CmpEndpoint> found = service.find("iot-cmp");
        assertTrue(found.isPresent());
        assertEquals("profile-v2", found.orElseThrow().profileId());
        assertEquals(CmpProtectionPolicy.SIGNATURE_BASED, found.orElseThrow().protectionPolicy());
    }

    @Test
    void listReturnsAllRegisteredEndpoints() {
        CmpEndpoint a = new CmpEndpoint("endpoint-a", "ca:root", "profile-a",
                CmpProtectionPolicy.SIGNATURE_BASED);
        CmpEndpoint b = new CmpEndpoint("endpoint-b", "ca:iot", "profile-b",
                CmpProtectionPolicy.SHARED_SECRET_MAC);
        service.register(a);
        service.register(b);
        var listed = service.list();
        assertEquals(2, listed.size());
        assertTrue(listed.contains(a));
        assertTrue(listed.contains(b));
    }

    @Test
    void listIsEmptyWhenNoEndpointsRegistered() {
        assertTrue(service.list().isEmpty());
    }

    @Test
    void rejectsNullEndpointOnRegister() {
        assertThrows(NullPointerException.class, () -> service.register(null));
    }

    @Test
    void rejectsNullLabelOnFind() {
        assertThrows(NullPointerException.class, () -> service.find(null));
    }

    @Test
    void rejectsNullLabelOnDeregister() {
        assertThrows(NullPointerException.class, () -> service.deregister(null));
    }
}
