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
package zeroecho.pki.server.scep;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import zeroecho.pki.server.ServerRealmContext;

/** Unit coverage for the SCEP endpoint registry. */
class ScepServiceTest {
    private static final String HASH = "a".repeat(64);

    private ScepService service;

    @BeforeEach
    void setUp() {
        service = new ScepService(mock(ServerRealmContext.class));
    }

    @Test
    void registersAndFindsEndpoint() {
        ScepEndpoint endpoint = new ScepEndpoint("devices", "ca:issuer", "device-cert", HASH);
        service.register(endpoint);
        Optional<ScepEndpoint> found = service.find("devices");
        assertTrue(found.isPresent());
        assertEquals(endpoint, found.orElseThrow());
    }

    @Test
    void returnsEmptyForUnknownLabel() {
        assertTrue(service.find("unknown").isEmpty());
    }

    @Test
    void deregistersExistingEndpoint() {
        ScepEndpoint endpoint = new ScepEndpoint("devices", "ca:issuer", "device-cert", HASH);
        service.register(endpoint);
        Optional<ScepEndpoint> removed = service.deregister("devices");
        assertTrue(removed.isPresent());
        assertEquals(endpoint, removed.orElseThrow());
        assertTrue(service.find("devices").isEmpty());
    }

    @Test
    void deregisterReturnsEmptyForAbsentLabel() {
        assertTrue(service.deregister("nonexistent").isEmpty());
    }

    @Test
    void registerReplacesExistingWithSameLabel() {
        String hashA = "a".repeat(64);
        String hashB = "b".repeat(64);
        ScepEndpoint first = new ScepEndpoint("devices", "ca:issuer", "device-cert", hashA);
        ScepEndpoint second = new ScepEndpoint("devices", "ca:issuer", "device-cert-v2", hashB);
        service.register(first);
        service.register(second);
        Optional<ScepEndpoint> found = service.find("devices");
        assertTrue(found.isPresent());
        assertEquals("device-cert-v2", found.orElseThrow().profileId());
        assertEquals(hashB, found.orElseThrow().challengePasswordHash());
    }

    @Test
    void listReturnsAllRegisteredEndpoints() {
        ScepEndpoint a = new ScepEndpoint("endpoint-a", "ca:issuer", "profile-a", "a".repeat(64));
        ScepEndpoint b = new ScepEndpoint("endpoint-b", "ca:issuer", "profile-b", "b".repeat(64));
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
