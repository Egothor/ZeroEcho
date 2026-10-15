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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.net.InetAddress;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import org.junit.jupiter.api.Test;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.scep.ScepEndpoint;
import zeroecho.pki.server.scep.ScepService;
import zeroecho.pki.spi.ProviderConfig;

class ScepRuntimeAdmissionTest {
    @Test void configuredAdmissionAndTimeoutCancelTheSameProtocolWork() throws Exception {
        PkiServerConfiguration.Execution execution = new PkiServerConfiguration.Execution(1, 1, 1, 1, 1,
                Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(1));
        PkiServerConfiguration.ScepListener listener = new PkiServerConfiguration.ScepListener("scep", InetAddress.getLoopbackAddress(),
                0, new ProviderConfig("test", Map.of()), execution, 1024, 1024);
        ScepService service = mock(ScepService.class);
        ScepEndpoint endpoint = new ScepEndpoint("managed", "authority", "profile", "enrollment", "a".repeat(64));
        when(service.find("managed")).thenReturn(Optional.of(endpoint));
        CountDownLatch cancelled = new CountDownLatch(1);
        when(service.processPkiOperation(eq(endpoint), any(byte[].class), any(CancellationSignal.class))).thenAnswer(invocation -> {
            CancellationSignal signal = invocation.getArgument(2);
            try { new CountDownLatch(1).await(); }
            catch (InterruptedException interruption) {
                if (signal.isCancelled()) cancelled.countDown();
                Thread.currentThread().interrupt();
            }
            return new byte[0];
        });
        try (ServerRuntime runtime = new ServerRuntime(execution, ServerRuntime.Lane.SCEP)) {
            ScepHttpHandler handler = new ScepHttpHandler(listener, mock(ServerRealmContext.class), service, runtime,
                    new RequestIds(new java.security.SecureRandom()), () -> true);
            assertTrue(runtime.tryAdmit());
            HttpExchange overloaded = exchange();
            handler.handle(overloaded);
            verify(overloaded).sendResponseHeaders(eq(503), anyLong());
            runtime.releaseAdmission();
            HttpExchange timedOut = exchange();
            handler.handle(timedOut);
            verify(timedOut).sendResponseHeaders(eq(504), anyLong());
            assertTrue(cancelled.await(5, TimeUnit.SECONDS));
            assertTrue(runtime.tryAdmit()); runtime.releaseAdmission();
        }
    }

    private static HttpExchange exchange() {
        HttpExchange exchange = mock(HttpExchange.class);
        when(exchange.getRequestHeaders()).thenReturn(new Headers());
        when(exchange.getResponseHeaders()).thenReturn(new Headers());
        when(exchange.getRequestURI()).thenReturn(URI.create("/scep/managed?operation=PKIOperation"));
        when(exchange.getRequestMethod()).thenReturn("POST");
        when(exchange.getRequestBody()).thenReturn(new java.io.ByteArrayInputStream(new byte[] {1}));
        when(exchange.getResponseBody()).thenReturn(new java.io.ByteArrayOutputStream());
        return exchange;
    }
}
