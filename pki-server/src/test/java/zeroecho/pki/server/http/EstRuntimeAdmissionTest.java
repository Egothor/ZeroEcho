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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpsExchange;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.Test;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.est.EstEndpoint;
import zeroecho.pki.server.est.EstService;
import zeroecho.pki.server.est.KeygenPolicy;

class EstRuntimeAdmissionTest {
    @Test void keygenBlockedDeliveryIsCancelledClosedAndRetryRemainsAvailable() throws Exception {
        EstService service = service();
        zeroecho.pki.server.est.EstServerKeygenResponse response = mock(zeroecho.pki.server.est.EstServerKeygenResponse.class);
        zeroecho.pki.server.est.EstServerKeygenResponse.Body delivery = mock(zeroecho.pki.server.est.EstServerKeygenResponse.Body.class);
        when(response.status()).thenReturn(200);
        when(response.contentType()).thenReturn("multipart/mixed; boundary=retained");
        when(response.openDelivery()).thenReturn(delivery);
        when(service.serverkeygen(any(), any(), any(), any())).thenReturn(response);
        CountDownLatch closed = new CountDownLatch(1);
        CountDownLatch released = new CountDownLatch(1);
        java.util.concurrent.atomic.AtomicReference<CancellationSignal> observed = new java.util.concurrent.atomic.AtomicReference<>();
        org.mockito.Mockito.doAnswer(invocation -> {
            observed.set(invocation.getArgument(1));
            ((java.io.OutputStream) invocation.getArgument(0)).write(42);
            return null;
        }).when(delivery).writeTo(any(), any());
        org.mockito.Mockito.doAnswer(invocation -> { released.countDown(); return null; }).when(delivery).close();
        try (ServerRuntime runtime = new ServerRuntime(execution(), ServerRuntime.Lane.EST)) {
            zeroecho.pki.server.est.EstHttpHandler handler = handler(service, runtime);
            HttpsExchange blocked = exchange(new byte[] {1});
            when(blocked.getRequestURI()).thenReturn(URI.create("/.well-known/est/managed/serverkeygen"));
            when(blocked.getResponseBody()).thenReturn(new java.io.OutputStream() {
                @Override public void write(int value) throws java.io.IOException {
                    boolean interrupted = false;
                    while (closed.getCount() != 0) {
                        try { closed.await(); }
                        catch (InterruptedException interruption) { interrupted = true; }
                    }
                    if (interrupted) Thread.currentThread().interrupt();
                    throw new java.io.IOException("Exchange closed");
                }
            });
            org.mockito.Mockito.doAnswer(invocation -> { closed.countDown(); return null; }).when(blocked).close();
            handler.handle(blocked);
            assertTrue(released.await(5, TimeUnit.SECONDS));
            assertTrue(observed.get().isCancelled());
            verify(blocked).sendResponseHeaders(200, 0);
            verify(blocked, never()).sendResponseHeaders(eq(504), anyLong());
            HttpsExchange retry = exchange(new byte[] {1});
            when(retry.getRequestURI()).thenReturn(URI.create("/.well-known/est/managed/serverkeygen"));
            handler.handle(retry);
            verify(retry).sendResponseHeaders(200, 0);
            org.junit.jupiter.api.Assertions.assertArrayEquals(new byte[] {42}, ((ByteArrayOutputStream) retry.getResponseBody()).toByteArray());
            verify(delivery, org.mockito.Mockito.times(2)).close();
        }
    }

    @Test void cancelledDeliveryAcquisitionCannotEmitLateErrorHeaders() throws Exception {
        EstService service = service();
        zeroecho.pki.server.est.EstServerKeygenResponse response = mock(zeroecho.pki.server.est.EstServerKeygenResponse.class);
        when(response.status()).thenReturn(200);
        CountDownLatch closed = new CountDownLatch(1);
        CountDownLatch exited = new CountDownLatch(1);
        when(response.openDelivery()).thenAnswer(invocation -> {
            boolean interrupted = false;
            while (closed.getCount() != 0) {
                try { closed.await(); }
                catch (InterruptedException interruption) { interrupted = true; }
            }
            if (interrupted) Thread.currentThread().interrupt();
            exited.countDown();
            throw new zeroecho.pki.server.est.EstProtocolException(410, "Expired");
        });
        when(service.serverkeygen(any(), any(), any(), any())).thenReturn(response);
        HttpsExchange request = exchange(new byte[] {1});
        try (ServerRuntime runtime = new ServerRuntime(execution(), ServerRuntime.Lane.EST)) {
            when(request.getRequestURI()).thenReturn(URI.create("/.well-known/est/managed/serverkeygen"));
            org.mockito.Mockito.doAnswer(invocation -> { closed.countDown(); return null; }).when(request).close();
            handler(service, runtime).handle(request);
            assertTrue(exited.await(5, TimeUnit.SECONDS));
        }
        verify(request, never()).sendResponseHeaders(org.mockito.ArgumentMatchers.anyInt(), anyLong());
    }
    @Test void registeredAdapterEnforcesConfiguredBodyBoundBeforeService() throws Exception {
        EstService service = service();
        try (ServerRuntime runtime = new ServerRuntime(execution(), ServerRuntime.Lane.EST)) {
            zeroecho.pki.server.est.EstHttpHandler handler = handler(service, runtime);
            HttpsExchange request = exchange(new byte[1025]);
            handler.handle(request);
            verify(request).sendResponseHeaders(eq(413), anyLong());
            verify(service, never()).simpleenroll(any(), any(), any(), any());
        }
    }

    @Test void registeredAdapterRejectsBusyAndCancelsOwnedWorkAtDeadline() throws Exception {
        EstService service = service();
        CountDownLatch cancelled = new CountDownLatch(1);
        when(service.simpleenroll(any(), any(), any(), any())).thenAnswer(invocation -> {
            CancellationSignal signal = invocation.getArgument(3);
            try { new CountDownLatch(1).await(); }
            catch (InterruptedException interruption) {
                if (signal.isCancelled()) cancelled.countDown();
                Thread.currentThread().interrupt();
            }
            return new EstService.EnrollmentResult(202, new byte[0], Optional.of(1L));
        });
        try (ServerRuntime runtime = new ServerRuntime(execution(), ServerRuntime.Lane.EST)) {
            zeroecho.pki.server.est.EstHttpHandler handler = handler(service, runtime);
            assertTrue(runtime.tryAdmit());
            HttpsExchange busy = exchange(new byte[] { 1 });
            handler.handle(busy);
            verify(busy).sendResponseHeaders(eq(429), anyLong());
            runtime.releaseAdmission();
            HttpsExchange timedOut = exchange(new byte[] { 1 });
            handler.handle(timedOut);
            verify(timedOut).sendResponseHeaders(eq(504), anyLong());
            assertTrue(cancelled.await(5, TimeUnit.SECONDS));
            assertTrue(runtime.tryAdmit());
            runtime.releaseAdmission();
        }
    }

    private static PkiServerConfiguration.Execution execution() {
        return new PkiServerConfiguration.Execution(1, 1, 1, 1, 1, Duration.ofSeconds(1),
                Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(1));
    }

    private static EstService service() {
        EstService service = mock(EstService.class);
        when(service.find("managed")).thenReturn(Optional.of(new EstEndpoint("managed", "authority", "profile", "enrollment", KeygenPolicy.DISABLED)));
        return service;
    }

    private static zeroecho.pki.server.est.EstHttpHandler handler(EstService service, ServerRuntime runtime) {
        return new zeroecho.pki.server.est.EstHttpHandler(mock(ServerRealmContext.class), service, runtime,
                new RequestIds(new SecureRandom()), () -> true, 1024, Duration.ofSeconds(1));
    }

    private static HttpsExchange exchange(byte[] body) throws Exception {
        HttpsExchange exchange = mock(HttpsExchange.class);
        SSLSession session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenReturn(new Certificate[] { mock(X509Certificate.class) });
        when(exchange.getSSLSession()).thenReturn(session);
        when(exchange.getRequestHeaders()).thenReturn(new Headers());
        when(exchange.getResponseHeaders()).thenReturn(new Headers());
        when(exchange.getRequestURI()).thenReturn(URI.create("/.well-known/est/managed/simpleenroll"));
        when(exchange.getRequestMethod()).thenReturn("POST");
        when(exchange.getRequestBody()).thenReturn(new ByteArrayInputStream(body));
        when(exchange.getResponseBody()).thenReturn(new ByteArrayOutputStream());
        return exchange;
    }
}
