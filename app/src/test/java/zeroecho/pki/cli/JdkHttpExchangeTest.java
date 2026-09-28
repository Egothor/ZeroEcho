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
package zeroecho.pki.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.sun.net.httpserver.HttpServer;

class JdkHttpExchangeTest {
    @Test
    @Timeout(10)
    void responseBodyStallHonorsWholeRequestTimeout() throws Exception {
        CountDownLatch headersSent = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService caller = Executors.newSingleThreadExecutor();
        try (Fixture fixture = stalled(headersSent, release)) {
            Future<IOException> result = caller.submit(() -> sendFailure(fixture.exchange, Duration.ofMillis(500)));
            assertTrue(headersSent.await(3, TimeUnit.SECONDS));
            assertInstanceOf(HttpTimeoutException.class, result.get(3, TimeUnit.SECONDS));
            fixture.exchange.close();
        } finally { release.countDown(); caller.shutdownNow(); }
    }

    @Test
    @Timeout(10)
    void interruptCancelsUnfinishedBodyAndRestoresCallerFlag() throws Exception {
        CountDownLatch headersSent = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicReference<Thread> callerThread = new AtomicReference<>();
        AtomicBoolean restored = new AtomicBoolean();
        ExecutorService caller = Executors.newSingleThreadExecutor();
        try (Fixture fixture = stalled(headersSent, release)) {
            Future<IOException> result = caller.submit(() -> {
                callerThread.set(Thread.currentThread());
                IOException failure = sendFailure(fixture.exchange, Duration.ofSeconds(30));
                restored.set(Thread.currentThread().isInterrupted());
                return failure;
            });
            assertTrue(headersSent.await(3, TimeUnit.SECONDS));
            callerThread.get().interrupt();
            assertInstanceOf(InterruptedException.class, result.get(3, TimeUnit.SECONDS).getCause());
            assertTrue(restored.get());
        } finally { release.countDown(); caller.shutdownNow(); }
    }

    @Test
    @Timeout(10)
    void responseLimitRejectsOverflowRatherThanReturningTruncatedData() throws Exception {
        for (int extra : new int[] { 0, 1 }) {
            try (Fixture fixture = new Fixture()) {
                int size = 4 * 1_048_576 + extra;
                fixture.server.createContext("/body", exchange -> {
                    try (exchange) {
                        exchange.sendResponseHeaders(200, size);
                        byte[] buffer = new byte[8192];
                        for (int remaining = size; remaining > 0; remaining -= Math.min(remaining, buffer.length)) {
                            exchange.getResponseBody().write(buffer, 0, Math.min(remaining, buffer.length));
                        }
                    } catch (IOException cancelled) {
                        // The client closes a response that exceeds its bounded protocol budget.
                    }
                });
                fixture.server.start();
                if (extra == 0) {
                    assertEquals(size, fixture.exchange.send(request(Duration.ofSeconds(3))).body().length);
                } else {
                    assertInstanceOf(PkiHttpExchange.InvalidResponseException.class,
                            sendFailure(fixture.exchange, Duration.ofSeconds(3)));
                }
            }
        }
    }

    private static Fixture stalled(CountDownLatch headersSent, CountDownLatch release) throws Exception {
        Fixture fixture = new Fixture();
        fixture.server.createContext("/body", exchange -> {
            try (exchange) {
                exchange.sendResponseHeaders(200, 100);
                exchange.getResponseBody().write(1);
                exchange.getResponseBody().flush();
                headersSent.countDown();
                try { release.await(); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            } catch (IOException cancelled) {
                // Timeout and interruption deliberately close the unfinished response.
            }
        });
        fixture.server.start();
        return fixture;
    }

    private static IOException sendFailure(JdkHttpExchange exchange, Duration timeout) {
        try {
            exchange.send(request(timeout));
            throw new AssertionError("Expected a bounded exchange failure");
        } catch (IOException expected) { return expected; }
    }

    private static PkiHttpExchange.Request request(Duration timeout) {
        return new PkiHttpExchange.Request(PkiHttpExchange.Method.GET, "/body", Optional.empty(), timeout);
    }

    private static final class Fixture implements AutoCloseable {
        private final ExecutorService serverExecutor = Executors.newSingleThreadExecutor();
        private final HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        private final JdkHttpExchange exchange;
        private Fixture() throws Exception {
            server.setExecutor(serverExecutor);
            exchange = JdkHttpExchange.open(URI.create("http://127.0.0.1:" + server.getAddress().getPort()), SSLContext.getDefault());
        }
        @Override public void close() {
            exchange.close();
            server.stop(0);
            serverExecutor.shutdownNow();
        }
    }
}
