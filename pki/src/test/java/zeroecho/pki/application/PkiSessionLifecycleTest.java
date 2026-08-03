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
package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.store.PkiStore;

class PkiSessionLifecycleTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-08-04T00:00:00Z"), ZoneOffset.UTC);

    @TempDir
    Path temporaryDirectory;

    @Test
    void opensReusesAndDeterministicallyClosesOneSession() throws Exception {
        System.out.println("opensReusesAndDeterministicallyClosesOneSession");
        PkiSessionConfiguration configuration = configuration(temporaryDirectory.resolve("store"));
        PkiSession session = PkiSession.open(configuration);
        PkiOperationOutcome first = session.operations().execute(new PkiOperation.ValidateConfiguration(),
                CancellationSignal.NONE);
        PkiOperationOutcome second = session.operations().execute(new PkiOperation.ValidateConfiguration(),
                CancellationSignal.NONE);
        System.out.println("...executions=2");
        assertInstanceOf(PkiOperationOutcome.Success.class, first);
        assertInstanceOf(PkiOperationOutcome.Success.class, second);
        session.close();
        session.close();
        assertThrows(IllegalStateException.class, session::operations);
        assertThrows(UnsupportedOperationException.class,
                () -> ((PkiOperationOutcome.Success) first).result().fields().put("x", new PkiOperationValue.Text("y")));
        System.out.println("...ok");
    }

    @Test
    void validatesBeforeAllocationAndCleansPartialConstruction() {
        System.out.println("validatesBeforeAllocationAndCleansPartialConstruction");
        PkiSessionConfiguration configuration = configuration(temporaryDirectory.resolve("unused"));
        AtomicInteger storesOpened = new AtomicInteger();
        AtomicInteger storesClosed = new AtomicInteger();
        DefaultPkiSession.Bootstrap invalid = bootstrap(storesOpened, storesClosed, true, false, false, false);
        assertThrows(IllegalArgumentException.class,
                () -> DefaultPkiSession.open(configuration, CLOCK, invalid));
        assertEquals(0, storesOpened.get());

        DefaultPkiSession.Bootstrap partial = bootstrap(storesOpened, storesClosed, false, true, false, false);
        assertThrows(IllegalStateException.class,
                () -> DefaultPkiSession.open(configuration, CLOCK, partial));
        System.out.println("...partialStoreCloses=" + storesClosed.get());
        assertEquals(1, storesClosed.get());
        System.out.println("...ok");
    }

    @Test
    void preservesPrimaryAndSuppressedCloseFailures() throws Exception {
        System.out.println("preservesPrimaryAndSuppressedCloseFailures");
        PkiSessionConfiguration configuration = configuration(temporaryDirectory.resolve("unused-close"));
        DefaultPkiSession.Bootstrap bootstrap = bootstrap(new AtomicInteger(), new AtomicInteger(), false, false,
                true, true);
        PkiSession session = DefaultPkiSession.open(configuration, CLOCK, bootstrap);
        Exception failure = assertThrows(Exception.class, session::close);
        System.out.println("...suppressed=" + failure.getSuppressed().length);
        assertEquals("audit-close", failure.getMessage());
        assertEquals(1, failure.getSuppressed().length);
        assertInstanceOf(IOException.class, failure.getSuppressed()[0]);
        session.close();
        System.out.println("...ok");
    }

    private static PkiSessionConfiguration configuration(Path storeRoot) {
        return new PkiSessionConfiguration(1, new ProviderConfig("fs", Map.of("root", storeRoot.toString())),
                new ProviderConfig("memory", Map.of("size", "16")));
    }

    private static DefaultPkiSession.Bootstrap bootstrap(AtomicInteger storesOpened, AtomicInteger storesClosed,
            boolean invalidAudit, boolean failAuditOpen, boolean failAuditClose, boolean failStoreClose) {
        return new DefaultPkiSession.Bootstrap() {
            @Override
            public void validateStore(ProviderConfig configuration) {
                // valid
            }

            @Override
            public void validateAudit(ProviderConfig configuration) {
                if (invalidAudit) {
                    throw new IllegalArgumentException("invalid");
                }
            }

            @Override
            public PkiStore openStore(ProviderConfig configuration) {
                storesOpened.incrementAndGet();
                return proxyStore(() -> {
                    storesClosed.incrementAndGet();
                    if (failStoreClose) {
                        throw new IOException("store-close");
                    }
                });
            }

            @Override
            public AuditSink openAudit(ProviderConfig configuration) {
                if (failAuditOpen) {
                    throw new IllegalStateException("audit-open");
                }
                return new AuditSink() {
                    @Override
                    public void record(zeroecho.pki.api.audit.AuditEvent event) {
                        // no-op
                    }

                    @Override
                    public void close() {
                        if (failAuditClose) {
                            throw new IllegalStateException("audit-close");
                        }
                    }
                };
            }
        };
    }

    private static PkiStore proxyStore(CloseAction close) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> {
                    if ("close".equals(method.getName())) {
                        close.close();
                        return null;
                    }
                    if ("toString".equals(method.getName())) {
                        return "test-store";
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    @FunctionalInterface
    private interface CloseAction {
        void close() throws Exception;
    }
}
