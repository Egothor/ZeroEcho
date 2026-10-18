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
package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.reflect.InvocationTargetException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.store.PkiStore;

class PkiSessionCloseContractTest {
    @TempDir Path directory;

    @Test
    void preservesIoUncheckedAndErrorIdentity() throws Exception {
        System.out.println("preservesIoUncheckedAndErrorIdentity");
        for (Throwable failure : List.of(new IOException("I/O"), new IllegalStateException("runtime"),
                new AssertionError("error"))) {
            assertSame(failure, translate(failure));
        }
        assertFalse(Thread.currentThread().isInterrupted());
        System.out.println("...ok");
    }

    @Test
    void translatesCheckedFailuresWithoutFlatteningSuppression() throws Exception {
        System.out.println("translatesCheckedFailuresWithoutFlatteningSuppression");
        Exception original = new ReflectiveOperationException("checked");
        IOException later = new IOException("later");
        original.addSuppressed(later);
        Throwable translated = translate(original);
        assertInstanceOf(IOException.class, translated);
        assertSame(original, translated.getCause());
        assertSame(later, original.getSuppressed()[0]);
        assertEquals(0, translated.getSuppressed().length);
        System.out.println("...ok");
    }

    @Test
    void restoresPrimaryAndSuppressedInterruptionEvenInCyclicGraphs() throws Exception {
        System.out.println("restoresPrimaryAndSuppressedInterruptionEvenInCyclicGraphs");
        assertFalse(Thread.currentThread().isInterrupted());
        try {
            InterruptedException interrupted = new InterruptedException("interrupted");
            Throwable translated = translate(interrupted);
            assertInstanceOf(InterruptedIOException.class, translated);
            assertSame(interrupted, translated.getCause());
            assertTrue(Thread.interrupted());
            IOException primary = new IOException("primary");
            primary.addSuppressed(interrupted);
            interrupted.addSuppressed(primary);
            assertSame(primary, translate(primary));
            assertTrue(Thread.currentThread().isInterrupted());
            assertSame(interrupted, primary.getSuppressed()[0]);
        } finally {
            Thread.interrupted();
        }
        System.out.println("...ok");
    }

    @Test
    void actualSessionClosesAuditBeforeStorePreservesFailuresAndClosesOnce() throws Exception {
        System.out.println("actualSessionClosesAuditBeforeStorePreservesFailuresAndClosesOnce");
        List<String> order = new ArrayList<>();
        IllegalStateException primary = new IllegalStateException("audit");
        IOException later = new IOException("store", new InterruptedException("suppressed interruption"));
        DefaultPkiSession.Bootstrap bootstrap = new DefaultPkiSession.Bootstrap() {
            @Override public void validateStore(ProviderConfig configuration) { }
            @Override public void validateAudit(ProviderConfig configuration) { }
            @Override public PkiStore openStore(ProviderConfig configuration) {
                PkiStore delegate = PkiBootstrap.openStore(configuration);
                return (PkiStore) java.lang.reflect.Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                        new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                            if (method.getName().equals("close")) {
                                order.add("store");
                                delegate.close();
                                throw later;
                            }
                            try {
                                return method.invoke(delegate, arguments);
                            } catch (InvocationTargetException failure) {
                                throw failure.getCause();
                            }
                        });
            }
            @Override public AuditSink openAudit(ProviderConfig configuration) {
                return new AuditSink() {
                    @Override public void record(zeroecho.pki.api.audit.AuditEvent event) { }
                    @Override public void close() {
                        order.add("audit");
                        throw primary;
                    }
                };
            }
        };
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", directory.resolve("store").toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.empty(), List.of(), List.of());
        PkiSession session = DefaultPkiSession.open(configuration, Clock.systemUTC(), bootstrap);
        try {
            assertSame(primary, assertThrows(IllegalStateException.class, session::close));
            assertSame(later, primary.getSuppressed()[0]);
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
        assertEquals(List.of("audit", "store"), order);
        session.close();
        assertEquals(2, order.size());
        assertThrows(IllegalStateException.class, session::operations);
        System.out.println("...ok");
    }

    /** Invokes the shared translation used by both early reactor and aggregate teardown failures. */
    private static Throwable translate(Throwable failure) throws ReflectiveOperationException {
        var method = DefaultPkiSession.class.getDeclaredMethod("rethrow", Throwable.class);
        method.setAccessible(true);
        InvocationTargetException thrown = assertThrows(InvocationTargetException.class,
                () -> method.invoke(null, failure));
        return thrown.getCause();
    }
}
