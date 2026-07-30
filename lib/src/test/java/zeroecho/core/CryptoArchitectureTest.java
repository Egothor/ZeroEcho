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
package zeroecho.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import zeroecho.core.audit.AuditListener;
import zeroecho.core.audit.AuditMode;
import zeroecho.core.context.DigestContext;
import zeroecho.sdk.ZeroEchoSession;

/**
 * Verifies authoritative registry ownership and explicitly scoped runtime
 * state.
 */
class CryptoArchitectureTest {

    @Test
    void authoritativeRegistry() {
        System.out.println("authoritativeRegistry");
        CryptoCatalog catalog = CryptoCatalog.load();

        assertSame(CryptoAlgorithms.registry(), catalog.algorithms());
        assertEquals(CryptoAlgorithms.available(), catalog.algorithms().keySet());
        for (String id : CryptoAlgorithms.available()) {
            assertSame(CryptoAlgorithms.require(id), catalog.algorithms().get(id));
        }

        System.out.println("...providerCount=" + CryptoAlgorithms.available().size());
        System.out.println("authoritativeRegistry...ok");
    }

    @Test
    void explicitPolicyOrder() throws Exception {
        System.out.println("explicitPolicyOrder");
        List<String> events = new ArrayList<>();
        AuditListener listener = policyOrderListener(events);
        ZeroEchoSession allowed = new ZeroEchoSession().withAuditListener(listener)
                .withPolicy((id, role, key, spec) -> events.add("policy"));
        try (DigestContext context = allowed.createContext("DIGEST", KeyUsage.DIGEST, NullKey.INSTANCE)) {
            assertSame(CryptoAlgorithms.require("DIGEST"), context.algorithm());
        }
        assertEquals(List.of("policy", "audit"), events);

        events.clear();
        IllegalArgumentException denial = new IllegalArgumentException("controlled denial");
        ZeroEchoSession denied = new ZeroEchoSession().withAuditListener(listener).withPolicy((id, role, key, spec) -> {
            events.add("policy");
            throw denial;
        });
        assertSame(denial, assertThrows(IllegalArgumentException.class,
                () -> denied.createContext("DIGEST", KeyUsage.DIGEST, NullKey.INSTANCE)));
        assertEquals(List.of("policy"), events);

        events.clear();
        IllegalStateException failure = new IllegalStateException("controlled policy failure");
        ZeroEchoSession failing = new ZeroEchoSession().withAuditListener(listener)
                .withPolicy((id, role, key, spec) -> {
                    events.add("policy");
                    throw failure;
                });
        assertSame(failure, assertThrows(IllegalStateException.class,
                () -> failing.createContext("DIGEST", KeyUsage.DIGEST, NullKey.INSTANCE)));
        assertEquals(List.of("policy"), events);

        System.out.println("...allow=1...deny=1...failure=1");
        System.out.println("explicitPolicyOrder...ok");
    }

    @Test
    void isolatedAuditConfiguration() throws Exception {
        System.out.println("isolatedAuditConfiguration");
        AtomicInteger firstEvents = new AtomicInteger();
        AtomicInteger secondEvents = new AtomicInteger();
        AuditListener firstListener = contextListener(firstEvents);
        AuditListener secondListener = contextListener(secondEvents);
        ZeroEchoSession wrapped = new ZeroEchoSession().withAuditListener(firstListener).withAuditMode(AuditMode.WRAP);
        ZeroEchoSession direct = new ZeroEchoSession().withAuditListener(secondListener);

        try (DigestContext wrappedContext = wrapped.createContext("DIGEST", KeyUsage.DIGEST, NullKey.INSTANCE)) {
            assertTrue(Proxy.isProxyClass(wrappedContext.getClass()));
        }
        int wrappedEvents = firstEvents.get();
        assertTrue(wrappedEvents > 0);
        assertEquals(0, secondEvents.get());
        try (DigestContext directContext = direct.createContext("DIGEST", KeyUsage.DIGEST, NullKey.INSTANCE)) {
            assertTrue(!Proxy.isProxyClass(directContext.getClass()));
        }
        assertEquals(wrappedEvents, firstEvents.get());
        assertEquals(1, secondEvents.get());
        assertEquals(AuditMode.WRAP, wrapped.auditMode());
        assertEquals(AuditMode.OFF, direct.auditMode());

        System.out.println("...firstEvents=" + firstEvents.get());
        System.out.println("...secondEvents=" + secondEvents.get());
        System.out.println("isolatedAuditConfiguration...ok");
    }

    @Test
    void immutableSessionChanges() {
        System.out.println("immutableSessionChanges");
        ZeroEchoSession base = new ZeroEchoSession();
        ZeroEchoSession changed = base.withAuditMode(AuditMode.WRAP)
                .withAuditListener(contextListener(new AtomicInteger()));

        assertNotSame(base, changed);
        assertEquals(AuditMode.OFF, base.auditMode());
        assertEquals(AuditMode.WRAP, changed.auditMode());
        assertNotSame(base.auditListener(), changed.auditListener());

        System.out.println("...baseMode=" + base.auditMode());
        System.out.println("...changedMode=" + changed.auditMode());
        System.out.println("immutableSessionChanges...ok");
    }

    @Test
    void concurrentSessionReads() throws Exception {
        System.out.println("concurrentSessionReads");
        ZeroEchoSession session = new ZeroEchoSession().withAuditMode(AuditMode.MANUAL);
        int taskCount = 16;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<Boolean>> futures = new ArrayList<>();
            for (int index = 0; index < taskCount; index++) {
                futures.add(executor.submit(() -> {
                    start.await();
                    for (int iteration = 0; iteration < 500; iteration++) {
                        if (session.auditMode() != AuditMode.MANUAL || session.available().isEmpty()
                                || session.require("DIGEST") != CryptoAlgorithms.require("DIGEST")) {
                            return Boolean.FALSE;
                        }
                    }
                    return Boolean.TRUE;
                }));
            }
            start.countDown();
            for (Future<Boolean> future : futures) {
                assertTrue(future.get().booleanValue());
            }
        } finally {
            executor.shutdownNow();
        }

        System.out.println("...completedTasks=" + taskCount);
        System.out.println("concurrentSessionReads...ok");
    }

    @Test
    void manualModeSilent() throws Exception {
        System.out.println("manualModeSilent");
        AtomicInteger events = new AtomicInteger();
        ZeroEchoSession session = new ZeroEchoSession().withAuditListener(contextListener(events))
                .withAuditMode(AuditMode.MANUAL);

        try (DigestContext context = session.createContext("DIGEST", KeyUsage.DIGEST, NullKey.INSTANCE)) {
            assertTrue(!Proxy.isProxyClass(context.getClass()));
        }

        assertEquals(0, events.get());
        System.out.println("...events=" + events.get());
        System.out.println("manualModeSilent...ok");
    }

    private static AuditListener contextListener(AtomicInteger count) {
        return new AuditListener() {
            @Override
            public void onContextCreatedMeta(String contextId, String algorithmId, String provider, KeyUsage role,
                    String keyFingerprint, java.util.Map<String, Object> specMeta) {
                count.incrementAndGet();
            }
        };
    }

    private static AuditListener policyOrderListener(List<String> events) {
        return new AuditListener() {
            @Override
            public void onContextCreatedMeta(String contextId, String algorithmId, String provider, KeyUsage role,
                    String keyFingerprint, java.util.Map<String, Object> specMeta) {
                events.add("audit");
            }
        };
    }
}
