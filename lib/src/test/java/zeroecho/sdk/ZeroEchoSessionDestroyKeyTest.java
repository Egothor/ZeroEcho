/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Key;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.junit.jupiter.api.Test;

import zeroecho.core.audit.AuditListener;

class ZeroEchoSessionDestroyKeyTest {
    @Test
    void strictDestroyDistinguishesEveryLifecycleOutcome() throws Exception {
        System.out.print("ZeroEchoSession/destroy-strict...");
        AtomicInteger audits = new AtomicInteger();
        ZeroEchoSession session = new ZeroEchoSession().withAuditListener(new AuditListener() {
            @Override
            public void onKeyDestroyed(String id, String provider, Key key) {
                audits.incrementAndGet();
            }
        });

        TestKey success = new TestKey(Behavior.SUCCESS);
        assertTrue(session.destroyKey("test", "provider", success));
        assertFalse(session.destroyKey("test", "provider", success));
        assertEquals(1, audits.get());
        assertFalse(session.destroyKey("test", "provider", new PlainKey()));
        assertThrows(NullPointerException.class, () -> session.destroyKey("test", "provider", null));
        assertThrows(DestroyFailedException.class,
                () -> session.destroyKey("test", "provider", new TestKey(Behavior.FAIL_CHECKED)));
        assertThrows(DestroyFailedException.class,
                () -> session.destroyKey("test", "provider", new TestKey(Behavior.NO_TRANSITION)));
        assertThrows(IllegalStateException.class,
                () -> session.destroyKey("test", "provider", new TestKey(Behavior.FAIL_RUNTIME)));
        assertEquals(1, audits.get());
        System.out.println("ok");
    }

    @Test
    void concurrentStrictDestroyReportsAndAuditsOneTransition() throws Exception {
        System.out.print("ZeroEchoSession/destroy-concurrent...");
        AtomicInteger audits = new AtomicInteger();
        ZeroEchoSession session = new ZeroEchoSession().withAuditListener(new AuditListener() {
            @Override
            public void onKeyDestroyed(String id, String provider, Key key) {
                audits.incrementAndGet();
            }
        });
        BlockingKey key = new BlockingKey();
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> first = executor.submit(() -> session.destroyKey("test", "provider", key));
            key.destroyEntered.await();
            Future<Boolean> second = executor.submit(() -> session.destroyKey("test", "provider", key));
            key.allowDestroy.countDown();

            boolean firstResult = first.get();
            boolean secondResult = second.get();
            assertTrue(firstResult ^ secondResult);
            assertEquals(1, audits.get());
            assertEquals(1, key.destroyCalls.get());
        } finally {
            executor.shutdownNow();
        }
        System.out.println("ok");
    }

    private enum Behavior {
        SUCCESS, FAIL_CHECKED, FAIL_RUNTIME, NO_TRANSITION
    }

    private static final class TestKey implements Key, Destroyable {
        private static final long serialVersionUID = 1L;
        private static final String SECRET = "secret-key-marker";
        private final Behavior behavior;
        private boolean destroyed;
        private boolean encodedCalled;
        private boolean toStringCalled;

        private TestKey(Behavior behavior) {
            this.behavior = behavior;
        }

        @Override
        public void destroy() throws DestroyFailedException {
            switch (behavior) {
                case SUCCESS -> destroyed = true;
                case FAIL_CHECKED -> throw new DestroyFailedException(SECRET);
                case FAIL_RUNTIME -> throw new IllegalStateException(SECRET);
                case NO_TRANSITION -> {
                    // Intentionally does not transition.
                }
            }
        }

        @Override
        public boolean isDestroyed() {
            return destroyed;
        }

        @Override
        public String getAlgorithm() {
            return "test";
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            encodedCalled = true;
            return SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }

        @Override
        public String toString() {
            toStringCalled = true;
            return SECRET;
        }
    }

    private static final class PlainKey implements Key {
        private static final long serialVersionUID = 1L;

        @Override
        public String getAlgorithm() {
            return "plain";
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }
    }

    private static final class BlockingKey implements Key, Destroyable {
        private static final long serialVersionUID = 1L;
        private final CountDownLatch destroyEntered = new CountDownLatch(1);
        private final CountDownLatch allowDestroy = new CountDownLatch(1);
        private final AtomicInteger destroyCalls = new AtomicInteger();
        private boolean destroyed;

        @Override
        public void destroy() throws DestroyFailedException {
            destroyCalls.incrementAndGet();
            destroyEntered.countDown();
            try {
                allowDestroy.await();
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new DestroyFailedException("Interrupted while testing destruction");
            }
            destroyed = true;
        }

        @Override
        public boolean isDestroyed() {
            return destroyed;
        }

        @Override
        public String getAlgorithm() {
            return "test";
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }
    }

}
