/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.impl.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationJournal;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.PkiStore;

final class DefaultRevocationServiceTest {
    private static final Instant NOW = Instant.parse("2026-07-01T12:00:00Z");
    private static final PkiId CREDENTIAL_ID = new PkiId("credential:audit");

    @Test
    void successAuditsCommittedStateAndRevisionOnce() {
        RevocationJournal committed = new RevocationJournal(CREDENTIAL_ID,
                List.of(new RevocationTransition(1L, RevocationState.HELD, NOW, Optional.empty(),
                        new SimpleAttributeSet())));
        List<AuditEvent> events = new ArrayList<>();
        DefaultRevocationService service = new DefaultRevocationService(store((method, arguments) -> {
            if ("transitionRevocation".equals(method)) {
                return committed;
            }
            throw new UnsupportedOperationException(method);
        }), Clock.fixed(NOW, ZoneOffset.UTC), events::add);

        assertEquals(committed,
                service.hold(new RevocationCommand.Hold(CREDENTIAL_ID, new SimpleAttributeSet())));
        assertEquals(1, events.size());
        assertEquals("COMMITTED", events.get(0).details().get("result"));
        assertEquals("HELD", events.get(0).details().get("state"));
        assertEquals("1", events.get(0).details().get("revision"));
    }

    @Test
    void hostileStoreFailureIsRedactedAndProducesOnlyOneRejectionAudit() {
        String sentinel = "DO_NOT_EXPOSE_REVOCATION_STORE_SENTINEL";
        List<AuditEvent> events = new ArrayList<>();
        AtomicBoolean lookupAttempted = new AtomicBoolean();
        DefaultRevocationService service = new DefaultRevocationService(store((method, arguments) -> {
            if ("transitionRevocation".equals(method)) {
                throw new IllegalStateException(sentinel);
            }
            if ("getRevocationJournal".equals(method)) {
                lookupAttempted.set(true);
                throw new IllegalStateException(sentinel);
            }
            throw new UnsupportedOperationException(method);
        }), Clock.fixed(NOW, ZoneOffset.UTC), events::add);

        PkiException failure = assertThrows(PkiException.class,
                () -> service.hold(new RevocationCommand.Hold(CREDENTIAL_ID, new SimpleAttributeSet())));
        assertEquals("Revocation operation failed: code=REVOCATION_STATE_UPDATE_FAILED", failure.getMessage());
        assertNull(failure.getCause());
        assertFalse(failure.toString().contains(sentinel));
        assertEquals(1, events.size());
        assertEquals("REJECTED", events.get(0).details().get("result"));
        assertEquals("REVOCATION_STATE_UPDATE_FAILED", events.get(0).details().get("code"));
        assertFalse(events.toString().contains(sentinel));
        assertTrue(lookupAttempted.get());
    }

    @Test
    void hostileClockFailureIsRedactedAuditedOnceAndNeverReachesStoreTransition() {
        String sentinel = "DO_NOT_EXPOSE_REVOCATION_CLOCK_SENTINEL";
        List<AuditEvent> events = new ArrayList<>();
        AtomicBoolean storeInvoked = new AtomicBoolean();
        Clock failingClock = new Clock() {
            @Override
            public ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                throw new IllegalStateException(sentinel);
            }
        };
        DefaultRevocationService service = new DefaultRevocationService(store((method, arguments) -> {
            storeInvoked.set(true);
            throw new AssertionError("Store must not be invoked after clock failure");
        }), failingClock, events::add);

        PkiException failure = assertThrows(PkiException.class,
                () -> service.hold(new RevocationCommand.Hold(CREDENTIAL_ID, new SimpleAttributeSet())));
        assertEquals("Revocation operation failed: code=REVOCATION_TIME_UNAVAILABLE", failure.getMessage());
        assertNull(failure.getCause());
        assertFalse(failure.toString().contains(sentinel));
        assertFalse(storeInvoked.get());
        assertEquals(1, events.size());
        assertEquals("REJECTED", events.get(0).details().get("result"));
        assertEquals("REVOCATION_TIME_UNAVAILABLE", events.get(0).details().get("code"));
        assertFalse(events.toString().contains(sentinel));
    }

    private static PkiStore store(Invocation invocation) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> invocation.invoke(method.getName(), arguments));
    }

    @FunctionalInterface
    private interface Invocation {
        Object invoke(String method, Object[] arguments);
    }
}
