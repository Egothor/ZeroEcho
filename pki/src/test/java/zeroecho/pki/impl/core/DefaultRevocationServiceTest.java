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
package zeroecho.pki.impl.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationQuery;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.RevocationSnapshot;
import zeroecho.core.io.CancellationSignal;

final class DefaultRevocationServiceTest {
    private static final Instant NOW = Instant.parse("2026-07-01T12:00:00Z");
    private static final PkiId CREDENTIAL_ID = new PkiId("credential:audit");

    @Test
    void successAuditsCommittedStateAndRevisionOnce() {
        RevocationRecord committed = new RevocationRecord(CREDENTIAL_ID,
                new RevocationTransition(1L, RevocationState.HELD, NOW, Optional.empty(), new SimpleAttributeSet()));
        List<AuditEvent> events = new ArrayList<>();
        DefaultRevocationService service = new DefaultRevocationService(store((method, arguments) -> {
            if ("transitionRevocation".equals(method)) {
                return committed;
            }
            throw new UnsupportedOperationException(method);
        }), Clock.fixed(NOW, ZoneOffset.UTC), events::add);

        assertEquals(committed, service.hold(new RevocationCommand.Hold(CREDENTIAL_ID, new SimpleAttributeSet())));
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
            if ("getRevocation".equals(method)) {
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
    void appendUncertaintyPreservesRecoveryRequiredCodeAndAuditsOnce() {
        List<AuditEvent> events = new ArrayList<>();
        DefaultRevocationService service = new DefaultRevocationService(store((method, arguments) -> {
            if ("transitionRevocation".equals(method)) {
                throw new PkiException("Revocation append outcome is unknown: code=REVOCATION_RECOVERY_REQUIRED");
            }
            if ("getRevocation".equals(method)) {
                return Optional.empty();
            }
            throw new UnsupportedOperationException(method);
        }), Clock.fixed(NOW, ZoneOffset.UTC), events::add);

        PkiException failure = assertThrows(PkiException.class,
                () -> service.hold(new RevocationCommand.Hold(CREDENTIAL_ID, new SimpleAttributeSet())));
        assertEquals("Revocation operation failed: code=REVOCATION_RECOVERY_REQUIRED", failure.getMessage());
        assertNull(failure.getCause());
        assertEquals(1, events.size());
        assertEquals("REJECTED", events.get(0).details().get("result"));
        assertEquals("REVOCATION_RECOVERY_REQUIRED", events.get(0).details().get("code"));
    }

    @Test
    void delayedIssuerFilterFailureIsRedactedAtCursorBoundary() throws Exception {
        String sentinel = "DO_NOT_EXPOSE_DELAYED_STORE_SENTINEL";
        RevocationRecord record = new RevocationRecord(CREDENTIAL_ID,
                new RevocationTransition(1L, RevocationState.HELD, NOW,
                        Optional.empty(), new SimpleAttributeSet()));
        RevocationSnapshot source = singleRecordSnapshot(record);
        DefaultRevocationService service = new DefaultRevocationService(store((method, arguments) -> {
            if ("openRevocationSnapshot".equals(method)) {
                return source;
            }
            if ("getCredential".equals(method)) {
                throw new IllegalStateException(sentinel);
            }
            throw new UnsupportedOperationException(method);
        }), Clock.fixed(NOW, ZoneOffset.UTC), event -> { });
        RevocationQuery query = new RevocationQuery(Optional.of(new PkiId("ca:issuer")),
                Optional.empty(), Optional.empty(), Optional.empty());

        try (RevocationSnapshot snapshot = service.search(query);
                RevocationSnapshot.Cursor cursor = snapshot.openCursor()) {
            PkiException failure = assertThrows(PkiException.class, cursor::next);
            assertEquals("Revocation operation failed: code=REVOCATION_STATE_UPDATE_FAILED", failure.getMessage());
            assertNull(failure.getCause());
            assertFalse(failure.toString().contains(sentinel));
        }
    }

    private static RevocationSnapshot singleRecordSnapshot(RevocationRecord record) {
        return new RevocationSnapshot() {
            @Override public String snapshotId() { return "snapshot:test"; }
            @Override public long revision() { return 1L; }
            @Override public long boundary() { return 1L; }
            @Override public String commitment() { return "00"; }
            @Override public OptionalLong count() { return OptionalLong.of(1L); }
            @Override public Cursor openCursor() {
                return new Cursor() {
                    private boolean advanced;
                    @Override public boolean next(CancellationSignal cancellation) {
                        if (advanced) {
                            return false;
                        }
                        advanced = true;
                        return true;
                    }
                    @Override public RevocationRecord current() { return record; }
                    @Override public long ordinal() { return 0L; }
                    @Override public void close() { }
                };
            }
            @Override public void close() throws IOException { }
        };
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
