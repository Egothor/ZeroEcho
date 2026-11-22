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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.spi.audit.AuditSink;

/**
 * Covers stable break-glass persistence identities and the minimal best-effort use audit contract.
 */
class BreakGlassServiceContractTest {
    @TempDir
    Path directory;

    @ParameterizedTest
    @CsvSource({"1, ACTIVE", "2, REVOKED", "3, EXPIRED", "4, PENDING"})
    void decodesTheStablePersistedLifecycleCodes(int code, BreakGlassService.State expected) {
        assertEquals(expected, BreakGlassService.State.fromCode(code));
        assertEquals(code, expected.code());
    }

    @ParameterizedTest
    @ValueSource(ints = {Integer.MIN_VALUE, -1, 0, 5, Integer.MAX_VALUE})
    void rejectsCodesOutsideThePersistedLifecycleDomain(int code) {
        assertThrows(IllegalArgumentException.class, () -> BreakGlassService.State.fromCode(code));
    }

    @Test
    void auditUseRecordsOnlyTheSafeUsageClassificationWithoutChangingTheGrant() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            BreakGlassService.Record retained = retainActiveGrant(opened.store());
            List<AuditEvent> events = new ArrayList<>();
            BreakGlassService service = new BreakGlassService(opened.store(), ServerTestSupport.CLOCK, events::add);

            service.auditUse("officer");

            assertEquals(1, events.size());
            AuditEvent event = events.getFirst();
            assertEquals(ServerTestSupport.CLOCK.instant(), event.time());
            assertEquals("SERVER_SECURITY", event.category());
            assertEquals("BREAK_GLASS_USE", event.action());
            assertEquals(new Principal("SERVER_PRINCIPAL", "officer"), event.principal());
            assertEquals(new Purpose("SERVER_CONTROL"), event.purpose());
            assertTrue(event.objectId().isEmpty());
            assertTrue(event.formatId().isEmpty());
            // Exact equality also excludes retained grant contents and the emergency reason.
            assertEquals(Map.of("used", "true"), event.details());
            assertEquals(retained, opened.store().requireBreakGlass(retained.breakGlassId()));
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 256})
    void auditUsePreservesUpstreamCanonicalPrincipalBoundaryLengths(int length) throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            // These are upstream identity boundaries, not an extra length check in auditUse.
            String principal = "p".repeat(length);
            assertEquals(principal, Permission.requirePrincipal(principal));
            AtomicReference<AuditEvent> captured = new AtomicReference<>();
            BreakGlassService service = new BreakGlassService(opened.store(), ServerTestSupport.CLOCK, captured::set);

            service.auditUse(principal);

            AuditEvent event = captured.get();
            assertNotNull(event);
            assertEquals(principal, event.principal().name());
            assertEquals(Map.of("used", "true"), event.details());
        }
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" "})
    void auditUseSuppressesInvalidAuditEventIdentityWithoutChangingTheGrant(String principal) throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            BreakGlassService.Record retained = retainActiveGrant(opened.store());
            List<AuditEvent> events = new ArrayList<>();
            BreakGlassService service = new BreakGlassService(opened.store(), ServerTestSupport.CLOCK, events::add);

            assertDoesNotThrow(() -> service.auditUse(principal));

            assertTrue(events.isEmpty());
            assertEquals(retained, opened.store().requireBreakGlass(retained.breakGlassId()));
        }
    }

    @Test
    void auditUseSuppressesSinkFailureAndCanDeliverTheNextUsageEvent() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            BreakGlassService.Record retained = retainActiveGrant(opened.store());
            AtomicInteger attempts = new AtomicInteger();
            List<AuditEvent> delivered = new ArrayList<>();
            AuditSink recovering = event -> {
                if (attempts.getAndIncrement() == 0) { throw new IllegalStateException("Fixture audit sink unavailable"); }
                delivered.add(event);
            };
            BreakGlassService service = new BreakGlassService(opened.store(), ServerTestSupport.CLOCK, recovering);

            assertDoesNotThrow(() -> service.auditUse("officer"));
            assertTrue(delivered.isEmpty());
            assertEquals(retained, opened.store().requireBreakGlass(retained.breakGlassId()));
            assertDoesNotThrow(() -> service.auditUse("officer"));

            assertEquals(2, attempts.get());
            assertEquals(1, delivered.size());
            assertEquals("BREAK_GLASS_USE", delivered.getFirst().action());
            assertEquals("officer", delivered.getFirst().principal().name());
            assertEquals(Map.of("used", "true"), delivered.getFirst().details());
            assertEquals(retained, opened.store().requireBreakGlass(retained.breakGlassId()));
        }
    }

    @Test
    void auditUseCompletesWhileAnotherThreadOwnsTheControlStoreMonitor() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            AtomicReference<AuditEvent> captured = new AtomicReference<>();
            AtomicReference<Throwable> failure = new AtomicReference<>();
            CountDownLatch finished = new CountDownLatch(1);
            BreakGlassService service = new BreakGlassService(opened.store(), ServerTestSupport.CLOCK, captured::set);
            Thread emitter = Thread.ofPlatform().daemon().name("break-glass-use-audit").unstarted(() -> {
                try {
                    service.auditUse("officer");
                } catch (Throwable unexpected) {
                    failure.set(unexpected);
                } finally {
                    finished.countDown();
                }
            });
            try {
                synchronized (opened.store()) {
                    emitter.start();
                    assertTrue(finished.await(2, TimeUnit.SECONDS),
                            "Best-effort usage telemetry waited for the held control authority");
                }
            } finally {
                emitter.join(TimeUnit.SECONDS.toMillis(5));
                if (emitter.isAlive()) { emitter.interrupt(); }
            }
            assertFalse(emitter.isAlive(), "Usage telemetry fixture thread did not finish");
            assertNull(failure.get());
            assertNotNull(captured.get());
            assertEquals(Map.of("used", "true"), captured.get().details());
        }
    }

    private static BreakGlassService.Record retainActiveGrant(ServerControlStore store) {
        Instant now = ServerTestSupport.CLOCK.instant();
        Permission.Grant grant = ServerTestSupport.grant("private-emergency-grant", "officer", Permission.Effect.ALLOW,
                Permission.Action.CERTIFICATE_REVOKE, Permission.ResourceType.REVOCATION,
                ServerTestSupport.scope(), Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED);
        BreakGlassService.Record retained = new BreakGlassService.Record("private-emergency", "officer", grant,
                "Fixture reason that must not enter the usage audit", "independent-issuer", Optional.empty(), now,
                Optional.of(now), now.plusSeconds(60), BreakGlassService.State.ACTIVE, ServerTestSupport.DIGEST);
        store.createBreakGlass(retained);
        return retained;
    }
}
