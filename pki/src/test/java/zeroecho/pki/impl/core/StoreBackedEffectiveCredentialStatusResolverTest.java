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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.CredentialUse;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.revocation.RevocationJournal;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.PkiStore;

final class StoreBackedEffectiveCredentialStatusResolverTest {
    private static final Instant NOW = Instant.parse("2026-06-01T12:00:00Z");

    @Test
    void resolvesInventoryValidityAndCurrentRevocationPrecedence() {
        Credential usable = credential("usable", CredentialStatus.ISSUED, NOW.minusSeconds(60), NOW.plusSeconds(60));
        assertStatus(usable, Optional.empty(), EffectiveCredentialStatus.USABLE);

        Credential future = credential("future", CredentialStatus.ISSUED, NOW.plusSeconds(1), NOW.plusSeconds(60));
        assertStatus(future, Optional.empty(), EffectiveCredentialStatus.NOT_YET_VALID);

        Credential exactNotAfter = credential("boundary", CredentialStatus.ISSUED, NOW.minusSeconds(60), NOW);
        assertStatus(exactNotAfter, Optional.empty(), EffectiveCredentialStatus.USABLE);

        Credential expiredByTime = credential("expired-time", CredentialStatus.ISSUED, NOW.minusSeconds(60),
                NOW.minusNanos(1));
        assertStatus(expiredByTime, Optional.empty(), EffectiveCredentialStatus.EXPIRED);

        Credential expiredMetadata = credential("expired-metadata", CredentialStatus.EXPIRED, NOW.minusSeconds(60),
                NOW.plusSeconds(60));
        assertStatus(expiredMetadata, Optional.empty(), EffectiveCredentialStatus.EXPIRED);

        Credential held = credential("held", CredentialStatus.ISSUED, NOW.minusSeconds(60), NOW.plusSeconds(60));
        assertStatus(held, revocation(held, RevocationReason.CERTIFICATE_HOLD, NOW), EffectiveCredentialStatus.HELD);

        Credential revoked = credential("revoked", CredentialStatus.ISSUED, NOW.minusSeconds(60), NOW.plusSeconds(60));
        assertStatus(revoked, revocation(revoked, RevocationReason.KEY_COMPROMISE, NOW),
                EffectiveCredentialStatus.PERMANENTLY_REVOKED);
    }

    @Test
    void embeddedRevokedIsPermanentFloorAcrossHoldAndUnholdRecords() {
        Credential revoked = credential("floor", CredentialStatus.REVOKED, NOW.minusSeconds(60), NOW.plusSeconds(60));
        assertStatus(revoked, Optional.empty(), EffectiveCredentialStatus.PERMANENTLY_REVOKED);
        assertStatus(revoked, revocation(revoked, RevocationReason.CERTIFICATE_HOLD, NOW),
                EffectiveCredentialStatus.PERMANENTLY_REVOKED);
        assertStatus(revoked, revocation(revoked, RevocationReason.REMOVE_FROM_CRL, NOW),
                EffectiveCredentialStatus.PERMANENTLY_REVOKED);
    }

    @Test
    void futureAndMismatchedJournalsFailClosed() {
        Credential credential = credential("invalid", CredentialStatus.ISSUED, NOW.minusSeconds(60),
                NOW.plusSeconds(60));
        assertResolutionFailure(credential, revocation(credential, RevocationReason.KEY_COMPROMISE, NOW.plusNanos(1)));
        RevocationJournal mismatch = new RevocationJournal(new PkiId("credential:other"),
                List.of(new RevocationTransition(1L, RevocationState.PERMANENTLY_REVOKED, NOW,
                        Optional.of(RevocationReason.KEY_COMPROMISE), new SimpleAttributeSet())));
        assertResolutionFailure(credential, Optional.of(mismatch));
    }

    @Test
    void lookupFailureIsRedactedAndRequireUsableUsesStableCode() {
        Credential credential = credential("failure", CredentialStatus.ISSUED, NOW.minusSeconds(60),
                NOW.plusSeconds(60));
        PkiStore failing = store(id -> {
            throw new IllegalStateException("DO_NOT_EXPOSE_REVOCATION_SENTINEL");
        }, new AtomicInteger());
        StoreBackedEffectiveCredentialStatusResolver resolver = new StoreBackedEffectiveCredentialStatusResolver(
                failing, Clock.fixed(NOW, ZoneOffset.UTC));

        PkiException failure = assertThrows(PkiException.class, () -> resolver.beginEvaluation().resolve(credential));
        assertEquals("Credential status resolution failed: code=CREDENTIAL_STATUS_RESOLUTION_FAILED",
                failure.getMessage());
        assertFalse(messages(failure).contains("DO_NOT_EXPOSE_REVOCATION_SENTINEL"));

        Credential held = credential("not-usable", CredentialStatus.ISSUED, NOW.minusSeconds(60), NOW.plusSeconds(60));
        EffectiveCredentialStatusResolver.Evaluation evaluation = resolver(
                revocation(held, RevocationReason.CERTIFICATE_HOLD, NOW)).beginEvaluation();
        PkiException rejected = assertThrows(PkiException.class,
                () -> evaluation.requireUsable(held, CredentialUse.BUNDLE_DELIVERY));
        assertEquals("Credential trust rejected: code=CREDENTIAL_NOT_USABLE", rejected.getMessage());
    }

    @Test
    void oneEvaluationCapturesClockOnceAndLooksUpEachCredentialOnce() {
        CountingClock clock = new CountingClock(NOW);
        AtomicInteger lookups = new AtomicInteger();
        StoreBackedEffectiveCredentialStatusResolver resolver = new StoreBackedEffectiveCredentialStatusResolver(
                store(id -> Optional.empty(), lookups), clock);
        EffectiveCredentialStatusResolver.Evaluation evaluation = resolver.beginEvaluation();
        Credential first = credential("first", CredentialStatus.ISSUED, NOW.minusSeconds(60), NOW.plusSeconds(60));
        Credential second = credential("second", CredentialStatus.ISSUED, NOW.minusSeconds(60), NOW.plusSeconds(60));

        assertEquals(EffectiveCredentialStatus.USABLE, evaluation.resolve(first));
        assertSame(second, evaluation.requireUsable(second, CredentialUse.END_ENTITY_ISSUER));
        assertEquals(NOW, evaluation.evaluationTime());
        assertEquals(1, clock.reads());
        assertEquals(2, lookups.get());
    }

    @Test
    void trustAuditOmitsFormatAndSensitiveMetadata() {
        String sentinel = "DO_NOT_AUDIT_FORMAT_SENTINEL";
        Credential credential = new Credential(new PkiId("credential:audit"), new FormatId(sentinel),
                new IssuerRef(new PkiId("ca:issuer")), new SubjectRef("CN=Audit"),
                new Validity(NOW.minusSeconds(60), NOW.plusSeconds(60)), "audit", new PkiId("key:audit"),
                new CaProfileBinding(new zeroecho.pki.api.profile.CertificateProfileRef("default", 1, new byte[32])),
                CredentialStatus.ISSUED, new EncodedObject(Encoding.DER, new byte[] { 1 }), new SimpleAttributeSet());
        AtomicReference<AuditEvent> recorded = new AtomicReference<>();

        CredentialTrustAudit.rejected(recorded::set, NOW, credential, CredentialUse.END_ENTITY_ISSUER,
                "ISSUER_CREDENTIAL_UNAVAILABLE", EffectiveCredentialStatus.HELD);

        AuditEvent event = recorded.get();
        assertEquals(Optional.empty(), event.formatId());
        assertFalse(event.toString().contains(sentinel));
        assertFalse(event.details().toString().contains(sentinel));
    }

    private static void assertStatus(Credential credential, Optional<RevocationJournal> revocation,
            EffectiveCredentialStatus expected) {
        assertEquals(expected, resolver(revocation).beginEvaluation().resolve(credential));
    }

    private static void assertResolutionFailure(Credential credential, Optional<RevocationJournal> revocation) {
        PkiException failure = assertThrows(PkiException.class,
                () -> resolver(revocation).beginEvaluation().resolve(credential));
        assertEquals("Credential status resolution failed: code=CREDENTIAL_STATUS_RESOLUTION_FAILED",
                failure.getMessage());
    }

    private static StoreBackedEffectiveCredentialStatusResolver resolver(Optional<RevocationJournal> revocation) {
        return new StoreBackedEffectiveCredentialStatusResolver(store(id -> revocation, new AtomicInteger()),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static PkiStore store(Function<PkiId, Optional<RevocationJournal>> lookup, AtomicInteger calls) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> {
                    if ("getRevocationJournal".equals(method.getName())) {
                        calls.incrementAndGet();
                        return lookup.apply((PkiId) arguments[0]);
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static Optional<RevocationJournal> revocation(Credential credential, RevocationReason reason,
            Instant time) {
        if (reason == RevocationReason.REMOVE_FROM_CRL) {
            return Optional.of(new RevocationJournal(credential.credentialId(),
                    List.of(new RevocationTransition(1L, RevocationState.HELD, time.minusNanos(1), Optional.empty(),
                            new SimpleAttributeSet()),
                            new RevocationTransition(2L, RevocationState.CLEAR, time, Optional.empty(),
                                    new SimpleAttributeSet()))));
        }
        RevocationState state = reason == RevocationReason.CERTIFICATE_HOLD ? RevocationState.HELD
                : RevocationState.PERMANENTLY_REVOKED;
        Optional<RevocationReason> permanentReason = state == RevocationState.PERMANENTLY_REVOKED ? Optional.of(reason)
                : Optional.empty();
        return Optional.of(new RevocationJournal(credential.credentialId(),
                List.of(new RevocationTransition(1L, state, time, permanentReason, new SimpleAttributeSet()))));
    }

    private static Credential credential(String suffix, CredentialStatus status, Instant notBefore, Instant notAfter) {
        return new Credential(new PkiId("credential:" + suffix), new FormatId("x509"),
                new IssuerRef(new PkiId("ca:issuer")), new SubjectRef("CN=" + suffix),
                new Validity(notBefore, notAfter), suffix, new PkiId("key:" + suffix),
                new CaProfileBinding(new zeroecho.pki.api.profile.CertificateProfileRef("default", 1, new byte[32])),
                status, new EncodedObject(Encoding.DER, new byte[] { 1, 2, 3 }), new SimpleAttributeSet());
    }

    private static String messages(Throwable throwable) {
        StringBuilder messages = new StringBuilder();
        Throwable current = throwable;
        while (current != null) {
            if (current.getMessage() != null) {
                messages.append(current.getMessage());
            }
            current = current.getCause();
        }
        return messages.toString();
    }

    private static final class CountingClock extends Clock {
        private final Instant instant;
        private final AtomicInteger reads;

        private CountingClock(Instant instant) {
            this.instant = instant;
            this.reads = new AtomicInteger();
        }

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
            reads.incrementAndGet();
            return instant;
        }

        private int reads() {
            return reads.get();
        }
    }
}
