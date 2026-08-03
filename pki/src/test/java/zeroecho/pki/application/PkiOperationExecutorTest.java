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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationQuery;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.RevocationHistory;
import zeroecho.pki.spi.store.RevocationSnapshot;

class PkiOperationExecutorTest {

    private static final PkiId CREDENTIAL_ID = new PkiId("credential:test");

    @Test
    void validatesConfigurationAndProfilesWithSafeTypedResults() {
        System.out.println("validatesConfigurationAndProfilesWithSafeTypedResults");
        DefaultPkiOperationExecutor executor = executor(new AtomicInteger());
        PkiOperationOutcome configuration = executor.execute(new PkiOperation.ValidateConfiguration(),
                CancellationSignal.NONE);
        byte[] profile = BuiltInCertificateProfileCatalog.load(getClass().getClassLoader()).get(0).canonicalJson();
        PkiOperationOutcome validated = executor.execute(new PkiOperation.ValidateProfile(profile),
                CancellationSignal.NONE);
        PkiOperationOutcome malformed = executor.execute(new PkiOperation.ValidateProfile(new byte[] { 1 }),
                CancellationSignal.NONE);
        System.out.println("...profileBytes=" + profile.length);
        assertInstanceOf(PkiOperationOutcome.Success.class, configuration);
        PkiOperationResult profileResult = ((PkiOperationOutcome.Success) validated).result();
        assertTrue(profileResult.field("profileId").isPresent());
        assertEquals(PkiOperationFailure.POLICY_REJECTION,
                ((PkiOperationOutcome.Failure) malformed).classification());
        System.out.println("...ok");
    }

    @Test
    void delegatesMutationAndStreamsBoundedHistory() {
        System.out.println("delegatesMutationAndStreamsBoundedHistory");
        AtomicInteger revocations = new AtomicInteger();
        DefaultPkiOperationExecutor executor = executor(revocations);
        PkiOperationOutcome mutation = executor.execute(
                new PkiOperation.RevokeCredential(CREDENTIAL_ID, RevocationReason.KEY_COMPROMISE),
                CancellationSignal.NONE);
        PkiOperationOutcome history = executor.execute(new PkiOperation.ReadRevocationHistory(CREDENTIAL_ID, 1),
                CancellationSignal.NONE);
        System.out.println("...mutations=" + revocations.get());
        assertInstanceOf(PkiOperationOutcome.Success.class, mutation);
        PkiOperationResult historyResult = ((PkiOperationOutcome.Success) history).result();
        assertEquals(new PkiOperationValue.BooleanValue(true), historyResult.field("truncated").orElseThrow());
        assertEquals(1, revocations.get());
        System.out.println("...ok");
    }

    @Test
    void classifiesMissingObjectsAndCancellationWithoutThrowableDetails() {
        System.out.println("classifiesMissingObjectsAndCancellationWithoutThrowableDetails");
        DefaultPkiOperationExecutor executor = executor(new AtomicInteger());
        PkiOperationOutcome missing = executor.execute(new PkiOperation.InspectPublication(new PkiId("missing")),
                CancellationSignal.NONE);
        PkiOperationOutcome cancelled = executor.execute(new PkiOperation.InspectCredential(CREDENTIAL_ID),
                () -> true);
        assertEquals(PkiOperationFailure.NOT_FOUND, ((PkiOperationOutcome.Failure) missing).classification());
        PkiOperationOutcome.Failure cancelledFailure = (PkiOperationOutcome.Failure) cancelled;
        assertEquals(PkiOperationFailure.CANCELLED, cancelledFailure.classification());
        assertEquals("OPERATION_CANCELLED", cancelledFailure.code());
        System.out.println("...ok");
    }

    private static DefaultPkiOperationExecutor executor(AtomicInteger mutations) {
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(1,
                new ProviderConfig("fs", Map.of("root", "unused")), new ProviderConfig("memory", Map.of()));
        PkiStore store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> switch (method.getName()) {
                    case "getCredential", "getPublicationRecord" -> Optional.empty();
                    case "close" -> null;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
        return new DefaultPkiOperationExecutor(configuration, store, revocations(mutations), () -> {
        });
    }

    private static RevocationService revocations(AtomicInteger mutations) {
        return new RevocationService() {
            @Override
            public RevocationRecord hold(RevocationCommand.Hold command) {
                throw new UnsupportedOperationException();
            }

            @Override
            public RevocationRecord unhold(RevocationCommand.Unhold command) {
                throw new UnsupportedOperationException();
            }

            @Override
            public RevocationRecord revokePermanently(RevocationCommand.RevokePermanently command) {
                mutations.incrementAndGet();
                return new RevocationRecord(command.credentialId(), transitions().get(1));
            }

            @Override
            public Optional<RevocationRecord> get(PkiId credentialId) {
                return Optional.empty();
            }

            @Override
            public RevocationHistory history(PkiId credentialId) {
                return historyCursor(credentialId);
            }

            @Override
            public RevocationSnapshot search(RevocationQuery query) {
                throw new UnsupportedOperationException();
            }
        };
    }

    private static RevocationHistory historyCursor(PkiId credentialId) {
        return new RevocationHistory() {
            private int index = -1;

            @Override
            public PkiId credentialId() {
                return credentialId;
            }

            @Override
            public boolean next(CancellationSignal cancellation) throws IOException {
                cancellation.throwIfCancelled();
                index++;
                return index < transitions().size();
            }

            @Override
            public RevocationTransition current() {
                return transitions().get(index);
            }

            @Override
            public void close() {
                // no-op
            }
        };
    }

    private static List<RevocationTransition> transitions() {
        return List.of(new RevocationTransition(1L, RevocationState.HELD, Instant.parse("2026-08-04T00:00:00Z"),
                Optional.empty(), new SimpleAttributeSet()),
                new RevocationTransition(2L, RevocationState.PERMANENTLY_REVOKED,
                        Instant.parse("2026-08-04T00:01:00Z"), Optional.of(RevocationReason.KEY_COMPROMISE),
                        new SimpleAttributeSet()));
    }
}
