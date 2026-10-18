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

package zeroecho.pki.impl.core.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.ACCESS;
import static zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.FAIRNESS;
import static zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.NOW;
import static zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.correlatedInput;
import static zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.issuance;
import static zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.open;
import static zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.request;
import static zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.semantic;
import static zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.signing;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedIssuancePreparation;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.impl.core.CorrelatedIssuanceIdentity;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningServiceTest.TestProvider;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FilesystemPkiStoreTestAccess;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.PkiTestRuntime;

final class CorrelatedIssuanceAcceptanceTest {
    @Test
    void concurrentIdenticalPreparationsHaveOneWinnerAndReturnItsReceipt(@TempDir Path root) throws Exception {
        concurrent(root, false);
    }

    @Test
    void concurrentChangedCsrConflictsAndCleansOnlyLosingCandidate(@TempDir Path root) throws Exception {
        concurrent(root, true);
    }

    private static void concurrent(Path root, boolean changedCsr) throws Exception {
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider();
                ExecutorService executor = Executors.newFixedThreadPool(2)) {
            CyclicBarrier acceptanceBarrier = new CyclicBarrier(2);
            DefaultSigningService signing = signing(store, provider, (command, custody) -> {
                custody.run();
                try {
                    acceptanceBarrier.await(10, TimeUnit.SECONDS);
                } catch (Exception failure) {
                    throw new AssertionError("Acceptance barrier failed", failure);
                }
                return store.acceptSign(command);
            });
            DefaultSemanticSigningService service = semantic(store, signing);
            CorrelatedEndEntityIssuanceRequest input = correlatedInput();
            CorrelatedEndEntityIssuanceRequest other = changedCsr ? changed(input) : input;
            DomainSigningRequest firstDomain = issuance(store, signing, input, -1, "");
            DomainSigningRequest secondDomain = issuance(store, signing, other, -1, "");
            PreparedSemanticSigningRequest first = service.prepare(firstDomain, FAIRNESS);
            PreparedSemanticSigningRequest second = service.prepare(secondDomain, FAIRNESS);
            Future<SigningAcceptanceResult> firstFuture = executor.submit(() -> service.accept(first));
            Future<SigningAcceptanceResult> secondFuture = executor.submit(() -> service.accept(second));
            SigningAcceptanceResult firstResult = firstFuture.get(15, TimeUnit.SECONDS);
            SigningAcceptanceResult secondResult = secondFuture.get(15, TimeUnit.SECONDS);
            boolean firstWon = firstResult.disposition() == SigningAcceptanceDisposition.ACCEPTED;
            SigningAcceptanceResult winner = firstWon ? firstResult : secondResult;
            SigningAcceptanceResult loser = firstWon ? secondResult : firstResult;
            DomainSigningRequest winnerDomain = firstWon ? firstDomain : secondDomain;
            DomainSigningRequest loserDomain = firstWon ? secondDomain : firstDomain;
            assertEquals(SigningAcceptanceDisposition.ACCEPTED, winner.disposition());
            assertEquals(changedCsr ? SigningAcceptanceDisposition.CONFLICT : SigningAcceptanceDisposition.ATTACHED_EXISTING,
                    loser.disposition());
            if (!changedCsr) assertEquals(winner.receipt(), loser.receipt());
            assertEquals(1, store.listSignWorkflows().size());
            assertEquals(winner.receipt().operationId(), store.getDomainContinuation(DomainContinuationStore.Kind.ISSUANCE,
                    CorrelatedIssuanceIdentity.derive(input).correlationId()).orElseThrow().operationId());
            assertTrue(store.getSignWorkflow(loserDomain.operationId()).isEmpty());
            assertTrue(PkiTestRuntime.readContent(store, winnerDomain.content()).length > 0);
            assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, loserDomain.content()));
            assertEquals(SigningAcceptanceResolution.MATCHED, service.resolve(winner.receipt()));
            assertEquals(0, provider.calls.get());
        }
    }

    @Test
    void winnerArrivingBetweenPrelookupAndAcceptIsAttachedEvenAtCapacity(@TempDir Path root) throws Exception {
        for (int capacity : List.of(1, 4)) {
            try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root.resolve("capacity-" + capacity), capacity,
                    Clock.fixed(NOW, ZoneOffset.UTC)); TestProvider provider = new TestProvider()) {
                DefaultSigningService winnerSigning = signing(store, provider);
                DefaultSemanticSigningService winnerService = semantic(store, winnerSigning);
                PreparedSemanticSigningRequest winner = winnerService.prepare(
                        issuance(store, winnerSigning, correlatedInput(), -1, ""), FAIRNESS);
                AtomicInteger acceptanceCalls = new AtomicInteger();
                DefaultSigningService loserSigning = signing(store, provider, (command, custody) -> {
                    acceptanceCalls.incrementAndGet();
                    winnerService.accept(winner);
                    custody.run();
                    return store.acceptSign(command);
                });
                DefaultSemanticSigningService loserService = semantic(store, loserSigning);
                DomainSigningRequest losingDomain = issuance(store, loserSigning, correlatedInput(), -1, "");
                SigningAcceptanceResult result = loserService.accept(loserService.prepare(losingDomain, FAIRNESS));
                assertEquals(SigningAcceptanceDisposition.ATTACHED_EXISTING, result.disposition());
                assertEquals(winner.receipt(), result.receipt());
                assertNotEquals(losingDomain.operationId(), result.receipt().operationId());
                assertEquals(1, acceptanceCalls.get());
                assertEquals(1, store.listSignWorkflows().size());
                assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, losingDomain.content()));
            }
        }
    }

    @Test
    void preexistingWinnerSkipsAdmissionAndForeignOrConsumedCarriersCannotAttach(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            AtomicInteger accepts = new AtomicInteger();
            DefaultSigningService signing = signing(store, provider, (command, custody) -> {
                accepts.incrementAndGet(); custody.run(); return store.acceptSign(command);
            });
            DefaultSemanticSigningService service = semantic(store, signing);
            PreparedSemanticSigningRequest winner = service.prepare(issuance(store, signing, correlatedInput(), -1, ""), FAIRNESS);
            DomainSigningRequest losingDomain = issuance(store, signing, correlatedInput(), -1, "");
            PreparedSemanticSigningRequest loser = service.prepare(losingDomain, FAIRNESS);
            service.accept(winner);
            assertThrows(IllegalArgumentException.class, () -> semantic(store, signing(store, provider)).accept(loser));
            SigningAcceptanceResult attached = service.accept(loser);
            assertEquals(SigningAcceptanceDisposition.ATTACHED_EXISTING, attached.disposition());
            assertEquals(winner.receipt(), attached.receipt());
            assertEquals(1, accepts.get());
            assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, losingDomain.content()));
            assertThrows(IllegalStateException.class, () -> service.accept(loser));
            assertThrows(IllegalStateException.class, () -> service.discard(loser));
            assertThrows(IllegalStateException.class, () -> service.accept(winner));
        }
    }

    @Test
    void differentPreexistingIntentConflictsAndDefiniteCapacityRejectionCleansUp(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root, 1, Clock.fixed(NOW, ZoneOffset.UTC));
                TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DefaultSemanticSigningService service = semantic(store, signing);
            PreparedSemanticSigningRequest winner = service.prepare(issuance(store, signing, correlatedInput(), -1, ""), FAIRNESS);
            DomainSigningRequest different = issuance(store, signing, changed(correlatedInput()), -1, "");
            PreparedSemanticSigningRequest loser = service.prepare(different, FAIRNESS);
            service.accept(winner);
            assertEquals(SigningAcceptanceDisposition.CONFLICT, service.accept(loser).disposition());
            assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, different.content()));
            DomainSigningRequest unrelated = request(store, signing, "unrelated");
            assertEquals(SigningAcceptanceDisposition.CAPACITY_REJECTED,
                    service.accept(service.prepare(unrelated, FAIRNESS)).disposition());
            assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, unrelated.content()));
        }
        try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(root.resolve("new-correlation"), 1,
                Clock.fixed(NOW, ZoneOffset.UTC)); TestProvider provider = new TestProvider()) {
            DefaultSigningService signing = signing(store, provider);
            DefaultSemanticSigningService service = semantic(store, signing);
            service.accept(service.prepare(request(store, signing, "fill"), FAIRNESS));
            DomainSigningRequest rejected = issuance(store, signing, correlatedInput(), -1, "");
            PreparedSemanticSigningRequest prepared = service.prepare(rejected, FAIRNESS);
            SigningAcceptanceResult result = service.accept(prepared);
            assertEquals(SigningAcceptanceDisposition.CAPACITY_REJECTED, result.disposition());
            assertEquals(prepared.receipt(), result.receipt());
            assertTrue(service.findIssuance(correlatedInput()).isEmpty());
            assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, rejected.content()));
            assertThrows(IllegalStateException.class, () -> service.discard(prepared));
        }
    }

    @Test
    void unknownCommitPreservesOriginalReceiptAndCandidateUntilAuthoritativeResolution(@TempDir Path root) throws Exception {
        for (boolean committed : List.of(false, true)) {
            Path directory = root.resolve(Boolean.toString(committed));
            SigningAcceptanceReceipt receipt;
            try (FilesystemPkiStore store = open(directory); TestProvider provider = new TestProvider()) {
                DefaultSigningService signing = signing(store, provider, (command, custody) -> {
                    custody.run();
                    if (committed) store.acceptSign(command);
                    throw new IllegalStateException("controlled unknown acceptance");
                });
                DefaultSemanticSigningService service = semantic(store, signing);
                DomainSigningRequest domain = issuance(store, signing, correlatedInput(), -1, "");
                PreparedSemanticSigningRequest prepared = service.prepare(domain, FAIRNESS);
                receipt = prepared.receipt();
                assertThrows(IllegalStateException.class, () -> service.accept(prepared));
                assertEquals(receipt, prepared.receipt());
                assertTrue(PkiTestRuntime.readContent(store, domain.content()).length > 0);
                assertThrows(IllegalStateException.class, () -> service.discard(prepared));
                assertThrows(IllegalStateException.class, () -> service.accept(prepared));
                assertEquals(0, provider.calls.get());
            }
            try (FilesystemPkiStore store = open(directory); TestProvider provider = new TestProvider()) {
                DefaultSemanticSigningService service = semantic(store, signing(store, provider));
                assertEquals(committed ? SigningAcceptanceResolution.MATCHED : SigningAcceptanceResolution.NOT_ACCEPTED,
                        service.resolve(receipt));
                if (committed) {
                    CorrelatedIssuancePreparation replay = service.prepareCorrelatedEndEntity(ACCESS, correlatedInput(), Optional.empty(),
                            CancellationSignal.NONE);
                    assertEquals(receipt.operationId(), ((CorrelatedIssuancePreparation.Existing) replay).operation().submissionId().id());
                } else {
                    assertTrue(service.findIssuance(correlatedInput()).isEmpty());
                }
            }
        }
    }

    private static CorrelatedEndEntityIssuanceRequest changed(CorrelatedEndEntityIssuanceRequest input) {
        return new CorrelatedEndEntityIssuanceRequest(new EndEntityIssuanceRequest(input.request().issuerCaId(),
                new byte[] { 8, 7, 6 }, input.request().profileId(), Optional.empty()), input.intent());
    }

    @Test
    void retainedTerminalWinnerStillOwnsCorrelation(@TempDir Path root) throws Exception {
        for (String terminal : List.of("FAILED", "CANCELLED", "EXPIRED")) {
            Path directory = root.resolve(terminal);
            SigningAcceptanceReceipt winnerReceipt;
            try (FilesystemPkiStore store = open(directory); TestProvider provider = new TestProvider()) {
                DefaultSigningService signing = signing(store, provider);
                DefaultSemanticSigningService service = semantic(store, signing);
                PreparedSemanticSigningRequest winner = service.prepare(issuance(store, signing, correlatedInput(), -1, ""), FAIRNESS);
                winnerReceipt = service.accept(winner).receipt();
                if (terminal.equals("CANCELLED")) {
                    service.cancel(winnerReceipt.operationId());
                } else if (terminal.equals("FAILED")) {
                    SignWorkflowStore.Workflow claimed = store.claimSignStep(winnerReceipt.operationId(), 0L,
                            Duration.ofSeconds(10)).orElseThrow();
                    store.transitionSign(winnerReceipt.operationId(), claimed.revision(), claimed.fence(),
                            SignWorkflowStore.State.FAILED, Optional.of("DENIED"), Optional.empty(), Optional.of(NOW)).orElseThrow();
                }
                if (!terminal.equals("EXPIRED")) {
                    store.transitionDomainContinuation(winnerReceipt.operationId(), 0L, DomainContinuationStore.State.FAILED,
                            Optional.empty(), Optional.of(terminal)).orElseThrow();
                }
            }
            try (FilesystemPkiStore store = FilesystemPkiStoreTestAccess.open(directory, 4,
                    Clock.fixed(NOW.plusSeconds(61), ZoneOffset.UTC)); TestProvider provider = new TestProvider()) {
                assertEquals(terminal, store.getSignWorkflow(winnerReceipt.operationId()).orElseThrow().state().name());
                DefaultSigningService signing = signing(store, provider);
                DefaultSemanticSigningService service = semantic(store, signing);
                DomainSigningRequest loser = issuance(store, signing, correlatedInput(), -1, "");
                SigningAcceptanceResult result = service.accept(service.prepare(loser, FAIRNESS));
                assertEquals(SigningAcceptanceDisposition.ATTACHED_EXISTING, result.disposition());
                assertEquals(winnerReceipt, result.receipt());
                assertEquals(1, store.listSignWorkflows().size());
                assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, loser.content()));
            }
        }
    }

    @Test
    void unknownLosingAttemptRequiresOriginalResolutionBeforeWinnerLookup(@TempDir Path root) throws Exception {
        SigningAcceptanceReceipt original;
        SigningAcceptanceReceipt winnerReceipt;
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSigningService winnerSigning = signing(store, provider);
            DefaultSemanticSigningService winnerService = semantic(store, winnerSigning);
            PreparedSemanticSigningRequest winner = winnerService.prepare(issuance(store, winnerSigning, correlatedInput(), -1, ""), FAIRNESS);
            winnerReceipt = winner.receipt();
            DefaultSigningService loserSigning = signing(store, provider, (command, custody) -> {
                custody.run();
                winnerService.accept(winner);
                throw new IllegalStateException("controlled uncertain losing attempt");
            });
            DefaultSemanticSigningService loserService = semantic(store, loserSigning);
            DomainSigningRequest domain = issuance(store, loserSigning, correlatedInput(), -1, "");
            PreparedSemanticSigningRequest prepared = loserService.prepare(domain, FAIRNESS);
            original = prepared.receipt();
            assertThrows(IllegalStateException.class, () -> loserService.accept(prepared));
            assertTrue(PkiTestRuntime.readContent(store, domain.content()).length > 0);
            assertEquals(original, prepared.receipt());
        }
        try (FilesystemPkiStore store = open(root); TestProvider provider = new TestProvider()) {
            DefaultSemanticSigningService service = semantic(store, signing(store, provider));
            assertEquals(SigningAcceptanceResolution.NOT_ACCEPTED, service.resolve(original));
            assertEquals(winnerReceipt.operationId(), service.findIssuance(correlatedInput()).orElseThrow().submissionId().id());
            assertEquals(SigningAcceptanceResolution.MATCHED, service.resolve(winnerReceipt));
        }
    }
}
