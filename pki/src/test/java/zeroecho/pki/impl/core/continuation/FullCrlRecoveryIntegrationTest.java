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

package zeroecho.pki.impl.core.continuation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.ACCESS;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.CA;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.CLOCK;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.NOW;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.fixture;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.open;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.semantic;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.sign;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.Fixture;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.impl.fs.FullCrlRecoveryFaults;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;

class FullCrlRecoveryIntegrationTest {
    @Test void reopensEveryDurableSuccessCutAndRetiresExactlyOnce(@TempDir Path root) throws Exception {
        for (SuccessCut cut : SuccessCut.values()) {
            Path source = root.resolve(cut.name());
            PkiId operation;
            DurableContentReference tbs;
            try (FilesystemPkiStore store = cut == SuccessCut.RETIRED_BEFORE_CLEANUP
                    ? FullCrlRecoveryFaults.failRetirement(source, CLOCK) : open(source)) {
                Fixture fixture = smallFixture(store);
                operation = accept(store, fixture);
                tbs = fixture.prepared().tbsContent();
                sign(store, operation, fixture.signature());
                if (cut != SuccessCut.SIGNED) { publishing(store, operation); }
                if (cut == SuccessCut.COMPLETED || cut == SuccessCut.RETIRED_BEFORE_CLEANUP) {
                    completeWithoutRetirement(store, operation, fixture.signature());
                }
                if (cut == SuccessCut.RETIRED_BEFORE_CLEANUP) {
                    assertThrows(PkiException.class, () -> new SigningOuterTerminalDriver(store)
                            .advance(store.getSignWorkflow(operation).orElseThrow()));
                    assertEquals(SignWorkflowStore.State.RETIRED, store.getSignWorkflow(operation).orElseThrow().state());
                } else {
                    try (RepeatableContent content = store.stagedContent().openContent(tbs)) {
                        assertEquals(tbs.length(), content.length().orElseThrow());
                    }
                }
            }
            PkiId result;
            try (FilesystemPkiStore store = open(source)) {
                new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow());
                DomainContinuationStore.Record completed = store.getDomainContinuation(operation).orElseThrow();
                FullCrlSigningCommand.requireCompleted(store, completed);
                result = FullCrlSigningCommand.resultId(completed.result().orElseThrow());
                assertEquals(SignWorkflowStore.State.RETIRED, store.getSignWorkflow(operation).orElseThrow().state());
                if (cut == SuccessCut.RETIRED_BEFORE_CLEANUP) {
                    assertTrue(store.stagedContent().contentOwners(tbs).isEmpty());
                } else {
                    assertThrows(Exception.class, () -> store.stagedContent().openContent(tbs));
                }
                assertEquals(1, store.listStatusObjects(CA).size());
            }
            try (FilesystemPkiStore store = open(source)) {
                new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow());
                assertEquals(result, FullCrlSigningCommand.resultId(store.getDomainContinuation(operation)
                        .orElseThrow().result().orElseThrow()));
                assertEquals(1, store.listStatusObjects(CA).size());
            }
            if (cut == SuccessCut.RETIRED_BEFORE_CLEANUP) {
                Clock afterHorizon = Clock.fixed(NOW.plus(Duration.ofDays(91)), ZoneOffset.UTC);
                try (FilesystemPkiStore store = new FilesystemPkiStore(source, FsPkiStoreOptions.defaults(), afterHorizon)) {
                    assertEquals(1, store.purgeExpiredSignRecords());
                }
                try (FilesystemPkiStore store = new FilesystemPkiStore(source, FsPkiStoreOptions.defaults(), afterHorizon)) {
                    assertThrows(Exception.class, () -> store.stagedContent().openContent(tbs));
                    assertTrue(store.getStatusObject(result).isPresent());
                }
            }
        }
    }

    @Test void terminalFailureCancellationAndExpiryNeverPublish(@TempDir Path root) throws Exception {
        for (SignWorkflowStore.State terminal : new SignWorkflowStore.State[] {
                SignWorkflowStore.State.FAILED, SignWorkflowStore.State.CANCELLED, SignWorkflowStore.State.EXPIRED }) {
            Path source = root.resolve(terminal.name());
            PkiId operation;
            DurableContentReference tbs;
            try (FilesystemPkiStore store = open(source)) {
                Fixture fixture = smallFixture(store);
                operation = accept(store, fixture);
                tbs = fixture.prepared().tbsContent();
                if (terminal == SignWorkflowStore.State.CANCELLED) {
                    store.requestSignCancellation(operation, 0, 0).orElseThrow();
                } else if (terminal != SignWorkflowStore.State.EXPIRED) {
                    SignWorkflowStore.Workflow claimed = store.claimSignStep(operation, 0, Duration.ofSeconds(10)).orElseThrow();
                    store.transitionSign(operation, claimed.revision(), claimed.fence(), terminal,
                            Optional.of(terminal.name()), Optional.empty(), Optional.of(NOW)).orElseThrow();
                }
            }
            Clock clock = terminal == SignWorkflowStore.State.EXPIRED
                    ? Clock.fixed(NOW.plusSeconds(120), ZoneOffset.UTC) : CLOCK;
            try (FilesystemPkiStore store = new FilesystemPkiStore(source, FsPkiStoreOptions.defaults(), clock)) {
                new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow());
                DomainContinuationStore.Record domain = store.getDomainContinuation(operation).orElseThrow();
                assertEquals(terminal == SignWorkflowStore.State.EXPIRED ? DomainContinuationStore.State.EXPIRED
                        : DomainContinuationStore.State.FAILED, domain.state());
                assertTrue(domain.result().isEmpty());
                assertTrue(store.listStatusObjects(CA).isEmpty());
                assertThrows(Exception.class, () -> store.stagedContent().openContent(tbs));
            }
            try (FilesystemPkiStore store = new FilesystemPkiStore(source, FsPkiStoreOptions.defaults(), clock)) {
                assertTrue(semantic(store, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 1).find(operation).isPresent());
                assertTrue(store.listStatusObjects(CA).isEmpty());
            }
        }
    }

    static Fixture smallFixture(FilesystemPkiStore store) throws Exception {
        return fixture(store, "RSA", "SHA256withRSA", BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 2);
    }

    static PkiId accept(FilesystemPkiStore store, Fixture fixture) {
        DefaultSemanticSigningService service = semantic(store, fixture.algorithm(), 1);
        return service.accept(service.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE)).receipt().operationId();
    }

    static DomainContinuationStore.Record publishing(FilesystemPkiStore store, PkiId operation) {
        return store.transitionDomainContinuation(operation, 0, DomainContinuationStore.State.PUBLISHING,
                Optional.empty(), Optional.empty()).orElseThrow();
    }

    static void completeWithoutRetirement(FilesystemPkiStore store, PkiId operation, EncodedObject signature) {
        DomainContinuationStore.Record domain = store.getDomainContinuation(operation).orElseThrow();
        EncodedObject result = new FullCrlContinuationPublisher(store, StandardX509Bindings.catalog(), 1).publish(domain, signature);
        store.transitionDomainContinuation(operation, domain.revision(), DomainContinuationStore.State.COMPLETED,
                Optional.of(result), Optional.of("COMPLETED")).orElseThrow();
    }

    private enum SuccessCut { SIGNED, PUBLISHING, COMPLETED, RETIRED_BEFORE_CLEANUP }
}
