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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.InterruptedIOException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSigningOperation;
import zeroecho.pki.application.PkiSigningCommands;

class ServerSigningExecutorTest {
    @TempDir Path directory;
    private static final KeyRef KEY = new KeyRef("key:subject");

    @Test
    void sharedPreparationPolicyRejectionDoesNotReachAcceptance() {
        Fixture fixture = fixture();
        when(fixture.commands().prepare(any(), any(), any(), any()))
                .thenThrow(new PkiException("Policy rejected"));
        PkiOperationOutcome.Failed failed = assertInstanceOf(PkiOperationOutcome.Failed.class,
                fixture.executor().execute(request(root()), Optional.empty(), CancellationSignal.NONE));
        assertEquals(PkiOperationFailure.POLICY_REJECTION, failed.classification());
        assertEquals("PKI_POLICY_REJECTED", failed.code());
        verify(fixture.signing(), never()).accept(any());
    }

    @Test
    void wrappedPreparationCancellationIsCancelledButDurabilityRetainsPriority() {
        for (boolean durability : List.of(false, true)) {
            Fixture fixture = fixture();
            AtomicBoolean cancelled = new AtomicBoolean();
            when(fixture.commands().prepare(any(), any(), any(), any())).thenAnswer(invocation -> {
                cancelled.set(true);
                if (durability) throw new PkiException("recovery", PkiFailureReason.STORE_DURABILITY_UNCONFIRMED);
                throw new PkiException("cancelled", new InterruptedIOException("cancelled"));
            });
            PkiOperationOutcome.Failed failed = assertInstanceOf(PkiOperationOutcome.Failed.class,
                    fixture.executor().execute(request(root()), Optional.empty(), cancelled::get));
            assertEquals(durability ? PkiOperationFailure.RECOVERY_REQUIRED : PkiOperationFailure.CANCELLED,
                    failed.classification());
            verify(fixture.signing(), never()).accept(any());
            verify(fixture.signing(), never()).discard(any());
        }
    }

    @Test
    void cancellationAfterPreparationDiscardsOnceBeforeAcceptance() throws Exception {
        try (SemanticPreparationFixture custody = SemanticPreparationFixture.open(directory.resolve("cancel"))) {
            Fixture fixture = fixture();
            AtomicBoolean cancelled = new AtomicBoolean();
            when(fixture.commands().prepare(any(), any(), any(), any())).thenAnswer(invocation -> {
                cancelled.set(true);
                return custody.prepared();
            });
            PkiOperationOutcome.Failed failed = assertInstanceOf(PkiOperationOutcome.Failed.class,
                    fixture.executor().execute(request(root()), Optional.empty(), cancelled::get));
            assertEquals(PkiOperationFailure.CANCELLED, failed.classification());
            verify(fixture.signing()).discard(custody.prepared());
            verify(fixture.signing(), never()).accept(any());
        }
    }

    @Test
    void cancellationAfterAcceptInvocationDoesNotDiscardOrReplaceUncertainAdmission() throws Exception {
        try (SemanticPreparationFixture custody = SemanticPreparationFixture.open(directory.resolve("accept"))) {
            for (SigningAcceptanceResolution resolution : List.of(SigningAcceptanceResolution.MATCHED,
                    SigningAcceptanceResolution.CONFLICT)) {
                Fixture fixture = fixture();
                AtomicBoolean cancelled = new AtomicBoolean();
                when(fixture.commands().prepare(any(), any(), any(), any())).thenReturn(custody.prepared());
                when(fixture.signing().accept(custody.prepared())).thenAnswer(invocation -> {
                    cancelled.set(true);
                    throw new PkiException("uncertain", new InterruptedIOException("cancelled"));
                });
                when(fixture.signing().resolve(custody.prepared().receipt())).thenReturn(resolution);
                PkiOperationOutcome outcome = fixture.executor().execute(request(root()), Optional.empty(), cancelled::get);
                if (resolution == SigningAcceptanceResolution.MATCHED) {
                    assertEquals(custody.prepared().receipt().operationId(),
                            assertInstanceOf(PkiOperationOutcome.Pending.class, outcome).operationId());
                } else {
                    assertEquals(PkiOperationFailure.CONFLICT,
                            assertInstanceOf(PkiOperationOutcome.Failed.class, outcome).classification());
                }
                verify(fixture.signing()).accept(custody.prepared());
                verify(fixture.signing(), never()).discard(any());
            }
            Fixture unresolved = fixture();
            AtomicBoolean cancelled = new AtomicBoolean();
            when(unresolved.commands().prepare(any(), any(), any(), any())).thenReturn(custody.prepared());
            when(unresolved.signing().accept(custody.prepared())).thenAnswer(invocation -> {
                cancelled.set(true);
                throw new PkiException("uncertain");
            });
            when(unresolved.signing().resolve(custody.prepared().receipt())).thenThrow(new PkiException("unavailable"));
            assertEquals(PkiOperationFailure.RECOVERY_REQUIRED, assertInstanceOf(PkiOperationOutcome.Failed.class,
                    unresolved.executor().execute(request(root()), Optional.empty(), cancelled::get)).classification());
            verify(unresolved.signing()).accept(custody.prepared());
            verify(unresolved.signing(), never()).discard(any());
        }
    }

    @Test
    void forwardsServerIdentityEvidenceAndCancellationAndReturnsAcceptedWinner() throws Exception {
        try (SemanticPreparationFixture custody = SemanticPreparationFixture.open(directory.resolve("forward"))) {
            for (SigningAcceptanceDisposition disposition : List.of(SigningAcceptanceDisposition.ACCEPTED,
                    SigningAcceptanceDisposition.ATTACHED_EXISTING)) {
                Fixture fixture = fixture();
                PkiSigningOperation operation = new PkiSigningOperation.IssueCredential(
                        new PkiId("ca:issuer"), new PkiId("csr:request"), "profile");
                Optional<IssuanceExecutionEvidence> evidence = Optional.of(mock(IssuanceExecutionEvidence.class));
                CancellationSignal cancellation = () -> false;
                SigningAcceptanceReceipt winner = SigningAcceptanceReceipt.parse(new PkiId("signing:winner"),
                        custody.prepared().receipt().encodedCommitment());
                when(fixture.commands().prepare(any(), any(), any(), any())).thenReturn(custody.prepared());
                when(fixture.signing().accept(custody.prepared()))
                        .thenReturn(new SigningAcceptanceResult(disposition, winner));
                PkiOperationOutcome.Pending pending = assertInstanceOf(PkiOperationOutcome.Pending.class,
                        fixture.executor().execute(request(operation), evidence, cancellation));
                assertEquals(winner.operationId(), pending.operationId());
                assertEquals(operation.name(), pending.operationName());
                ArgumentCaptor<AccessContext> access = ArgumentCaptor.forClass(AccessContext.class);
                verify(fixture.commands()).prepare(same(operation), access.capture(), same(evidence), same(cancellation));
                assertEquals("ADMIN_PRINCIPAL", access.getValue().principal().type());
                assertEquals("administrator", access.getValue().principal().name());
                assertEquals(operation.name(), access.getValue().purpose().value());
                verify(fixture.signing(), never()).find(any());
                verify(fixture.signing(), never()).discard(any());
                verify(fixture.session(), never()).localSigning();
            }
        }
    }

    @Test
    void missingCommandsAndOcspKeepTheirServerFailureCodes() {
        Fixture fixture = fixture();
        when(fixture.session().signingCommands()).thenReturn(Optional.empty());
        PkiOperationOutcome.Failed unavailable = assertInstanceOf(PkiOperationOutcome.Failed.class,
                fixture.executor().execute(request(root()), Optional.empty(), CancellationSignal.NONE));
        assertEquals("CAPABILITY_NOT_CONFIGURED", unavailable.code());
        PkiOperationOutcome.Failed ocsp = assertInstanceOf(PkiOperationOutcome.Failed.class,
                fixture.executor().execute(request(new PkiSigningOperation.GenerateStatus(
                        new PkiId("ca:issuer"), StatusObjectType.OCSP, new FormatId("x509"))),
                        Optional.empty(), CancellationSignal.NONE));
        assertEquals(PkiOperationFailure.VALIDATION_FAILURE, ocsp.classification());
        assertEquals("OCSP_TARGET_REQUIRED", ocsp.code());
        verify(fixture.commands(), never()).prepare(any(), any(), any(), any());
        verify(fixture.signing(), never()).accept(any());
    }

    @Test
    void realReactiveSessionAcceptsSharedCommandAndCompletesThroughExistingReactor() throws Exception {
        try (SemanticPreparationFixture fixture = SemanticPreparationFixture.open(directory.resolve("reactive"), Clock.systemUTC())) {
            PkiSession session = fixture.session();
            PkiSigningOperation operation = new PkiSigningOperation.CreateAuthority(new FormatId("x509"),
                    new SubjectRef("CN=Server Shared Commands"), "root-ca", new KeyRef("fixture:root.prv"));
            PkiOperationOutcome.Pending accepted = assertInstanceOf(PkiOperationOutcome.Pending.class,
                    new ServerSigningExecutor(session).execute(request(operation), Optional.empty(), CancellationSignal.NONE));
            SemanticSigningOperation completed = assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
                SemanticSigningOperation observation;
                do {
                    observation = session.semanticSigning().orElseThrow().find(accepted.operationId()).orElseThrow();
                    if (observation.state() == SemanticSigningState.COMPLETED
                            || observation.state() == SemanticSigningState.FAILED
                            || observation.state() == SemanticSigningState.EXPIRED) break;
                    Thread.sleep(10);
                } while (true);
                return observation;
            }, () -> {
                SemanticSigningOperation last = session.semanticSigning().orElseThrow().find(accepted.operationId()).orElseThrow();
                return "Last observation: " + last.state() + "/" + last.signingState() + ", detail=" + last.detailCode();
            });
            assertEquals(SemanticSigningState.COMPLETED, completed.state());
            assertEquals("ADMIN_PRINCIPAL", completed.scope().accessContext().principal().type());
            assertEquals("administrator", completed.scope().accessContext().principal().name());
            assertEquals("signing.operation", session.signingCommands().orElseThrow().completedResult(completed).operationName());
        }
    }

    private static PkiSigningOperation root() {
        return new PkiSigningOperation.CreateAuthority(new FormatId("x509"), new SubjectRef("CN=Root"), "root", KEY);
    }

    private static ServerOperationGateway.Request request(PkiSigningOperation operation) {
        return new ServerOperationGateway.Request(ServerTestSupport.REALM, "administrator",
                new AdministrativeOperation.Signing(operation),
                new Permission.Resource(Permission.ResourceType.AUTHORITY,
                        new Permission.Scope(ServerTestSupport.REALM, Optional.empty(), Optional.empty(), Optional.empty()),
                        Optional.empty(), Optional.empty()), Permission.Relationship.ANY,
                Permission.Context.empty(), Optional.empty(), "request-signing");
    }

    private static Fixture fixture() {
        PkiSession session = mock(PkiSession.class);
        SemanticSigningService signing = mock(SemanticSigningService.class);
        PkiSigningCommands commands = mock(PkiSigningCommands.class);
        when(session.semanticSigning()).thenReturn(Optional.of(signing));
        when(session.signingCommands()).thenReturn(Optional.of(commands));
        return new Fixture(session, signing, commands, new ServerSigningExecutor(session));
    }

    private record Fixture(PkiSession session, SemanticSigningService signing, PkiSigningCommands commands, ServerSigningExecutor executor) { }
}
