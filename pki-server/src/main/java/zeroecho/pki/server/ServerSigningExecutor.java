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

import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSigningOperation;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.server.jfr.SigningOperationEvent;

/** Stateless authorized-command adapter; the existing session owns every resource. */
final class ServerSigningExecutor implements ServerOperationGateway.SigningExecutor {
    private final PkiSession session;

    /* default */ ServerSigningExecutor(PkiSession session) {
        this.session = Objects.requireNonNull(session, "session");
    }

    @Override
    public PkiOperationOutcome execute(ServerOperationGateway.Request request,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        PkiSigningOperation operation = ((AdministrativeOperation.Signing) request.operation()).operation();
        SigningOperationEvent jfrEvent = new SigningOperationEvent();
        jfrEvent.operationId = operation.name();
        jfrEvent.authorityId = request.resource().scope().authorityId()
                .map(Object::toString).orElse("");
        jfrEvent.begin();
        boolean acceptanceInvoked = false;
        PkiOperationOutcome outcome = null;
        try {
            cancellation.throwIfCancelled();
            if (operation instanceof PkiSigningOperation.GenerateStatus status
                    && status.type() == zeroecho.pki.api.status.StatusObjectType.OCSP) {
                outcome = failed(operation, PkiOperationFailure.VALIDATION_FAILURE, "OCSP_TARGET_REQUIRED");
                return outcome;
            }
            SemanticSigningService service = session.semanticSigning().orElseThrow(UnsupportedOperationException::new);
            AccessContext access = new AccessContext(new Principal("ADMIN_PRINCIPAL", request.principalId()),
                    new Purpose(operation.name()), Optional.empty(), Optional.empty());
            PreparedSemanticSigningRequest prepared = session.signingCommands()
                    .orElseThrow(UnsupportedOperationException::new)
                    .prepare(operation, access, evidence, cancellation);
            requireActivePreparation(service, prepared, cancellation);
            // This flag records crossing the same accept boundary, even when the result is uncertain.
            acceptanceInvoked = true;
            outcome = accept(service, prepared, operation);
            return outcome;
        } catch (java.io.InterruptedIOException cancelled) {
            outcome = failed(operation, PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED");
            return outcome;
        } catch (UnsupportedOperationException missingCapability) {
            outcome = failed(operation, PkiOperationFailure.VALIDATION_FAILURE, "CAPABILITY_NOT_CONFIGURED");
            return outcome;
        } catch (NoSuchElementException missing) {
            outcome = failed(operation, PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND");
            return outcome;
        } catch (IllegalArgumentException invalid) {
            outcome = failed(operation, PkiOperationFailure.VALIDATION_FAILURE, "OPERATION_INPUT_INVALID");
            return outcome;
        } catch (SigningExecutionException execution) {
            outcome = failed(operation, execution.classification() == SigningExecutionException.Classification.OVERLOADED
                    ? PkiOperationFailure.OVERLOADED : PkiOperationFailure.RESOURCE_FAILURE,
                    execution.classification() == SigningExecutionException.Classification.OVERLOADED
                            ? "SIGNING_OVERLOADED" : "PKI_RESOURCE_FAILED");
            return outcome;
        } catch (PkiException rejected) {
            if (rejected.failureReason().orElse(null) == PkiFailureReason.STORE_DURABILITY_UNCONFIRMED) {
                outcome = failed(operation, PkiOperationFailure.RECOVERY_REQUIRED, "RECOVERY_REQUIRED");
                return outcome;
            }
            if (!acceptanceInvoked && cancelledPreparation(rejected, cancellation)) {
                outcome = failed(operation, PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED");
                return outcome;
            }
            outcome = failed(operation, PkiOperationFailure.POLICY_REJECTION, "PKI_POLICY_REJECTED");
            return outcome;
        } catch (IllegalStateException unavailable) {
            if (!acceptanceInvoked && cancelledPreparation(unavailable, cancellation)) {
                outcome = failed(operation, PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED");
                return outcome;
            }
            outcome = failed(operation, PkiOperationFailure.RESOURCE_FAILURE, "PKI_RESOURCE_FAILED");
            return outcome;
        } finally {
            commitEvent(jfrEvent, outcome);
        }
    }

    private static void commitEvent(SigningOperationEvent event, PkiOperationOutcome outcome) {
        if (event.shouldCommit()) {
            event.succeeded = !(outcome instanceof PkiOperationOutcome.Failed);
            if (outcome instanceof PkiOperationOutcome.Failed failed) {
                event.failureReason = failed.code();
            }
            event.commit();
        }
    }

    private static boolean cancelledPreparation(RuntimeException failure, CancellationSignal cancellation) {
        if (cancellation.isCancelled()) { return true; }
        Throwable cause = failure;
        while (cause != null) {
            if (cause instanceof java.io.InterruptedIOException) { return true; }
            cause = cause.getCause();
        }
        return false;
    }

    private static PkiOperationOutcome failed(PkiSigningOperation operation,
            PkiOperationFailure classification, String code) {
        return new PkiOperationOutcome.Failed(operation.name(), classification, code);
    }

    // Every uncertain provider outcome is resolved using its original receipt, without replay.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private static PkiOperationOutcome accept(SemanticSigningService service,
            PreparedSemanticSigningRequest prepared, PkiSigningOperation operation) {
        SigningAcceptanceResult accepted;
        try {
            // Invoking accept transfers custody. Never discard or submit a replacement after this boundary.
            accepted = service.accept(prepared);
        } catch (RuntimeException uncertain) {
            SigningAcceptanceResolution resolution;
            try {
                resolution = service.resolve(prepared.receipt());
            } catch (RuntimeException unresolved) {
                return failed(operation, PkiOperationFailure.RECOVERY_REQUIRED, "RECOVERY_REQUIRED");
            }
            if (resolution == SigningAcceptanceResolution.MATCHED) {
                return new PkiOperationOutcome.Pending(operation.name(), prepared.receipt().operationId());
            }
            if (resolution == SigningAcceptanceResolution.CONFLICT) {
                return failed(operation, PkiOperationFailure.CONFLICT, "OPERATION_CONFLICT");
            }
            throw uncertain;
        }
        return switch (accepted.disposition()) {
            case ACCEPTED, ATTACHED_EXISTING ->
                new PkiOperationOutcome.Pending(operation.name(), accepted.receipt().operationId());
            case CONFLICT -> failed(operation, PkiOperationFailure.CONFLICT, "OPERATION_CONFLICT");
            case CAPACITY_REJECTED -> failed(operation, PkiOperationFailure.OVERLOADED, "SIGNING_OVERLOADED");
        };
    }


    // Discard occurs only before the original acceptance boundary, preserving the original cancellation.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private static void requireActivePreparation(SemanticSigningService service,
            PreparedSemanticSigningRequest prepared, CancellationSignal cancellation) throws java.io.InterruptedIOException {
        try {
            cancellation.throwIfCancelled();
        } catch (java.io.InterruptedIOException cancelled) {
            try {
                service.discard(prepared);
            } catch (RuntimeException cleanup) {
                cancelled.addSuppressed(cleanup);
            }
            throw cancelled;
        }
    }

}
