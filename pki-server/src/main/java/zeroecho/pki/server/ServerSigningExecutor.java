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
        boolean acceptanceInvoked = false;
        try {
            cancellation.throwIfCancelled();
            if (operation instanceof PkiSigningOperation.GenerateStatus status
                    && status.type() == zeroecho.pki.api.status.StatusObjectType.OCSP) {
                return failed(operation, PkiOperationFailure.VALIDATION_FAILURE, "OCSP_TARGET_REQUIRED");
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
            return accept(service, prepared, operation);
        } catch (java.io.InterruptedIOException cancelled) {
            return failed(operation, PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED");
        } catch (UnsupportedOperationException missingCapability) {
            return failed(operation, PkiOperationFailure.VALIDATION_FAILURE, "CAPABILITY_NOT_CONFIGURED");
        } catch (NoSuchElementException missing) {
            return failed(operation, PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND");
        } catch (IllegalArgumentException invalid) {
            return failed(operation, PkiOperationFailure.VALIDATION_FAILURE, "OPERATION_INPUT_INVALID");
        } catch (SigningExecutionException execution) {
            return failed(operation, execution.classification() == SigningExecutionException.Classification.OVERLOADED
                    ? PkiOperationFailure.OVERLOADED : PkiOperationFailure.RESOURCE_FAILURE,
                    execution.classification() == SigningExecutionException.Classification.OVERLOADED
                            ? "SIGNING_OVERLOADED" : "PKI_RESOURCE_FAILED");
        } catch (PkiException rejected) {
            if (rejected.failureReason().orElse(null) == PkiFailureReason.STORE_DURABILITY_UNCONFIRMED) {
                return failed(operation, PkiOperationFailure.RECOVERY_REQUIRED, "RECOVERY_REQUIRED");
            }
            if (!acceptanceInvoked && cancelledPreparation(rejected, cancellation)) {
                return failed(operation, PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED");
            }
            return failed(operation, PkiOperationFailure.POLICY_REJECTION, "PKI_POLICY_REJECTED");
        } catch (IllegalStateException unavailable) {
            if (!acceptanceInvoked && cancelledPreparation(unavailable, cancellation)) {
                return failed(operation, PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED");
            }
            return failed(operation, PkiOperationFailure.RESOURCE_FAILURE, "PKI_RESOURCE_FAILED");
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
