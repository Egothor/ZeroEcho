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
package zeroecho.pki.cli;

import java.io.IOException;
import java.net.URLEncoder;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import javax.net.ssl.SSLHandshakeException;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.application.PkiOperationValue;

/** Submit-once remote execution and caller-thread observation of a retained receipt. */
final class RemotePkiOperationTransport { // NOPMD - CyclomaticComplexity totals independent cohesive operations; method-level checks remain enabled.
    private static final int HTTP_UNAUTHORIZED = 401;
    private static final String OPERATIONS_PATH = "/admin/v1/operations/";
    private static final String SIGNING_PATH = "/admin/v1/signing-operations/";
    private static final Set<String> SIGNING_OPERATIONS = Set.of("ca.create", "ca.intermediate.create",
            "ca.intermediate.issue", "ca.rollover", "ca.rotate", "credential.issue", "credential.renew",
            "credential.replace", "credential.reissue", "status.generate");
    private final PkiHttpExchange exchange;
    private final Duration pendingWait;
    private final Duration pollInterval;

    /* default */ RemotePkiOperationTransport(PkiHttpExchange exchange, Duration pendingWait, Duration pollInterval) {
        this.exchange = Objects.requireNonNull(exchange, "exchange");
        this.pendingWait = Objects.requireNonNull(pendingWait, "pendingWait");
        this.pollInterval = Objects.requireNonNull(pollInterval, "pollInterval");
        if (pendingWait.isNegative() || pollInterval.isNegative() || pollInterval.isZero()) {
            throw new IllegalArgumentException("Invalid observation duration");
        }
    }

    /* default */ // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
                  @SuppressWarnings({ "PMD.PreserveStackTrace" })
                  PkiRemoteResult submit(String operation, PkiOperationValue.ObjectValue arguments,
            Optional<String> authorityId, Optional<String> approvalId, Optional<String> deadline,
            CancellationSignal cancellation) throws PkiRemoteTransportException {
        if (cancelled(cancellation)) {
            return new PkiRemoteResult.Failed(operation, "CANCELLED", "REMOTE_CANCELLED", false, false);
        }
        byte[] body = PkiRemoteEnvelope.encodeRequest(authorityId, approvalId, deadline, arguments);
        PkiHttpExchange.Response response;
        try {
            response = exchange.send(PkiHttpExchange.Request.post(OPERATIONS_PATH + segment(operation), body));
        } catch (PkiHttpExchange.InvalidResponseException invalid) {
            throw new PkiRemoteTransportException(9, "INTERNAL_FAILURE", "REMOTE_PROTOCOL_INVALID");
        } catch (SSLHandshakeException handshake) {
            throw new PkiRemoteTransportException(3, "CONFIGURATION_FAILURE", "REMOTE_TLS_HANDSHAKE_FAILED");
        } catch (IOException uncertain) {
            return new PkiRemoteResult.Failed(operation, "EXTERNAL_OUTCOME_UNKNOWN",
                    "REMOTE_ACCEPTANCE_UNKNOWN", false, true);
        }
        PkiRemoteResult result = interpret(response, operation, Optional.empty());
        return result instanceof PkiRemoteResult.Pending pending ? awaitPending(pending, cancellation) : result;
    }

    /* default */ PkiRemoteResult inspect(String operationId, CancellationSignal cancellation) {
        requireIdentifier(operationId);
        PkiRemoteResult.Pending pending = pending("signing.operation", operationId);
        if (cancelled(cancellation)) { return interrupted(pending); }
        return observe(pending, Duration.ofSeconds(60), false);
    }

    // Observation is confined to the CLI caller; it never advances or cancels server work.
    @SuppressWarnings("PMD.DoNotUseThreads")
    private PkiRemoteResult awaitPending(PkiRemoteResult.Pending initialPending, CancellationSignal cancellation) {
        PkiRemoteResult.Pending pending = initialPending;
        long started = System.nanoTime();
        long budget = pendingWait.toNanos();
        while (true) {
            if (cancelled(cancellation)) { return interrupted(pending); }
            long remaining = budget - (System.nanoTime() - started);
            if (remaining <= 0) { return pending; }
            try {
                Thread.sleep(Duration.ofNanos(Math.min(pollInterval.toNanos(), remaining)));
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return interrupted(pending);
            }
            if (cancelled(cancellation)) { return interrupted(pending); }
            remaining = budget - (System.nanoTime() - started);
            if (remaining <= 0) { return pending; }
            PkiRemoteResult observed = observe(pending, Duration.ofNanos(Math.min(
                    Duration.ofSeconds(60).toNanos(), remaining)), remaining <= Duration.ofSeconds(60).toNanos());
            if (!(observed instanceof PkiRemoteResult.Pending next) || next.observationFailure().isPresent()) {
                return observed;
            }
            pending = next;
        }
    }

    // Standalone execution checks or restores interruption; it neither creates threads nor runs in a J2EE container.
    @SuppressWarnings({ "PMD.DoNotUseThreads" })
    private PkiRemoteResult observe(PkiRemoteResult.Pending pending, Duration timeout, boolean budgetLimited) {
        try {
            PkiHttpExchange.Response response = exchange.send(new PkiHttpExchange.Request(
                    PkiHttpExchange.Method.GET, SIGNING_PATH + segment(pending.operationId()), Optional.empty(), timeout));
            return interpret(response, pending.operation(), Optional.of(pending.operationId()));
        } catch (PkiHttpExchange.InvalidResponseException invalid) {
            return observationFailure(pending, "INTERNAL_FAILURE", "REMOTE_PROTOCOL_INVALID", 9);
        } catch (HttpTimeoutException timeoutFailure) {
            return budgetLimited ? pending : observationFailure(pending, "RESOURCE_FAILURE", "REMOTE_OBSERVATION_FAILED", 8);
        } catch (IOException failure) {
            return Thread.currentThread().isInterrupted() ? interrupted(pending)
                    : observationFailure(pending, "RESOURCE_FAILURE", "REMOTE_OBSERVATION_FAILED", 8);
        } catch (PkiRemoteTransportException failure) {
            return observationFailure(pending, failure.category(), failure.code(), failure.exitCode());
        }
    }

    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    private static PkiRemoteResult interpret(PkiHttpExchange.Response response, String requested,
            Optional<String> knownId) throws PkiRemoteTransportException {
        if (response.statusCode() == HTTP_UNAUTHORIZED) {
            throw new PkiRemoteTransportException(3, "CONFIGURATION_FAILURE", "REMOTE_AUTHENTICATION_FAILED");
        }
        try {
            return interpretEnvelope(response, requested, knownId);
        } catch (IllegalArgumentException | java.util.NoSuchElementException malformed) {
            throw new PkiRemoteTransportException(9, "INTERNAL_FAILURE", "REMOTE_PROTOCOL_INVALID");
        }
    }

    private static PkiRemoteResult interpretEnvelope(PkiHttpExchange.Response response, String requested,
            Optional<String> knownId) {
        PkiRemoteEnvelope.ResponseEnvelope envelope = PkiRemoteEnvelope.decodeResponse(response.body());
        String operation = envelope.operation().orElseThrow();
        String status = envelope.status().orElseThrow();
        Optional<String> bodyId = responseIdentity(envelope, operation, status, requested, knownId);
        int http = response.statusCode();
        return switch (status) {
            case "SUCCEEDED" -> succeeded(envelope, http, requested, knownId, bodyId);
            case "PENDING" -> {
                if (http != 202 || envelope.failure().isPresent()) { throw invalid(); }
                yield pending(requested, bodyId.orElseThrow(RemotePkiOperationTransport::invalid));
            }
            case "APPROVAL_REQUIRED" -> approvalRequired(envelope, http, requested, knownId);
            case "FAILED" -> failed(envelope, http, requested, bodyId.or(() -> knownId));
            default -> throw invalid();
        };
    }

    private static Optional<String> responseIdentity(PkiRemoteEnvelope.ResponseEnvelope envelope,
            String operation, String status, String requested, Optional<String> knownId) {
        String expectedOperation = knownId.isPresent() ? "signing.operation" : requested;
        if (!operation.equals(expectedOperation)
                && !("FAILED".equals(status) && Set.of("operation", "request").contains(operation))) { throw invalid(); }
        Optional<String> bodyId = envelope.result().flatMap(value -> text(value, "operationId"));
        bodyId.ifPresent(RemotePkiOperationTransport::requireIdentifier);
        if (knownId.isPresent() && bodyId.isPresent() && !knownId.equals(bodyId)) { throw invalid(); }
        return bodyId;
    }

    private static PkiRemoteResult succeeded(PkiRemoteEnvelope.ResponseEnvelope envelope, int http,
            String requested, Optional<String> knownId, Optional<String> bodyId) {
        if (http != 200 || envelope.failure().isPresent()
                || (knownId.isEmpty() && SIGNING_OPERATIONS.contains(requested))) { throw invalid(); }
        PkiOperationValue.ObjectValue fields = envelope.result().orElseThrow(RemotePkiOperationTransport::invalid);
        if (knownId.isPresent() || "signing.operation".equals(envelope.operation().orElseThrow()) || bodyId.isPresent()) {
            if (bodyId.isEmpty()) { throw invalid(); }
            validateCompletion(fields);
        }
        return new PkiRemoteResult.Succeeded(requested, fields, bodyId);
    }

    private static PkiRemoteResult approvalRequired(PkiRemoteEnvelope.ResponseEnvelope envelope, int http,
            String requested, Optional<String> knownId) {
        if (http != 409 || knownId.isPresent() || envelope.failure().isEmpty()
                || !"APPROVAL_REQUIRED".equals(envelope.failure().orElseThrow().code())
                || !"APPROVAL_REQUIRED".equals(envelope.failure().orElseThrow().classification())) { throw invalid(); }
        String commitment = text(envelope.result().orElseThrow(RemotePkiOperationTransport::invalid),
                "operationCommitment").orElseThrow(RemotePkiOperationTransport::invalid);
        if (!commitment.matches("[0-9a-f]{64}")) { throw invalid(); }
        return new PkiRemoteResult.ApprovalRequired(requested, commitment);
    }

    private static PkiRemoteResult failed(PkiRemoteEnvelope.ResponseEnvelope envelope, int http,
            String requested, Optional<String> operationId) {
        if (http < 400 || http > 599) { throw invalid(); }
        PkiRemoteEnvelope.Failure failure = envelope.failure().orElseThrow(RemotePkiOperationTransport::invalid);
        if (!failure.classification().matches("[A-Z][A-Z0-9_]{0,127}")
                || !failure.code().matches("[A-Z][A-Z0-9_]{0,127}")) { throw invalid(); }
        return new PkiRemoteResult.Failed(requested, failure.classification(), failure.code(),
                failure.recoveryRequired(), failure.reconciliationRequired(), operationId);
    }

    private static void validateCompletion(PkiOperationValue.ObjectValue result) {
        String kind = text(result, "kind").orElseThrow(RemotePkiOperationTransport::invalid);
        String encoding = text(result, "encoding").orElseThrow(RemotePkiOperationTransport::invalid);
        String digest = text(result, "resultSha256").orElseThrow(RemotePkiOperationTransport::invalid);
        for (String optionalId : Set.of("credentialId", "statusObjectId")) {
            text(result, optionalId).ifPresent(value -> { if (value.isBlank()) { throw invalid(); } });
        }
        if (!Set.of("CA", "ISSUANCE", "STATUS").contains(kind)
                || !Set.of("DER", "PEM", "BINARY").contains(encoding) || !digest.matches("[0-9a-f]{64}")) { throw invalid(); }
    }

    /* default */ static void requireIdentifier(String identifier) {
        if (identifier == null || identifier.isBlank() || identifier.length() > 512 || identifier.contains("/")) {
            throw invalid();
        }
    }

    private static Optional<String> text(PkiOperationValue.ObjectValue object, String field) {
        PkiOperationValue value = object.fields().get(field);
        if (value == null) { return Optional.empty(); }
        if (!(value instanceof PkiOperationValue.Text text)) { throw invalid(); }
        return Optional.of(text.value());
    }

    private static PkiRemoteResult.Pending pending(String operation, String identifier) {
        return new PkiRemoteResult.Pending(operation, identifier, Optional.empty());
    }

    private static PkiRemoteResult.Pending interrupted(PkiRemoteResult.Pending pending) {
        return observationFailure(pending, "CANCELLED", "REMOTE_OBSERVATION_INTERRUPTED", 130);
    }

    private static PkiRemoteResult.Pending observationFailure(PkiRemoteResult.Pending pending,
            String classification, String code, int exit) {
        return new PkiRemoteResult.Pending(pending.operation(), pending.operationId(), Optional.of(
                new PkiRemoteResult.ObservationFailure(classification, code, exit)));
    }

    // Standalone execution checks or restores interruption; it neither creates threads nor runs in a J2EE container.
    @SuppressWarnings({ "PMD.DoNotUseThreads" })
    private static boolean cancelled(CancellationSignal cancellation) {
        return Thread.currentThread().isInterrupted() || cancellation.isCancelled();
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid remote protocol");
    }

    private static String segment(String value) {
        String encoded = URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
        return ".".equals(value) || "..".equals(value) ? encoded.replace(".", "%2E") : encoded;
    }
}
