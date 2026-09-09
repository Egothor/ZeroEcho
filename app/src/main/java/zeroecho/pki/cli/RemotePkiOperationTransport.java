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
package zeroecho.pki.cli;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.Optional;

import javax.net.ssl.SSLException;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.application.PkiOperationValue;

/**
 * Executes one PKI operation against a running {@code pki-server} over its
 * mutual-TLS admin HTTP API and returns a terminal (or bounded-wait-exhausted)
 * {@link PkiRemoteResult}.
 *
 * <p>The transport POSTs the request envelope to
 * {@code /admin/v1/operations/{operationId}} and interprets the HTTP status and
 * response envelope together. A {@code 202 PENDING} signing hand-off is resolved
 * by polling {@code /admin/v1/signing-operations/{id}} until it terminalizes or
 * the {@code --pending-wait} deadline elapses, mirroring the local bounded-wait
 * behavior; a still-pending operation is returned as {@link PkiRemoteResult.Pending}
 * for a clean operator resume.</p>
 */
final class RemotePkiOperationTransport {

    private static final String OPERATIONS_PATH = "/admin/v1/operations/";
    private static final String SIGNING_PATH = "/admin/v1/signing-operations/";
    private static final int HTTP_OK = 200;
    private static final int HTTP_ACCEPTED = 202;
    private static final int HTTP_BAD_REQUEST = 400;
    private static final int HTTP_UNAUTHORIZED = 401;
    private static final int HTTP_FORBIDDEN = 403;
    private static final int HTTP_NOT_FOUND = 404;
    private static final int HTTP_CONFLICT = 409;
    private static final int HTTP_UNPROCESSABLE = 422;
    private static final int HTTP_TOO_MANY = 429;
    private static final int HTTP_INTERNAL = 500;
    private static final int HTTP_UNAVAILABLE = 503;
    private static final int HTTP_GATEWAY_TIMEOUT = 504;

    private final PkiHttpExchange exchange;
    private final Duration pendingWait;
    private final long pollMillis;

    /**
     * Creates a transport over one open HTTP exchange.
     *
     * @param exchange open admin-API exchange
     * @param pendingWait bounded wait for a pending signing operation to terminalize
     * @param pollInterval interval between signing-operation status polls
     */
    /* default */ RemotePkiOperationTransport(PkiHttpExchange exchange, Duration pendingWait,
            Duration pollInterval) {
        this.exchange = Objects.requireNonNull(exchange, "exchange");
        this.pendingWait = Objects.requireNonNull(pendingWait, "pendingWait");
        if (pendingWait.isNegative()) {
            throw new IllegalArgumentException("pendingWait must not be negative");
        }
        this.pollMillis = Math.max(1L, Objects.requireNonNull(pollInterval, "pollInterval").toMillis());
    }

    /**
     * Submits one operation and resolves it to a terminal (or wait-exhausted) result.
     *
     * @param operationId dotted server operation identifier
     * @param arguments typed operation arguments
     * @param authorityId authority scope, absent for realm-wide operations
     * @param approvalId prior approval identifier, absent on first submission
     * @param deadline optional ISO-8601 execution deadline
     * @param cancellation cooperative cancellation signal
     * @return terminal or still-pending remote result
     * @throws PkiRemoteTransportException on TLS, authentication, connection, or protocol failure
     */
    /* default */ PkiRemoteResult submit(String operationId, PkiOperationValue.ObjectValue arguments,
            Optional<String> authorityId, Optional<String> approvalId, Optional<String> deadline,
            CancellationSignal cancellation) throws PkiRemoteTransportException {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(cancellation, "cancellation");
        if (cancellation.isCancelled()) {
            return new PkiRemoteResult.Failed(operationId, "CANCELLED", "REMOTE_CANCELLED", false, false);
        }
        byte[] body = PkiRemoteEnvelope.encodeRequest(authorityId, approvalId, deadline, arguments);
        PkiHttpExchange.Response response = send(PkiHttpExchange.Request.post(OPERATIONS_PATH
                + encodeSegment(operationId), body));
        PkiRemoteResult result = interpret(response, operationId, Optional.empty());
        if (result instanceof PkiRemoteResult.Pending pending) {
            return awaitPending(pending, cancellation);
        }
        return result;
    }

    // CLI polling deliberately uses the caller thread; no executor or background lifecycle is created.
    @SuppressWarnings("PMD.DoNotUseThreads")
    private PkiRemoteResult awaitPending(PkiRemoteResult.Pending pending, CancellationSignal cancellation)
            throws PkiRemoteTransportException {
        if (pendingWait.isZero()) {
            return pending;
        }
        long deadlineNanos = System.nanoTime() + pendingWait.toNanos();
        PkiRemoteResult current = pending;
        while (current instanceof PkiRemoteResult.Pending waiting && !cancellation.isCancelled()
                && System.nanoTime() < deadlineNanos) {
            try {
                Thread.sleep(pollMillis);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return current;
            }
            PkiHttpExchange.Response response = send(PkiHttpExchange.Request.get(SIGNING_PATH
                    + encodeSegment(waiting.operationId())));
            current = interpret(response, waiting.operation(), Optional.of(waiting.operationId()));
        }
        return current;
    }

    private PkiRemoteResult interpret(PkiHttpExchange.Response response, String operationId,
            Optional<String> knownPendingId) throws PkiRemoteTransportException {
        int status = response.statusCode();
        if (status == HTTP_UNAUTHORIZED) {
            throw new PkiRemoteTransportException(PkiExitCodes.CONFIGURATION_FAILURE, "CONFIGURATION_FAILURE",
                    "REMOTE_AUTHENTICATION_FAILED");
        }
        Optional<PkiRemoteEnvelope.ResponseEnvelope> envelope = tryDecode(response.body());
        String operation = envelope.flatMap(PkiRemoteEnvelope.ResponseEnvelope::operation).orElse(operationId);
        Optional<String> statusToken = envelope.flatMap(PkiRemoteEnvelope.ResponseEnvelope::status);
        if (statusToken.isPresent()) {
            Optional<PkiRemoteResult> resolved = fromStatusToken(statusToken.orElseThrow(), operation, envelope,
                    response, status, knownPendingId);
            if (resolved.isPresent()) {
                return resolved.orElseThrow();
            }
        }
        return synthesize(status, operation, envelope, response, knownPendingId);
    }

    private Optional<PkiRemoteResult> fromStatusToken(String statusToken, String operation,
            Optional<PkiRemoteEnvelope.ResponseEnvelope> envelope, PkiHttpExchange.Response response, int status,
            Optional<String> knownPendingId) throws PkiRemoteTransportException {
        return switch (statusToken) {
            case "SUCCEEDED" -> Optional.of(new PkiRemoteResult.Succeeded(operation, resultOf(envelope)));
            case "PENDING" -> Optional.of(pendingResult(operation, envelope, response, knownPendingId));
            case "APPROVAL_REQUIRED" -> Optional.of(approvalResult(operation, envelope));
            case "FAILED" -> Optional.of(failedResult(operation, envelope, status));
            default -> Optional.empty();
        };
    }

    private PkiRemoteResult synthesize(int status, String operation,
            Optional<PkiRemoteEnvelope.ResponseEnvelope> envelope, PkiHttpExchange.Response response,
            Optional<String> knownPendingId) throws PkiRemoteTransportException {
        return switch (status) {
            case HTTP_OK -> new PkiRemoteResult.Succeeded(operation, resultOf(envelope));
            case HTTP_ACCEPTED -> pendingResult(operation, envelope, response, knownPendingId);
            case HTTP_CONFLICT -> approvalResult(operation, envelope);
            case HTTP_FORBIDDEN -> classified(operation, "AUTHORIZATION_DENIED", status);
            case HTTP_BAD_REQUEST -> classified(operation, "VALIDATION_FAILURE", status);
            case HTTP_UNPROCESSABLE -> classified(operation, "POLICY_REJECTION", status);
            case HTTP_NOT_FOUND -> classified(operation, "NOT_FOUND", status);
            case HTTP_TOO_MANY -> classified(operation, "OVERLOADED", status);
            case HTTP_UNAVAILABLE -> classified(operation, "RESOURCE_FAILURE", status);
            case HTTP_GATEWAY_TIMEOUT -> classified(operation, "DEADLINE_EXCEEDED", status);
            case HTTP_INTERNAL -> classified(operation, "INTERNAL_FAILURE", status);
            default -> classified(operation, "INTERNAL_FAILURE", status);
        };
    }

    private static PkiRemoteResult failedResult(String operation,
            Optional<PkiRemoteEnvelope.ResponseEnvelope> envelope, int status) {
        Optional<PkiRemoteEnvelope.Failure> failure = envelope
                .flatMap(PkiRemoteEnvelope.ResponseEnvelope::failure);
        if (failure.isPresent()) {
            PkiRemoteEnvelope.Failure detail = failure.orElseThrow();
            return new PkiRemoteResult.Failed(operation, detail.classification(), detail.code(),
                    detail.recoveryRequired(), detail.reconciliationRequired());
        }
        return classified(operation, "INTERNAL_FAILURE", status);
    }

    private static PkiRemoteResult classified(String operation, String classification, int status) {
        return new PkiRemoteResult.Failed(operation, classification, "REMOTE_STATUS_" + status, false, false);
    }

    private PkiRemoteResult pendingResult(String operation,
            Optional<PkiRemoteEnvelope.ResponseEnvelope> envelope, PkiHttpExchange.Response response,
            Optional<String> knownPendingId) throws PkiRemoteTransportException {
        Optional<String> fromResult = envelope.flatMap(PkiRemoteEnvelope.ResponseEnvelope::result)
                .flatMap(object -> text(object, "operationId"));
        Optional<String> identifier = fromResult
                .or(() -> response.location().map(RemotePkiOperationTransport::lastSegment))
                .or(() -> knownPendingId);
        if (identifier.isEmpty()) {
            throw new PkiRemoteTransportException(PkiExitCodes.RESOURCE_FAILURE, "RESOURCE_FAILURE",
                    "REMOTE_PENDING_IDENTIFIER_MISSING");
        }
        return new PkiRemoteResult.Pending(operation, identifier.orElseThrow());
    }

    private static PkiRemoteResult approvalResult(String operation,
            Optional<PkiRemoteEnvelope.ResponseEnvelope> envelope) {
        Optional<String> commitment = envelope.flatMap(PkiRemoteEnvelope.ResponseEnvelope::result)
                .flatMap(object -> text(object, "operationCommitment"));
        if (commitment.isPresent()) {
            return new PkiRemoteResult.ApprovalRequired(operation, commitment.orElseThrow());
        }
        return new PkiRemoteResult.Failed(operation, "POLICY_REJECTION", "REMOTE_APPROVAL_REQUIRED", false, false);
    }

    private static PkiOperationValue.ObjectValue resultOf(
            Optional<PkiRemoteEnvelope.ResponseEnvelope> envelope) {
        return envelope.flatMap(PkiRemoteEnvelope.ResponseEnvelope::result)
                .orElseGet(() -> new PkiOperationValue.ObjectValue(new LinkedHashMap<>()));
    }

    private static Optional<String> text(PkiOperationValue.ObjectValue object, String name) {
        PkiOperationValue value = object.fields().get(name);
        return value instanceof PkiOperationValue.Text textValue ? Optional.of(textValue.value())
                : Optional.empty();
    }

    // A remote error body is untrusted and optional; every decoder runtime failure means "no envelope".
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private static Optional<PkiRemoteEnvelope.ResponseEnvelope> tryDecode(byte[] body) {
        if (body == null || body.length == 0) {
            return Optional.empty();
        }
        try {
            return Optional.of(PkiRemoteEnvelope.decodeResponse(body));
        } catch (RuntimeException failure) {
            return Optional.empty();
        }
    }

    // The CLI boundary intentionally replaces provider exception graphs with stable non-sensitive codes.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private PkiHttpExchange.Response send(PkiHttpExchange.Request request) throws PkiRemoteTransportException {
        try {
            return exchange.send(request);
        } catch (SSLException tls) {
            throw new PkiRemoteTransportException(PkiExitCodes.CONFIGURATION_FAILURE, "CONFIGURATION_FAILURE",
                    "REMOTE_TLS_HANDSHAKE_FAILED");
        } catch (IOException network) {
            throw new PkiRemoteTransportException(PkiExitCodes.RESOURCE_FAILURE, "RESOURCE_FAILURE",
                    "REMOTE_CONNECTION_FAILED");
        }
    }

    private static String lastSegment(String path) {
        String trimmed = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        int slash = trimmed.lastIndexOf('/');
        return slash < 0 ? trimmed : trimmed.substring(slash + 1);
    }

    private static String encodeSegment(String segment) {
        return URLEncoder.encode(segment, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
