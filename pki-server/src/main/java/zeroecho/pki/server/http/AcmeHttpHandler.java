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
package zeroecho.pki.server.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsExchange;

import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofResult;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.acme.AcmeJwsVerifier;
import zeroecho.pki.server.acme.AcmeNonceService;
import zeroecho.pki.server.acme.AcmeRateAdmission;
import zeroecho.pki.server.acme.AcmeService;
import zeroecho.pki.server.acme.AcmeState;
import zeroecho.pki.server.acme.AcmeWireBounds;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;

/**
 * Strict ACME route adapter; protocol state and PKI business rules remain in {@link AcmeService}.
 */
/* default */ final class AcmeHttpHandler implements HttpHandler {
    private static final int RESOURCE_SEGMENTS = 4;

    private static final String TEXT_SERVERINTERNAL = "serverInternal";
    private static final String TEXT_MALFORMED = "malformed";
    private static final String TEXT_RATELIMITED = "rateLimited";
    private static final int BOUND_5 = 5;
    private static final String TEXT_CHALLENGE = "challenge";
    private static final String TEXT_ACCOUNTDOESNOTEXIST = "accountDoesNotExist";
    private static final String TEXT_ACME = "/acme/";
    private static final String TEXT_CONTACT = "contact";
    private static final String TEXT_LITERAL_52D9 = "\"}";

    private static final String JOSE = "application/jose+json";
    private static final String JSON = "application/json";
    private static final String PROBLEM = "application/problem+json";
    private static final String PEM_CHAIN = "application/pem-certificate-chain";
    private final PkiServerConfiguration.AcmeListener configuration;
    private final ServerRealmContext realm;
    private final AcmeService service;
    private final AcmeNonceService nonces;
    private final AcmeJwsVerifier verifier = new AcmeJwsVerifier();
    private final AcmeRateAdmission rates;
    private final ServerRuntime runtime;
    private final ServerRuntime.ChallengeRuntime validations;
    private final Clock clock;
    private final RequestIds requestIds;
    private final BooleanSupplier ready;
    private final AcmeTransportAuthentication transportAuthentication;

    /**
     * Composes ACME HTTP admission, account authentication and challenge-validation execution.
     *
     * @param configuration ACME listener, origin, rate and proxy-transport policies
     * @param realm lifecycle-owned realm context
     * @param service realm-owned ACME service
     * @param nonces bounded ACME replay-nonce owner
     * @param runtime lifecycle-owned protocol operation executor
     * @param validations separately admitted challenge-validation executor
     * @param clock deadline, rate and audit time source
     * @param requestIds correlation-identifier validator/generator
     * @param ready readiness observation checked before request admission
     */
    /* default */ AcmeHttpHandler(
            PkiServerConfiguration.AcmeListener configuration,
            ServerRealmContext realm,
            AcmeService service,
            AcmeNonceService nonces,
            ServerRuntime runtime,
            ServerRuntime.ChallengeRuntime validations,
            Clock clock,
            RequestIds requestIds,
            BooleanSupplier ready) {
        this.configuration = configuration;
        this.realm = realm;
        this.service = service;
        this.nonces = nonces;
        this.runtime = runtime;
        this.validations = validations;
        this.clock = clock;
        this.requestIds = requestIds;
        this.ready = ready;
        this.rates = new AcmeRateAdmission(configuration, clock);
        this.transportAuthentication = new AcmeTransportAuthentication(configuration, realm, clock);
    }

    /**
     * {@inheritDoc}
     */
    // This transport boundary must preserve cleanup and finite masking of provider/runtime
    // failures. The
    // standalone transport owns bounded task executors and preserves cancellation/thread lifetime.
    @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.DoNotUseThreads"})
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String requestId = "unavailable-request";
        try {
            requestId = requestIds.resolve(exchange.getRequestHeaders().get(RequestIds.HEADER));
            requireHeaders(exchange.getRequestHeaders());
            if (!ready.getAsBoolean()) {
                send(exchange, problem(503, TEXT_SERVERINTERNAL), requestId, null);
                return;
            }
            if (!transportAuthentication.authenticate((HttpsExchange) exchange, requestId)) {
                audit("ACME_TRANSPORT_AUTH", "system", requestId, "REJECTED");
                send(exchange, problem(401, "unauthorized"), requestId, null);
                return;
            }
            audit("ACME_TRANSPORT_AUTH", "system", requestId, "ACCEPTED");
            if (containsForwardedIdentity(exchange.getRequestHeaders())) {
                send(exchange, problem(400, TEXT_MALFORMED), requestId, null);
                return;
            }
            if (!runtime.tryAdmit()) {
                send(exchange, problem(429, TEXT_RATELIMITED), requestId, null);
                return;
            }
            try {
                String exactRequestId = requestId;
                Instant requestDeadline =
                        clock.instant().plus(configuration.execution().maximumDeadline());
                ServerRuntime.Submitted<Response> submitted =
                        runtime.submit(
                                cancellation ->
                                        new RequestRouting()
                                                .route(
                                                        exchange,
                                                        exactRequestId,
                                                        cancellation,
                                                        requestDeadline));
                Response response;
                try {
                    response =
                            submitted
                                    .future()
                                    .get(
                                            configuration.execution().maximumDeadline().toMillis(),
                                            TimeUnit.MILLISECONDS);
                } catch (TimeoutException timeout) {
                    submitted.cancellation().cancel();
                    submitted.future().cancel(true);
                    response = problem(504, TEXT_SERVERINTERNAL);
                } catch (InterruptedException interrupted) {
                    submitted.cancellation().cancel();
                    submitted.future().cancel(true);
                    Thread.currentThread().interrupt();
                    response = problem(504, TEXT_SERVERINTERNAL);
                } catch (ExecutionException failure) {
                    response = protocolFailure(failure.getCause());
                }
                try {
                    send(exchange, response, requestId, response.directoryId());
                } finally {
                    submitted.finish();
                }
            } catch (RejectedExecutionException overloaded) {
                send(exchange, problem(429, TEXT_RATELIMITED), requestId, null);
            } finally {
                runtime.releaseAdmission();
            }
        } catch (IllegalArgumentException malformed) {
            send(exchange, problem(400, TEXT_MALFORMED), requestId, null);
        } catch (RuntimeException failure) {
            send(exchange, problem(500, TEXT_SERVERINTERNAL), requestId, null);
        }
    }

    // This transport boundary must preserve cleanup and finite masking of provider/runtime
    // failures. Untrusted
    // transport/parser failures retain the existing finite safe HTTP diagnostics. Preserve the
    // exact
    // exchange-finally ownership and close-failure precedence.
    @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.UseTryWithResources"})
    private void send(
            HttpExchange exchange, Response response, String requestId, String directoryId)
            throws IOException {
        try {
            String nonceScope =
                    directoryId == null
                            ? nonceScope(exchange.getRequestURI())
                            : service.directory(directoryId).alias();
            exchange.getResponseHeaders().set("Replay-Nonce", nonces.issue(nonceScope));
        } catch (RuntimeException ignored) {
            /* Capacity failure is already represented by the response. */
        }
        exchange.getResponseHeaders().set(RequestIds.HEADER, requestId);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("Content-Type", response.contentType());
        response.headers().forEach((name, value) -> exchange.getResponseHeaders().set(name, value));
        boolean delivered = false;
        try {
            if (response.writer().isPresent()) {
                exchange.sendResponseHeaders(response.status(), 0);
                try (OutputStream output = exchange.getResponseBody()) {
                    response.writer().orElseThrow().write(output);
                }
            } else {
                exchange.sendResponseHeaders(response.status(), response.body().length);
                try (OutputStream output = exchange.getResponseBody()) {
                    output.write(response.body());
                }
            }
            delivered = true;
        } finally {
            audit(
                    "ACME_REQUEST",
                    "system",
                    requestId,
                    delivered ? "HTTP_" + response.status() : "DELIVERY_UNKNOWN");
            exchange.close();
        }
    }

    private String nonceScope(URI requestUri) {
        String[] parts = requestUri.getPath().split("/", -1);
        if (parts.length >= 3 && "acme".equals(parts[1])) {
            return service.nonceScope(parts[2]);
        }
        throw new IllegalArgumentException("ACME nonce scope is unavailable");
    }

    private void audit(String action, String actor, String requestId, String outcome) {
        realm.auditTransport(action, actor, Map.of("requestId", requestId, "outcome", outcome,
                "mode", configuration.transportMode().name()));
    }

    private static Response json(int status, String json, String directoryId) {
        return json(status, json, directoryId, Map.of());
    }
    private static Response json(int status, String json, String directoryId, Map<String, String> headers) {
        return new Response(status, JSON, json.getBytes(StandardCharsets.UTF_8), Optional.empty(), directoryId,
                headers);
    }
    private static Response problem(int status, String type) {
        return new Response(status, PROBLEM, ("{\"type\":\"urn:ietf:params:acme:error:" + type
                + "\",\"detail\":\"ACME request rejected\"}").getBytes(StandardCharsets.UTF_8),
                Optional.empty(), null, Map.of());
    }

    /**
     * Maps an execution failure to a safe ACME problem document without exposing exception text.
     *
     * @param failure protocol, authorization, CSR, signing or internal failure
     * @return ACME problem response with the corresponding HTTP status
     */
    /* default */ static Response protocolFailure(Throwable failure) {
        if (failure instanceof zeroecho.pki.api.SigningExecutionException signingFailure
                && signingFailure.classification()
                        == zeroecho.pki.api.SigningExecutionException.Classification.OVERLOADED) {
            return problem(429, TEXT_RATELIMITED);
        }
        if (failure instanceof AcmeJwsVerifier.AcmeProblem problem) {
            return problem(problemStatus(problem.type()), problem.type());
        }
        if (failure instanceof SecurityException || failure instanceof IllegalArgumentException) {
            return problem(403, "unauthorized");
        }
        if (failure instanceof zeroecho.pki.api.PkiException) {
            return problem(400, "badCSR");
        }
        if (failure instanceof IllegalStateException) {
            return problem(403, "orderNotReady");
        }
        return problem(500, TEXT_SERVERINTERNAL);
    }

    private static int problemStatus(String type) {
        return switch (type) {
            case "unauthorized", TEXT_ACCOUNTDOESNOTEXIST, "orderNotReady", "userActionRequired" ->
                    403;
            case TEXT_RATELIMITED -> 429;
            case TEXT_SERVERINTERNAL -> 500;
            default -> 400;
        };
    }

    private static byte[] readBody(InputStream input, int maximum) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(maximum, 16_384));
        byte[] buffer = new byte[8_192];
        int total = 0;
        int count;
        while ((count = input.read(buffer)) >= 0) {
            if (count == 0) {
                continue;
            }
            total = Math.addExact(total, count);
            if (total > maximum) {
                throw new IllegalArgumentException("ACME request body is too large");
            }
            output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }

    private void requireHeaders(Map<String, List<String>> headers) {
        long count = 0;
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            count += entry.getKey().length();
            for (String value : entry.getValue()) {
                count += value.length();
            }
            if (count > configuration.maximumHeaderBytes()) {
                throw new IllegalArgumentException("ACME headers too large");
            }
        }
    }

    private static boolean containsForwardedIdentity(Map<String, List<String>> headers) {
        return headers.containsKey(ForwardedClientCertificateParser.RFC_CERTIFICATE_HEADER)
                || headers.containsKey(ForwardedClientCertificateParser.RFC_CHAIN_HEADER)
                || headers.containsKey(
                        ForwardedClientCertificateParser.DIRECT_REJECTED_NGINX_HEADER);
    }

    private static String baseContentType(String value) {
        return value == null ? "" : value.split(";", 2)[0].trim();
    }
    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    /**
     * ACME response metadata with either a buffered entity or a deferred streaming writer.
     *
     * @param status HTTP response status
     * @param contentType response media type
     * @param body buffered entity bytes; copied
     * @param writer optional deferred entity writer
     * @param directoryId directory identity for link metadata, or null when unavailable
     * @param headers additional response header values; copied to an immutable map
     */
    /* default */ record Response(int status, String contentType, byte[] body, Optional<BodyWriter> writer,
            String directoryId, Map<String, String> headers) {
        /**
         * Snapshots buffered entity bytes and additional response headers.
         *
         * @param status HTTP response status
         * @param contentType response media type
         * @param body buffered entity bytes; copied
         * @param writer optional deferred entity writer
         * @param directoryId directory identity, or null
         * @param headers additional response fields; copied
         * @throws NullPointerException if body, writer, headers or a header entry is null
         */
        /* default */ Response {
            body = body.clone();
            writer = Objects.requireNonNull(writer, "writer");
            headers = Map.copyOf(headers);
        }
        /**
         * Copies the buffered ACME response entity.
         *
         * @return caller-owned response bytes; empty for responses using only a streaming writer
         */
        @Override public byte[] body() { return body.clone(); }
    }
    /** Writes one deferred body while the response sender owns the exchange. */
    @FunctionalInterface private interface BodyWriter {
        /** Writes the complete body, leaving stream closure to the response sender. */
        void write(OutputStream output) throws IOException;
    }

    /** Strict bounded ACME payload field grammar. */
    private static final class FieldValues {
        private static void requirePostAsGet(byte[] payload) {
            if (payload.length != 0) {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
            }
        }

        private static PkiOperationValue.ObjectValue objectOrEmpty(byte[] payload) {
            return payload.length == 0
                    ? new PkiOperationValue.ObjectValue(Map.of())
                    : object(StrictJson.parse(payload, 65_536));
        }

        private static PkiOperationValue.ObjectValue object(PkiOperationValue value) {
            if (value instanceof PkiOperationValue.ObjectValue object) {
                return object;
            }
            throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
        }

        private static void requireOnly(PkiOperationValue.ObjectValue value, String... fields) {
            if (!java.util.Set.of(fields).containsAll(value.fields().keySet())) {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
            }
        }

        private static boolean bool(
                PkiOperationValue.ObjectValue value, String field, boolean defaultValue) {
            PkiOperationValue item = value.fields().get(field);
            if (item == null) {
                return defaultValue;
            }
            if (item instanceof PkiOperationValue.BooleanValue flag) {
                return flag.value();
            }
            throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
        }

        private static String requiredText(PkiOperationValue.ObjectValue value, String field) {
            if (value.fields().get(field) instanceof PkiOperationValue.Text text) {
                return text.value();
            }
            throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
        }

        private static long requiredLong(PkiOperationValue.ObjectValue value, String field) {
            if (value.fields().get(field) instanceof PkiOperationValue.IntegerValue integer) {
                return integer.value();
            }
            throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
        }

        // Untrusted transport/parser failures retain the existing finite safe HTTP diagnostics.
        @SuppressWarnings({"PMD.PreserveStackTrace"})
        private static byte[] decodeProofResponse(String encoded) {
            if (encoded.isEmpty()
                    || encoded.length() > AcmeWireBounds.MAX_PROOF_B64URL_CHARS
                    || !encoded.matches("[A-Za-z0-9_-]+")) {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
            }
            byte[] decoded;
            try {
                decoded = Base64.getUrlDecoder().decode(encoded);
            } catch (IllegalArgumentException malformed) {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
            }
            if (!encoded.equals(Base64.getUrlEncoder().withoutPadding().encodeToString(decoded))) {
                java.util.Arrays.fill(decoded, (byte) 0);
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
            }
            return decoded;
        }

        private static List<String> textList(
                PkiOperationValue.ObjectValue value, String field, int maximum, int maximumLength) {
            PkiOperationValue item = value.fields().get(field);
            if (item == null) {
                return List.of();
            }
            if (!(item instanceof PkiOperationValue.ListValue list)
                    || list.values().size() > maximum) {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
            }
            List<String> result = new ArrayList<>();
            for (PkiOperationValue element : list.values()) {
                if (!(element instanceof PkiOperationValue.Text text)
                        || text.value().length() > maximumLength) {
                    throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
                }
                result.add(text.value());
            }
            return List.copyOf(result);
        }

        private static List<AcmeState.Identifier> identifiers(PkiOperationValue item) {
            if (!(item instanceof PkiOperationValue.ListValue list)
                    || list.values().isEmpty()
                    || list.values().size() > 64) {
                throw new AcmeJwsVerifier.AcmeProblem("rejectedIdentifier");
            }
            List<AcmeState.Identifier> result = new ArrayList<>();
            for (PkiOperationValue entry : list.values()) {
                PkiOperationValue.ObjectValue object = object(entry);
                requireOnly(object, "type", "value");
                if (!(object.fields().get("type") instanceof PkiOperationValue.Text type)
                        || !"dns".equals(type.value())
                        || !(object.fields().get("value")
                                instanceof PkiOperationValue.Text value)) {
                    throw new AcmeJwsVerifier.AcmeProblem("rejectedIdentifier");
                }
                boolean wildcard = value.value().startsWith("*.");
                result.add(
                        new AcmeState.Identifier(
                                AcmeState.IdentifierType.DNS,
                                wildcard ? value.value().substring(2) : value.value(),
                                wildcard));
            }
            return List.copyOf(result);
        }

        // This transport boundary must preserve cleanup and finite masking of provider/runtime
        // failures. Untrusted
        // transport/parser failures retain the existing finite safe HTTP diagnostics.
        @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace"})
        private static Optional<Instant> optionalInstant(
                PkiOperationValue.ObjectValue value, String field) {
            PkiOperationValue item = value.fields().get(field);
            if (item == null) {
                return Optional.empty();
            }
            if (item instanceof PkiOperationValue.Text text) {
                try {
                    return Optional.of(Instant.parse(text.value()));
                } catch (RuntimeException invalid) {
                    throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
                }
            }
            throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
        }

        private static RevocationReason revocationReason(int code) {
            return switch (code) {
                case 0 -> RevocationReason.UNSPECIFIED;
                case 1 -> RevocationReason.KEY_COMPROMISE;
                case 2 -> RevocationReason.CA_COMPROMISE;
                case 3 -> RevocationReason.AFFILIATION_CHANGED;
                case 4 -> RevocationReason.SUPERSEDED;
                case BOUND_5 -> RevocationReason.CESSATION_OF_OPERATION;
                case 9 -> RevocationReason.PRIVILEGE_WITHDRAWN;
                case 10 -> RevocationReason.AA_COMPROMISE;
                default -> throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
            };
        }
    }

    /** Existing ACME JSON projection and resource-link spelling. */
    private final class JsonRepresentations {
        private String resourceUrl(AcmeState.Directory directory, String type, String id) {
            return configuration
                    .externalBaseUri()
                    .resolve(TEXT_ACME + directory.alias() + "/" + type + "/" + id)
                    .toASCIIString();
        }

        private String directoryJson(AcmeState.Directory value) {
            String base =
                    configuration
                            .externalBaseUri()
                            .resolve(TEXT_ACME + value.alias() + "/")
                            .toASCIIString();
            String document =
                    "{\"newNonce\":\""
                            + base
                            + "new-nonce\",\"newAccount\":\""
                            + base
                            + "new-account\",\"newOrder\":\""
                            + base
                            + "new-order\",\"revokeCert\":\""
                            + base
                            + "revoke-cert\",\"keyChange\":\""
                            + base
                            + "key-change\"";
            if (configuration.hybridSdk().isPresent() && service.hybridSdkAvailable(value)) {
                document +=
                        ",\"meta\":{\"zeroechoHybridSdk\":"
                                + new String(
                                        new AccountRoutes().sdkCapability(value),
                                        StandardCharsets.UTF_8)
                                + "}";
            }
            return document + "}";
        }

        private String accountJson(AcmeState.Account value) {
            return "{\"status\":\""
                    + value.status().name().toLowerCase(java.util.Locale.ROOT)
                    + TEXT_LITERAL_52D9;
        }

        private String orderJson(AcmeState.Order value, AcmeState.Directory directory) {
            StringBuilder out =
                    new StringBuilder(256)
                            .append("{\"status\":\"")
                            .append(value.status().name().toLowerCase(java.util.Locale.ROOT))
                            .append("\",\"identifiers\":[");
            for (int index = 0; index < value.identifiers().size(); index++) {
                if (index != 0) {
                    out.append(',');
                }
                AcmeState.Identifier identifier = value.identifiers().get(index);
                out.append("{\"type\":\"dns\",\"value\":\"")
                        .append(escape(identifier.presentation()))
                        .append(TEXT_LITERAL_52D9);
            }
            out.append("],\"authorizations\":[");
            appendUrls(out, value.authorizationIds(), base(directory) + "authz/");
            out.append("],\"finalize\":\"")
                    .append(base(directory))
                    .append("finalize/")
                    .append(value.orderId())
                    .append('"');
            value.credentialId()
                    .ifPresent(
                            ignored ->
                                    out.append(",\"certificate\":\"")
                                            .append(base(directory))
                                            .append("certificate/")
                                            .append(value.orderId())
                                            .append('"'));
            if (requiresCredentialConfirmation(value)) {
                String confirmationBase = base(directory) + "credential-confirmation/v1/";
                out.append(",\"credentialConfirmation\":{\"version\":1,\"challenge\":\"")
                        .append(confirmationBase)
                        .append("challenge/")
                        .append(value.orderId())
                        .append("\",\"complete\":\"")
                        .append(confirmationBase)
                        .append("complete/")
                        .append(value.orderId())
                        .append(TEXT_LITERAL_52D9);
            }
            return out.append('}').toString();
        }

        private boolean requiresCredentialConfirmation(AcmeState.Order order) {
            if (order.status() != AcmeState.OrderStatus.VALID || order.credentialId().isEmpty()) {
                return false;
            }
            CredentialConfirmationLifecycle lifecycle =
                    realm.session()
                            .confirmations()
                            .get(order.credentialId().orElseThrow())
                            .orElseThrow(
                                    () ->
                                            new IllegalStateException(
                                                    "ACME credential confirmation is unavailable"));
            return lifecycle.state() == CredentialConfirmationLifecycle.State.PENDING;
        }

        private static String confirmationChallengeJson(
                CredentialConfirmationProofChallenge challenge) {
            byte[] presentation = challenge.presentation();
            try {
                return "{\"version\":1,\"expectedLifecycleRevision\":"
                        + challenge.proofCas().expectedLifecycleRevision()
                        + ",\"expectedLifecycleRecordCommitment\":\""
                        + challenge.proofCas().expectedLifecycleRecordCommitment()
                        + "\",\"expectedChallengeRecordCommitment\":\""
                        + challenge.proofCas().expectedChallengeRecordCommitment()
                        + "\",\"proofSuiteId\":\""
                        + challenge.proofSuiteBinding().proofSuiteRef().suiteId()
                        + "\",\"proofSuiteConfigurationCommitment\":\""
                        + challenge.proofSuiteBinding().proofSuiteRef().configurationCommitment()
                        + "\",\"rsaMaximumModulusBits\":"
                        + challenge.proofSuiteBinding().rsaMaximumModulusBits()
                        + ",\"expiresAt\":\""
                        + challenge.expiresAt()
                        + "\",\"maximumResponseBytes\":"
                        + challenge.maximumResponseBytes()
                        + ",\"presentation\":\""
                        + Base64.getUrlEncoder().withoutPadding().encodeToString(presentation)
                        + TEXT_LITERAL_52D9;
            } finally {
                java.util.Arrays.fill(presentation, (byte) 0);
            }
        }

        private String authorizationJson(
                AcmeState.Authorization value, AcmeState.Directory directory) {
            StringBuilder out =
                    new StringBuilder(128)
                            .append("{\"identifier\":{\"type\":\"dns\",\"value\":\"")
                            .append(escape(value.identifier().value()))
                            .append("\"},\"status\":\"")
                            .append(value.status().name().toLowerCase(java.util.Locale.ROOT))
                            .append('"');
            if (value.identifier().wildcard()) {
                out.append(",\"wildcard\":true");
            }
            out.append(",\"challenges\":[");
            appendUrls(out, value.challengeIds(), base(directory) + "challenge/");
            return out.append("]}").toString();
        }

        private String challengeJson(AcmeState.Challenge value, AcmeState.Directory directory) {
            return "{\"type\":\""
                    + challengeType(value.type())
                    + "\",\"url\":\""
                    + base(directory)
                    + "challenge/"
                    + value.challengeId()
                    + "\",\"status\":\""
                    + value.status().name().toLowerCase(java.util.Locale.ROOT)
                    + "\",\"token\":\""
                    + value.token()
                    + TEXT_LITERAL_52D9;
        }

        private String base(AcmeState.Directory value) {
            return configuration
                    .externalBaseUri()
                    .resolve(TEXT_ACME + value.alias() + "/")
                    .toASCIIString();
        }

        private static void appendUrls(StringBuilder out, List<String> ids, String prefix) {
            for (int index = 0; index < ids.size(); index++) {
                if (index != 0) {
                    out.append(',');
                }
                out.append('"').append(prefix).append(ids.get(index)).append('"');
            }
        }

        private static String challengeType(AcmeState.ChallengeType type) {
            return type == AcmeState.ChallengeType.HTTP_01 ? "http-01" : "dns-01";
        }
    }

    /** Verified account-bound protocol operations. */
    private final class AccountRoutes {
        private Response newAccount(
                AcmeState.Directory directory, AcmeJwsVerifier.Verified verified) {
            PkiOperationValue.ObjectValue payload =
                    FieldValues.object(StrictJson.parse(verified.payload(), 65_536));
            FieldValues.requireOnly(
                    payload,
                    "onlyReturnExisting",
                    TEXT_CONTACT,
                    "termsOfServiceAgreed",
                    "externalAccountBinding");
            boolean onlyExisting = FieldValues.bool(payload, "onlyReturnExisting", false);
            boolean terms = FieldValues.bool(payload, "termsOfServiceAgreed", false);
            List<String> contacts = FieldValues.textList(payload, TEXT_CONTACT, 16, 512);
            Optional<byte[]> eabDocument =
                    Optional.ofNullable(payload.fields().get("externalAccountBinding"))
                            .map(StrictJson::encode);
            if (!rates.admitAccount(directory.directoryId())) {
                return problem(429, TEXT_RATELIMITED);
            }
            Optional<String> eab =
                    service.verifyExternalAccountBinding(
                            directory, verified.keyThumbprint(), eabDocument);
            boolean existing =
                    service.accountByKey(directory.directoryId(), verified.keyThumbprint())
                            .isPresent();
            AcmeState.Account account =
                    service.createAccount(
                            directory,
                            verified.keyThumbprint(),
                            verified.publicKey().getEncoded(),
                            contacts,
                            terms,
                            eab,
                            onlyExisting);
            return json(
                    existing ? 200 : 201,
                    new JsonRepresentations().accountJson(account),
                    directory.directoryId(),
                    Map.of(
                            "Location",
                            new JsonRepresentations()
                                    .resourceUrl(directory, "account", account.accountId())));
        }

        private Response newOrder(
                AcmeState.Directory directory, AcmeJwsVerifier.AccountKey account, byte[] raw) {
            PkiOperationValue.ObjectValue payload =
                    FieldValues.object(StrictJson.parse(raw, 65_536));
            FieldValues.requireOnly(payload, "identifiers", "notBefore", "notAfter");
            List<AcmeState.Identifier> identifiers =
                    FieldValues.identifiers(payload.fields().get("identifiers"));
            Optional<Instant> notBefore = FieldValues.optionalInstant(payload, "notBefore");
            Optional<Instant> notAfter = FieldValues.optionalInstant(payload, "notAfter");
            if (notBefore.isPresent() != notAfter.isPresent()) {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
            }
            if (service.pendingOrderCount(
                            account.accountId(), configuration.maximumPendingOrdersPerAccount())
                    >= configuration.maximumPendingOrdersPerAccount()) {
                return problem(429, TEXT_RATELIMITED);
            }
            if (!rates.admitOrder(account.accountId())) {
                return problem(429, TEXT_RATELIMITED);
            }
            AcmeState.Order order =
                    service.createOrder(
                            account.accountId(),
                            account.recordCommitment(),
                            directory,
                            identifiers,
                            notBefore,
                            notAfter,
                            Duration.ofHours(24));
            return json(
                    201,
                    new JsonRepresentations().orderJson(order, directory),
                    directory.directoryId(),
                    Map.of(
                            "Location",
                            new JsonRepresentations()
                                    .resourceUrl(directory, "order", order.orderId())));
        }

        private Response account(
                AcmeJwsVerifier.AccountKey authenticated,
                String id,
                byte[] payload,
                AcmeState.Directory directory) {
            if (!authenticated.accountId().equals(id)) {
                return problem(404, TEXT_ACCOUNTDOESNOTEXIST);
            }
            PkiOperationValue.ObjectValue value = FieldValues.objectOrEmpty(payload);
            FieldValues.requireOnly(value, "status", TEXT_CONTACT);
            if (value.fields().containsKey("status") && value.fields().containsKey(TEXT_CONTACT)) {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
            }
            AcmeState.Account account = service.account(id);
            if (value.fields().get("status") instanceof PkiOperationValue.Text status) {
                if (!"deactivated".equals(status.value())) {
                    throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
                }
                account = service.deactivateAccount(id, authenticated.recordCommitment());
            }
            if (value.fields().containsKey(TEXT_CONTACT)) {
                account =
                        service.updateAccountContacts(
                                id,
                                authenticated.recordCommitment(),
                                FieldValues.textList(value, TEXT_CONTACT, 16, 512));
            }
            return json(
                    200, new JsonRepresentations().accountJson(account), directory.directoryId());
        }

        private Response order(
                AcmeJwsVerifier.AccountKey account,
                String id,
                byte[] payload,
                AcmeState.Directory directory,
                ServerRuntime.CancellationToken cancellation) {
            FieldValues.requirePostAsGet(payload);
            return json(
                    200,
                    new JsonRepresentations()
                            .orderJson(
                                    service.order(
                                            account.accountId(),
                                            account.recordCommitment(),
                                            id,
                                            cancellation),
                                    directory),
                    directory.directoryId());
        }

        private Response authorization(
                String accountId, String id, byte[] payload, AcmeState.Directory directory) {
            FieldValues.requirePostAsGet(payload);
            AcmeState.Authorization value = service.authorization(accountId, id);
            return json(
                    200,
                    new JsonRepresentations().authorizationJson(value, directory),
                    directory.directoryId());
        }

        private Response challenge(
                AcmeJwsVerifier.AccountKey account,
                String id,
                byte[] payload,
                AcmeState.Directory directory,
                ServerRuntime.CancellationToken cancellation,
                Instant requestDeadline)
                throws IOException, InterruptedException, ExecutionException {
            FieldValues.objectOrEmpty(payload);
            if (!rates.admitValidation(account.accountId())) {
                return problem(429, TEXT_RATELIMITED);
            }
            if (!validations.tryAdmit()) {
                return problem(429, TEXT_RATELIMITED);
            }
            Future<AcmeState.Challenge> future = null;
            try {
                future =
                        validations.submit(
                                () ->
                                        service.validateChallenge(
                                                account.accountId(),
                                                account.recordCommitment(),
                                                id,
                                                account.keyThumbprint(),
                                                requestDeadline,
                                                cancellation));
                AcmeState.Challenge value =
                        future.get(
                                configuration.execution().maximumDeadline().toMillis(),
                                TimeUnit.MILLISECONDS);
                return json(
                        200,
                        new JsonRepresentations().challengeJson(value, directory),
                        directory.directoryId());
            } catch (TimeoutException timeout) {
                if (future != null) {
                    future.cancel(true);
                }
                return problem(504, "connection");
            } finally {
                validations.release();
            }
        }

        private Response sdkAction(
                AcmeJwsVerifier.AccountKey account,
                AcmeState.Directory directory,
                String action,
                String orderId,
                byte[] payload,
                ServerRuntime.CancellationToken cancellation) {
            boolean acceptance = "accept".equals(action);
            Map<String, PkiOperationValue> fields =
                    HybridSdkHttpCodec.parse(
                            payload,
                            configuration.maximumBodyBytes(),
                            acceptance,
                            java.util.Set.of("csr"));
            byte[] csr =
                    HybridSdkHttpCodec.bytes(
                            fields,
                            "csr",
                            1,
                            zeroecho.pki.api.request.X509EnrollmentPayload.MAXIMUM_DER_BYTES);
            if (!rates.tryAcquireFinalization()) {
                return problem(429, TEXT_RATELIMITED);
            }
            try {
                String origin = configuration.hybridSdk().orElseThrow().canonicalOrigin();
                if (!acceptance) {
                    zeroecho.pki.server.enrollment.EnrollmentSdkAdmission.Challenge challenge =
                            service.challengeSdk(
                                    account.accountId(),
                                    account.recordCommitment(),
                                    orderId,
                                    csr,
                                    HybridSdkHttpCodec.bytes(fields, "clientNonce", 32, 32),
                                    origin);
                    return new Response(
                            200,
                            JSON,
                            HybridSdkHttpCodec.challenge(
                                    challenge.intentId(),
                                    challenge.primaryFrame(),
                                    challenge.targetFrame()),
                            Optional.empty(),
                            directory.directoryId(),
                            Map.of());
                }
                AcmeState.Order order =
                        service.acceptSdk(
                                account.accountId(),
                                account.recordCommitment(),
                                orderId,
                                csr,
                                HybridSdkHttpCodec.text(fields, "intentId"),
                                HybridSdkHttpCodec.text(fields, "sdkRequestId"),
                                HybridSdkHttpCodec.bytes(fields, "primaryProof", 1, 104),
                                HybridSdkHttpCodec.bytes(fields, "alternativeProof", 4_627, 4_627),
                                origin,
                                cancellation);
                return json(
                        200,
                        new JsonRepresentations().orderJson(order, directory),
                        directory.directoryId(),
                        Map.of(
                                "Location",
                                new JsonRepresentations()
                                        .resourceUrl(directory, "order", order.orderId())));
            } finally {
                java.util.Arrays.fill(csr, (byte) 0);
                rates.releaseFinalization();
            }
        }

        private byte[] sdkCapability(AcmeState.Directory directory) {
            String base =
                    configuration
                            .externalBaseUri()
                            .resolve(TEXT_ACME + directory.alias() + "/hybrid-sdk/v1")
                            .toASCIIString();
            byte[] encoded =
                    HybridSdkHttpCodec.capability(
                            base,
                            List.of("credential.issue"),
                            configuration.hybridSdk().orElseThrow().canonicalOrigin(),
                            configuration.maximumBodyBytes());
            PkiOperationValue.ObjectValue parsed =
                    (PkiOperationValue.ObjectValue)
                            StrictJson.parse(encoded, configuration.maximumBodyBytes());
            Map<String, PkiOperationValue> fields = new java.util.LinkedHashMap<>(parsed.fields());
            fields.put(TEXT_CHALLENGE, new PkiOperationValue.Text(base + "/challenge/{orderId}"));
            fields.put("accept", new PkiOperationValue.Text(base + "/accept/{orderId}"));
            return StrictJson.encode(new PkiOperationValue.ObjectValue(fields));
        }

        private Response finalizeOrder(
                AcmeJwsVerifier.AccountKey account,
                String id,
                byte[] payload,
                AcmeState.Directory directory,
                ServerRuntime.CancellationToken cancellation) {
            byte[] csr =
                    AcmePayloads.requiredBase64Url(
                            payload, "csr", configuration.maximumBodyBytes());
            if (!rates.tryAcquireFinalization()) {
                java.util.Arrays.fill(csr, (byte) 0);
                return problem(429, TEXT_RATELIMITED);
            }
            try {
                TransportCancellationGateway.finalizeAcme(
                        service,
                        account.accountId(),
                        account.recordCommitment(),
                        id,
                        csr,
                        cancellation);
            } finally {
                java.util.Arrays.fill(csr, (byte) 0);
                rates.releaseFinalization();
            }
            return json(
                    200,
                    new JsonRepresentations()
                            .orderJson(
                                    service.order(
                                            account.accountId(),
                                            account.recordCommitment(),
                                            id,
                                            cancellation),
                                    directory),
                    directory.directoryId());
        }

        private Response certificate(
                AcmeJwsVerifier.AccountKey account,
                String id,
                byte[] payload,
                AcmeState.Directory directory,
                ServerRuntime.CancellationToken cancellation,
                Instant requestDeadline) {
            FieldValues.requirePostAsGet(payload);
            AcmeState.Order order =
                    service.order(
                            account.accountId(), account.recordCommitment(), id, cancellation);
            if (order.status() != AcmeState.OrderStatus.VALID || order.credentialId().isEmpty()) {
                return problem(403, "orderNotReady");
            }
            return new Response(
                    200,
                    PEM_CHAIN,
                    new byte[0],
                    Optional.of(
                            output ->
                                    new AcmeCertificateStream(realm, clock)
                                            .writePemChain(
                                                    output, order, cancellation, requestDeadline)),
                    directory.directoryId(),
                    Map.of());
        }

        private Response credentialConfirmationChallenge(
                AcmeJwsVerifier.AccountKey account,
                String orderId,
                byte[] payload,
                AcmeState.Directory directory) {
            if (!java.util.Arrays.equals(payload, new byte[] {'{', '}'})) {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
            }
            CredentialConfirmationProofChallenge challenge =
                    service.issueCredentialConfirmationChallenge(
                            account.accountId(), account.recordCommitment(), orderId);
            return json(
                    200,
                    JsonRepresentations.confirmationChallengeJson(challenge),
                    directory.directoryId());
        }

        private Response credentialConfirmationComplete(
                AcmeJwsVerifier.AccountKey account,
                String orderId,
                byte[] payload,
                AcmeState.Directory directory) {
            PkiOperationValue.ObjectValue value =
                    FieldValues.object(StrictJson.parse(payload, configuration.maximumBodyBytes()));
            FieldValues.requireOnly(
                    value,
                    "expectedLifecycleRevision",
                    "expectedLifecycleRecordCommitment",
                    "expectedChallengeRecordCommitment",
                    "response");
            String encodedResponse = FieldValues.requiredText(value, "response");
            byte[] response = FieldValues.decodeProofResponse(encodedResponse);
            try {
                CredentialConfirmationProofResult result =
                        service.completeCredentialConfirmation(
                                account.accountId(),
                                account.recordCommitment(),
                                orderId,
                                FieldValues.requiredLong(value, "expectedLifecycleRevision"),
                                FieldValues.requiredText(
                                        value, "expectedLifecycleRecordCommitment"),
                                FieldValues.requiredText(
                                        value, "expectedChallengeRecordCommitment"),
                                response);
                return json(
                        200,
                        "{\"version\":1,\"confirmationResult\":\""
                                + result.name()
                                + TEXT_LITERAL_52D9,
                        directory.directoryId());
            } finally {
                java.util.Arrays.fill(response, (byte) 0);
            }
        }
    }

    /** Native route selection and account-directory binding. */
    private final class RequestRouting {
        private Response route(
                HttpExchange exchange,
                String requestId,
                ServerRuntime.CancellationToken cancellation,
                Instant requestDeadline)
                throws IOException, InterruptedException, ExecutionException {
            URI requestUri = exchange.getRequestURI();
            if (requestUri.getRawQuery() != null || requestUri.getRawFragment() != null) {
                return problem(400, TEXT_MALFORMED);
            }
            String[] parts = requestUri.getPath().split("/", -1);
            if (!nativePath(parts)) {
                return problem(404, TEXT_MALFORMED);
            }
            String resource = parts[3];
            boolean sdk = "hybrid-sdk".equals(resource);
            if (sdk) {
                Response preflight = sdkPreflight(exchange, requestUri, parts);
                if (preflight != null) {
                    return preflight;
                }
            }
            if (parts.length == RESOURCE_SEGMENTS
                    && "directory".equals(resource)
                    && "GET".equals(exchange.getRequestMethod())) {
                AcmeState.Directory directory = activeDirectory(parts[2]);
                return json(
                        200,
                        new JsonRepresentations().directoryJson(directory),
                        directory.directoryId());
            }
            if (parts.length == RESOURCE_SEGMENTS
                    && "new-nonce".equals(resource)
                    && ("GET".equals(exchange.getRequestMethod())
                            || "HEAD".equals(exchange.getRequestMethod()))) {
                service.nonceScope(parts[2]);
                return new Response(204, JSON, new byte[0], Optional.empty(), null, Map.of());
            }
            if (!"POST".equals(exchange.getRequestMethod())) {
                return problem(405, TEXT_MALFORMED);
            }
            if (!JOSE.equalsIgnoreCase(
                    baseContentType(exchange.getRequestHeaders().getFirst("Content-Type")))) {
                return problem(415, TEXT_MALFORMED);
            }
            byte[] body = readBody(exchange.getRequestBody(), configuration.maximumBodyBytes());
            URI exactUrl = configuration.externalBaseUri().resolve(requestUri.getRawPath());
            AcmeState.Directory directory =
                    resolveRequestDirectory(parts, resource, body, exactUrl);
            AcmeJwsVerifier.KeyMode mode =
                    "new-account".equals(resource)
                            ? AcmeJwsVerifier.KeyMode.JWK
                            : AcmeJwsVerifier.KeyMode.KID;
            AcmeJwsVerifier.Verified verified =
                    verifier.verify(
                            body,
                            configuration.maximumBodyBytes(),
                            exactUrl,
                            directory.alias(),
                            mode,
                            nonces,
                            kid -> accountKey(directory, kid));
            return new VerifiedActions()
                    .execute(
                            parts,
                            resource,
                            sdk,
                            directory,
                            verified,
                            cancellation,
                            requestDeadline,
                            requestId,
                            exactUrl);
        }

        // This transport boundary must preserve cleanup and finite masking of provider/runtime
        // failures. Untrusted
        // transport/parser failures retain the existing finite safe HTTP diagnostics.
        @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace"})
        private AcmeState.Directory activeDirectory(String alias) {
            try {
                return service.activeDirectory(alias);
            } catch (RuntimeException unavailable) {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
            }
        }

        private AcmeState.Directory resolveRequestDirectory(
                String[] parts, String resource, byte[] body, URI exactUrl) {
            AcmeState.Directory directory;
            if (parts.length == RESOURCE_SEGMENTS) {
                directory = shortDirectory(parts, resource, body, exactUrl);
            } else if (parts.length == BOUND_5) {
                directory =
                        switch (resource) {
                            case "account" -> service.accountDirectory(parts[4]);
                            case "order", "finalize", "certificate" ->
                                    service.orderDirectory(parts[4]);
                            case "authz" -> service.authorizationDirectory(parts[4]);
                            case TEXT_CHALLENGE -> service.challengeDirectory(parts[4]);
                            default -> throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
                        };
            } else if (orderExtension(parts, resource)) {
                directory = service.orderDirectory(parts[6]);
            } else {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
            }
            if (!directory.alias().equals(parts[2])) {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_ACCOUNTDOESNOTEXIST);
            }
            return directory;
        }

        private String accountIdFromKid(String alias, String kid) {
            String prefix =
                    configuration
                            .externalBaseUri()
                            .resolve(TEXT_ACME + alias + "/account/")
                            .toASCIIString();
            if (!kid.startsWith(prefix)) {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_ACCOUNTDOESNOTEXIST);
            }
            return kid.substring(prefix.length());
        }

        private AcmeJwsVerifier.AccountKey accountKey(AcmeState.Directory directory, String kid) {
            String prefix =
                    configuration
                            .externalBaseUri()
                            .resolve(TEXT_ACME + directory.alias() + "/account/")
                            .toASCIIString();
            if (!kid.startsWith(prefix)) {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_ACCOUNTDOESNOTEXIST);
            }
            return service.accountKey(kid.substring(prefix.length()), kid);
        }

        private void requireAccountDirectory(String accountId, AcmeState.Directory directory) {
            AcmeState.Account account = service.account(accountId);
            if (!account.directoryId().equals(directory.directoryId())
                    || account.status() != AcmeState.AccountStatus.VALID) {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_ACCOUNTDOESNOTEXIST);
            }
        }

        private static boolean nativePath(String... parts) {
            return parts.length >= 4 && "".equals(parts[0]) && "acme".equals(parts[1]);
        }

        private Response sdkPreflight(HttpExchange exchange, URI requestUri, String... parts) {

            if (configuration.hybridSdk().isEmpty()) {
                return problem(404, TEXT_MALFORMED);
            }
            if (!requestUri.getRawPath().equals(requestUri.getPath())
                    || parts.length < BOUND_5
                    || !"v1".equals(parts[4])) {
                return problem(404, TEXT_MALFORMED);
            }
            if (parts.length == BOUND_5) {
                if (!"GET".equals(exchange.getRequestMethod())) {
                    return problem(405, TEXT_MALFORMED);
                }
                AcmeState.Directory directory = activeDirectory(parts[2]);
                if (!service.hybridSdkAvailable(directory)) {
                    return problem(404, TEXT_MALFORMED);
                }
                return new Response(
                        200,
                        JSON,
                        new AccountRoutes().sdkCapability(directory),
                        Optional.empty(),
                        directory.directoryId(),
                        Map.of());
            }
            if (parts.length != 7
                    || !(TEXT_CHALLENGE.equals(parts[BOUND_5]) || "accept".equals(parts[BOUND_5]))
                    || parts[6].isEmpty()) {
                return problem(404, TEXT_MALFORMED);
            }
            return null;
        }

        private AcmeState.Directory shortDirectory(
                String[] parts, String resource, byte[] body, URI exactUrl) {
            if (parts.length == RESOURCE_SEGMENTS
                    && ("new-account".equals(resource) || "new-order".equals(resource))) {
                return activeDirectory(parts[2]);
            } else if (parts.length == RESOURCE_SEGMENTS
                    && ("key-change".equals(resource) || "revoke-cert".equals(resource))) {
                String kid =
                        verifier.kidRoutingHint(body, configuration.maximumBodyBytes(), exactUrl);
                return service.accountDirectory(accountIdFromKid(parts[2], kid));
            } else {
                throw new AcmeJwsVerifier.AcmeProblem(TEXT_MALFORMED);
            }
        }

        private static boolean orderExtension(String[] parts, String resource) {
            return (parts.length == 7
                            && "hybrid-sdk".equals(resource)
                            && "v1".equals(parts[4])
                            && (TEXT_CHALLENGE.equals(parts[BOUND_5])
                                    || "accept".equals(parts[BOUND_5])))
                    || (parts.length == 7
                            && "credential-confirmation".equals(resource)
                            && "v1".equals(parts[4])
                            && (TEXT_CHALLENGE.equals(parts[BOUND_5])
                                    || "complete".equals(parts[BOUND_5])));
        }
    }

    /** Dispatches already JWS-verified, directory-bound account actions. */
    private final class VerifiedActions {
        private Response execute(
                String[] parts,
                String resource,
                boolean sdk,
                AcmeState.Directory directory,
                AcmeJwsVerifier.Verified verified,
                ServerRuntime.CancellationToken cancellation,
                Instant requestDeadline,
                String requestId,
                URI exactUrl)
                throws IOException, InterruptedException, ExecutionException {
            if (parts.length == RESOURCE_SEGMENTS && "new-account".equals(resource)) {
                return new AccountRoutes().newAccount(directory, verified);
            }
            AcmeJwsVerifier.AccountKey account = verified.account().orElseThrow();
            new RequestRouting().requireAccountDirectory(account.accountId(), directory);
            if (sdk) {
                return new AccountRoutes()
                        .sdkAction(
                                account,
                                directory,
                                parts[BOUND_5],
                                parts[6],
                                verified.payload(),
                                cancellation);
            }
            if (parts.length == RESOURCE_SEGMENTS && "new-order".equals(resource)) {
                return new AccountRoutes().newOrder(directory, account, verified.payload());
            }
            Response mutation =
                    accountMutation(
                            parts, resource, verified, account, directory, exactUrl, requestId);
            if (mutation != null) {
                return mutation;
            }
            Response confirmation =
                    confirmationAction(parts, resource, account, verified, directory);
            if (confirmation != null) {
                return confirmation;
            }
            if (parts.length != BOUND_5) {
                return problem(404, TEXT_MALFORMED);
            }
            return switch (resource) {
                case "account" ->
                        new AccountRoutes()
                                .account(account, parts[4], verified.payload(), directory);
                case "order" ->
                        new AccountRoutes()
                                .order(
                                        account,
                                        parts[4],
                                        verified.payload(),
                                        directory,
                                        cancellation);
                case "authz" ->
                        new AccountRoutes()
                                .authorization(
                                        account.accountId(),
                                        parts[4],
                                        verified.payload(),
                                        directory);
                case TEXT_CHALLENGE ->
                        new AccountRoutes()
                                .challenge(
                                        account,
                                        parts[4],
                                        verified.payload(),
                                        directory,
                                        cancellation,
                                        requestDeadline);
                case "finalize" ->
                        new AccountRoutes()
                                .finalizeOrder(
                                        account,
                                        parts[4],
                                        verified.payload(),
                                        directory,
                                        cancellation);
                case "certificate" ->
                        new AccountRoutes()
                                .certificate(
                                        account,
                                        parts[4],
                                        verified.payload(),
                                        directory,
                                        cancellation,
                                        requestDeadline);
                default -> problem(404, TEXT_MALFORMED);
            };
        }

        private Response accountMutation(
                String[] parts,
                String resource,
                AcmeJwsVerifier.Verified verified,
                AcmeJwsVerifier.AccountKey account,
                AcmeState.Directory directory,
                URI exactUrl,
                String requestId) {
            if (parts.length == RESOURCE_SEGMENTS && "key-change".equals(resource)) {
                AcmeJwsVerifier.Verified replacement =
                        verifier.verifyKeyChange(
                                verified.payload(),
                                configuration.maximumBodyBytes(),
                                exactUrl,
                                account.kid(),
                                account.keyThumbprint());
                AcmeState.Account updated =
                        service.rolloverAccount(
                                account.accountId(),
                                account.recordCommitment(),
                                replacement.keyThumbprint(),
                                replacement.publicKey().getEncoded());
                return json(
                        200,
                        new JsonRepresentations().accountJson(updated),
                        directory.directoryId());
            }
            if (parts.length == RESOURCE_SEGMENTS && "revoke-cert".equals(resource)) {
                AcmePayloads.RevocationPayload revocation =
                        AcmePayloads.revocation(
                                verified.payload(), configuration.maximumBodyBytes());
                byte[] certificate = revocation.certificateDer();
                try {
                    service.revokeCertificate(
                            account.accountId(),
                            account.recordCommitment(),
                            directory,
                            certificate,
                            FieldValues.revocationReason(revocation.reasonCode()),
                            requestId);
                } finally {
                    java.util.Arrays.fill(certificate, (byte) 0);
                }
                return json(200, "{}", directory.directoryId());
            }
            return null;
        }

        private Response confirmationAction(
                String[] parts,
                String resource,
                AcmeJwsVerifier.AccountKey account,
                AcmeJwsVerifier.Verified verified,
                AcmeState.Directory directory) {
            if (parts.length == 7
                    && "credential-confirmation".equals(resource)
                    && "v1".equals(parts[4])) {

                return switch (parts[BOUND_5]) {
                    case TEXT_CHALLENGE ->
                            new AccountRoutes()
                                    .credentialConfirmationChallenge(
                                            account, parts[6], verified.payload(), directory);
                    case "complete" ->
                            new AccountRoutes()
                                    .credentialConfirmationComplete(
                                            account, parts[6], verified.payload(), directory);
                    default -> problem(404, TEXT_MALFORMED);
                };
            }
            return null;
        }
    }
}
