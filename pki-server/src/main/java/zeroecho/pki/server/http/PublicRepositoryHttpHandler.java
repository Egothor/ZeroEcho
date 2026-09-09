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
package zeroecho.pki.server.http;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;

import javax.net.ssl.SSLPeerUnverifiedException;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsExchange;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.AdministrativeAuthenticationMode;
import zeroecho.pki.server.PublicRepositoryGateway;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.SecurityPrincipal;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationResult;

/** Exact read-only HTTP adapter for the isolated public repository namespace. */
@SuppressWarnings("PMD")
final class PublicRepositoryHttpHandler implements HttpHandler {
    private static final int BUFFER_SIZE = 16_384;
    private static final String JSON = "application/json; charset=utf-8";
    private final PkiServerConfiguration.PublicListener configuration;
    private final ServerRealmContext realm;
    private final AdministrativeAuthenticator authenticator;
    private final ServerRuntime runtime;
    private final Clock clock;
    private final RequestIds requestIds;
    private final BooleanSupplier ready;

    PublicRepositoryHttpHandler(PkiServerConfiguration.PublicListener configuration,
            ServerRealmContext realm, AdministrativeAuthenticator authenticator, ServerRuntime runtime,
            Clock clock, RequestIds requestIds, BooleanSupplier ready) {
        this.configuration = java.util.Objects.requireNonNull(configuration);
        this.realm = java.util.Objects.requireNonNull(realm);
        this.authenticator = java.util.Objects.requireNonNull(authenticator);
        this.runtime = java.util.Objects.requireNonNull(runtime);
        this.clock = java.util.Objects.requireNonNull(clock);
        this.requestIds = java.util.Objects.requireNonNull(requestIds);
        this.ready = java.util.Objects.requireNonNull(ready);
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String requestId = "unavailable-request";
        String auditPrincipal = "anonymous";
        boolean admitted = false;
        try {
            requireHeadersBounded(exchange.getRequestHeaders());
            requireNoBody(exchange.getRequestHeaders());
            requestId = requestIds.resolve(exchange.getRequestHeaders().get(RequestIds.HEADER));
            if (!ready.getAsBoolean()) {
                sendFailure(exchange, requestId, 503, "NOT_READY");
                return;
            }
            URI uri = exchange.getRequestURI();
            if (uri.getRawFragment() != null || uri.getRawPath().indexOf('%') >= 0) {
                sendFailure(exchange, requestId, 400, "MALFORMED_REQUEST");
                return;
            }
            if (!runtime.tryAdmit()) {
                realm.auditTransport("PUBLIC_OVERLOAD", "anonymous",
                        Map.of("request", requestId, "classification", "ADMISSION_REJECTED"));
                sendFailure(exchange, requestId, 429, "ADMISSION_REJECTED");
                return;
            }
            admitted = true;
            Identity identity = authenticate(exchange, requestId);
            if (!identity.accepted()) {
                sendFailure(exchange, requestId, 401, "PUBLIC_AUTHENTICATION_FAILED");
                return;
            }
            PublicRepositoryGateway.Access access = access(exchange.getRequestHeaders(), identity, requestId);
            auditPrincipal = access.principal().map(SecurityPrincipal::principalId)
                    .orElseGet(() -> access.capabilityBearer().isPresent() ? "capability" : "anonymous");
            Instant deadline = clock.instant().plus(configuration.maximumStreamDuration());
            execute(exchange, uri, requestId, access, deadline);
            realm.auditTransport("PUBLIC_RETRIEVAL_COMPLETE", auditPrincipal,
                    Map.of("request", requestId, "classification", "COMPLETED"));
        } catch (AuthenticationFailure rejected) {
            realm.auditTransport("PUBLIC_AUTHENTICATION_DENIED", "anonymous",
                    Map.of("request", requestId, "classification", "DENIED"));
            sendFailure(exchange, requestId, 401, "PUBLIC_AUTHENTICATION_FAILED");
        } catch (MalformedRequest malformed) {
            sendFailure(exchange, requestId, 400, "MALFORMED_REQUEST");
        } catch (IllegalArgumentException unavailable) {
            realm.auditTransport("PUBLIC_RETRIEVAL_DENIED", auditPrincipal,
                    Map.of("request", requestId, "classification", "NOT_DISCLOSED"));
            sendFailure(exchange, requestId, 404, "RESOURCE_UNAVAILABLE");
        } catch (RuntimeException failure) {
            sendFailure(exchange, requestId, 500, "SAFE_INTERNAL_FAILURE");
        } finally {
            if (admitted) runtime.releaseAdmission();
            exchange.close();
        }
    }

    private static void requireNoBody(Headers headers) {
        if (headers.containsKey("Transfer-Encoding")) {
            throw new MalformedRequest();
        }
        List<String> contentLength = headers.get("Content-Length");
        if (contentLength != null && (contentLength.size() != 1 || !"0".equals(contentLength.get(0)))) {
            throw new MalformedRequest();
        }
    }

    private void execute(HttpExchange exchange, URI uri, String requestId,
            PublicRepositoryGateway.Access access, Instant deadline) throws IOException {
        ServerRuntime.Submitted<Void> submitted;
        java.util.concurrent.atomic.AtomicBoolean started = new java.util.concurrent.atomic.AtomicBoolean();
        try {
            submitted = runtime.submit(cancellation -> {
                started.set(true);
                cancellation.throwIfCancelled();
                if (!clock.instant().isBefore(deadline)) {
                    throw new StreamDeadlineExceeded();
                }
                route(exchange, uri, requestId, access, deadline);
                return null;
            });
        } catch (RejectedExecutionException overloaded) {
            sendFailure(exchange, requestId, 429, "PUBLIC_STREAM_QUEUE_FULL");
            return;
        }
        try {
            long remaining = Math.max(1L, java.time.Duration.between(clock.instant(), deadline).toMillis());
            submitted.future().get(remaining, TimeUnit.MILLISECONDS);
        } catch (TimeoutException timeout) {
            submitted.cancellation().cancel();
            submitted.future().cancel(true);
            if (!started.get()) {
                sendFailure(exchange, requestId, 504, "PUBLIC_STREAM_DEADLINE");
            }
        } catch (InterruptedException interrupted) {
            submitted.cancellation().cancel();
            submitted.future().cancel(true);
            Thread.currentThread().interrupt();
            if (!started.get()) {
                sendFailure(exchange, requestId, 504, "PUBLIC_STREAM_CANCELLED");
            }
        } catch (ExecutionException failure) {
            Throwable cause = failure.getCause();
            if (cause instanceof StreamDeadlineExceeded) {
                sendFailure(exchange, requestId, 504, "PUBLIC_STREAM_DEADLINE");
            } else if (cause instanceof IOException ioFailure) {
                throw ioFailure;
            } else if (cause instanceof RuntimeException runtimeFailure) {
                throw runtimeFailure;
            } else if (cause instanceof Error error) {
                throw error;
            } else {
                throw new IllegalStateException("Public repository execution failed");
            }
        } finally {
            submitted.finish();
        }
    }

    private void route(HttpExchange exchange, URI uri, String requestId,
            PublicRepositoryGateway.Access access, Instant deadline) throws IOException {
        boolean head = "HEAD".equals(exchange.getRequestMethod());
        if (!head && !"GET".equals(exchange.getRequestMethod())) {
            sendFailure(exchange, requestId, 405, "METHOD_NOT_ALLOWED");
            return;
        }
        String[] part = uri.getRawPath().split("/", -1);
        if (part.length == 4 && "".equals(part[0]) && "public".equals(part[1])
                && "v1".equals(part[2]) && "authorities".equals(part[3])) {
            if (!configuration.authorityListExposed()) throw unavailable();
            AuthorityPage page = authorityPage(uri.getRawQuery());
            authorities(exchange, requestId, head, page);
            return;
        }
        if (uri.getRawQuery() != null) throw new MalformedRequest();
        if (part.length == 5 && prefix(part, "authorities")) {
            authority(exchange, id(part[4]), requestId, head);
            return;
        }
        if (part.length == 8 && prefix(part, "authorities") && "issuers".equals(part[5])
                && "certificate".equals(part[7])) {
            content(exchange, realm.publicRepository().issuerCertificate(id(part[4]), id(part[6]), access),
                    requestId, head, false, deadline);
            return;
        }
        if (part.length == 9 && prefix(part, "authorities") && "issuers".equals(part[5])
                && "paths".equals(part[7])) {
            chain(exchange, realm.publicRepository().chainPath(id(part[4]), id(part[6]), id(part[8]), access),
                    requestId, head);
            return;
        }
        if (part.length == 6 && prefix(part, "authorities") && "chain".equals(part[5])) {
            chain(exchange, realm.publicRepository().currentChain(id(part[4]), access), requestId, head);
            return;
        }
        if (part.length == 6 && prefix(part, "authorities") && "crl".equals(part[5])) {
            content(exchange, realm.publicRepository().currentCrl(id(part[4]), access), requestId, head, true,
                    deadline);
            return;
        }
        if (part.length == 6 && prefix(part, "authorities") && "delta-crl".equals(part[5])) {
            content(exchange, realm.publicRepository().currentDeltaCrl(id(part[4]), access), requestId, head, true,
                    deadline);
            return;
        }
        if (part.length == 5 && "".equals(part[0]) && "public".equals(part[1])
                && "v1".equals(part[2]) && "certificates".equals(part[3])) {
            content(exchange, realm.publicRepository().credential(id(part[4]), access), requestId, head, false,
                    deadline);
            return;
        }
        if (part.length == 5 && "".equals(part[0]) && "public".equals(part[1])
                && "v1".equals(part[2]) && "status".equals(part[3])) {
            content(exchange, realm.publicRepository().statusObject(id(part[4]), access), requestId, head, false,
                    deadline);
            return;
        }
        throw unavailable();
    }

    private static boolean prefix(String[] part, String resource) {
        return "".equals(part[0]) && "public".equals(part[1]) && "v1".equals(part[2])
                && resource.equals(part[3]);
    }

    private void authorities(HttpExchange exchange, String requestId, boolean head, AuthorityPage page)
            throws IOException {
        List<PkiOperationValue> entries = realm.publicRepository().authorities(page.after(), page.limit()).stream()
                .map(PublicRepositoryHttpHandler::authorityValue).map(PkiOperationValue.class::cast).toList();
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("count", new PkiOperationValue.IntegerValue(entries.size()));
        fields.put("authorities", new PkiOperationValue.ListValue(entries));
        cache(exchange.getResponseHeaders(), PublicRepositoryGateway.CacheClass.PUBLIC_ALIAS);
        metadata(exchange, requestId, "repository.authority.list", new PkiOperationValue.ObjectValue(fields), head);
    }

    private void authority(HttpExchange exchange, PkiId authorityId, String requestId, boolean head)
            throws IOException {
        cache(exchange.getResponseHeaders(), PublicRepositoryGateway.CacheClass.PUBLIC_ALIAS);
        metadata(exchange, requestId, "repository.authority.inspect",
                authorityValue(realm.publicRepository().authority(authorityId)), head);
    }

    private static AuthorityPage authorityPage(String query) {
        if (query == null) return new AuthorityPage(Optional.empty(), 100);
        if (query.isEmpty() || query.length() > 1_024 || query.indexOf('%') >= 0) throw new MalformedRequest();
        Optional<PkiId> after = Optional.empty();
        int limit = 100;
        boolean foundAfter = false;
        boolean foundLimit = false;
        for (String field : query.split("&", -1)) {
            int separator = field.indexOf('=');
            if (separator <= 0 || separator != field.lastIndexOf('=')) throw new MalformedRequest();
            String name = field.substring(0, separator);
            String value = field.substring(separator + 1);
            if ("after".equals(name) && !foundAfter && !value.isEmpty()) {
                if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")) throw new MalformedRequest();
                after = Optional.of(new PkiId(value));
                foundAfter = true;
            } else if ("limit".equals(name) && !foundLimit && value.matches("[1-9][0-9]{0,3}")) {
                try { limit = Integer.parseInt(value); } catch (NumberFormatException failure) {
                    throw new MalformedRequest();
                }
                if (limit > 1_000) throw new MalformedRequest();
                foundLimit = true;
            } else {
                throw new MalformedRequest();
            }
        }
        return new AuthorityPage(after, limit);
    }

    private static PkiOperationValue.ObjectValue authorityValue(PublicRepositoryGateway.Authority value) {
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("authorityId", new PkiOperationValue.Text(value.authorityId().value()));
        fields.put("kind", new PkiOperationValue.Text(value.kind().name()));
        fields.put("currentIssuanceIssuerId", new PkiOperationValue.Text(
                value.currentIssuanceIssuerId().value()));
        fields.put("issuerIds", new PkiOperationValue.ListValue(value.issuerIds().stream()
                .map(PkiId::value).map(PkiOperationValue.Text::new).map(PkiOperationValue.class::cast).toList()));
        return new PkiOperationValue.ObjectValue(fields);
    }

    private void chain(HttpExchange exchange, PublicRepositoryGateway.Chain chain, String requestId,
            boolean head) throws IOException {
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put("authorityId", new PkiOperationValue.Text(chain.authorityId().value()));
        fields.put("issuerId", new PkiOperationValue.Text(chain.issuerId().value()));
        fields.put("pathId", new PkiOperationValue.Text(chain.pathId().value()));
        fields.put("pathCommitment", new PkiOperationValue.Text(chain.commitment()));
        fields.put("certificates", new PkiOperationValue.ListValue(chain.orderedCredentialIds().stream()
                .map(id -> "/public/v1/certificates/" + id.value()).map(PkiOperationValue.Text::new)
                .map(PkiOperationValue.class::cast).toList()));
        cache(exchange.getResponseHeaders(), chain.cacheClass());
        exchange.getResponseHeaders().set("ETag", chain.etag());
        if (notModified(exchange, chain.etag())) {
            exchange.sendResponseHeaders(304, -1);
            return;
        }
        metadata(exchange, requestId, "repository.chain.inspect", new PkiOperationValue.ObjectValue(fields), head);
    }

    private void metadata(HttpExchange exchange, String requestId, String operation,
            PkiOperationValue.ObjectValue value, boolean head) throws IOException {
        byte[] body = HttpResponses.success(requestId, operation, value).body();
        exchange.getResponseHeaders().set("Content-Type", JSON);
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set(RequestIds.HEADER, requestId);
        exchange.sendResponseHeaders(200, head ? -1 : body.length);
        if (!head) try (OutputStream output = exchange.getResponseBody()) { output.write(body); }
    }

    private void content(HttpExchange exchange, PublicRepositoryGateway.Content content, String requestId,
            boolean head, boolean alias, Instant deadline) throws IOException {
        try (content) {
            if (!accepts(exchange.getRequestHeaders(), content.mediaType())) {
                sendFailure(exchange, requestId, 406, "REPRESENTATION_NOT_ACCEPTABLE");
                return;
            }
            prevalidate(content.lease(), deadline);
            Headers headers = exchange.getResponseHeaders();
            headers.set("Content-Type", content.mediaType());
            headers.set("Content-Length", Long.toString(content.lease().length()));
            headers.set("ETag", content.etag());
            headers.set("X-Content-Type-Options", "nosniff");
            headers.set(RequestIds.HEADER, requestId);
            cache(headers, alias && content.cacheClass() == PublicRepositoryGateway.CacheClass.PUBLIC_IMMUTABLE
                    ? PublicRepositoryGateway.CacheClass.PUBLIC_ALIAS : content.cacheClass());
            if (notModified(exchange, content.etag())) {
                headers.remove("Content-Length");
                exchange.sendResponseHeaders(304, -1);
                return;
            }
            if (head) {
                exchange.sendResponseHeaders(200, -1);
                return;
            }
            exchange.sendResponseHeaders(200, content.lease().length());
            try (InputStream input = content.lease().openStream(); OutputStream output = exchange.getResponseBody()) {
                transfer(input, output, deadline);
            }
        }
    }

    private void prevalidate(zeroecho.pki.application.PkiRepositoryContent content, Instant deadline)
            throws IOException {
        try (InputStream input = content.openStream()) { transfer(input, OutputStream.nullOutputStream(), deadline); }
    }

    private void transfer(InputStream input, OutputStream output, Instant deadline) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        int read;
        while ((read = input.read(buffer)) >= 0) {
            if (!clock.instant().isBefore(deadline) || Thread.currentThread().isInterrupted()) {
                throw new IOException("Public repository stream deadline exceeded");
            }
            output.write(buffer, 0, read);
        }
    }

    private Identity authenticate(HttpExchange exchange, String requestId) {
        Map<String, List<String>> headers = authenticationHeaders(exchange.getRequestHeaders());
        boolean forwarded = ForwardedClientCertificateParser.containsForwardedIdentity(headers);
        AdministrativeAuthenticationMode mode = configuration.authentication().mode();
        if (mode == AdministrativeAuthenticationMode.DIRECT_MTLS && forwarded) return Identity.rejected();
        Optional<PkiServerAuthenticationContext> context = tlsContext(exchange, requestId, headers);
        if (mode == AdministrativeAuthenticationMode.DIRECT_MTLS) {
            if (context.isEmpty()) return Identity.anonymous();
            return identity(authenticator.authenticate(context.orElseThrow()));
        }
        if (context.isEmpty()) return Identity.rejected();
        if (!forwarded) return authenticator.authenticatePublicProxyTransport(context.orElseThrow())
                .map(transport -> new Identity(true, Optional.of(transport), Optional.empty()))
                .orElseGet(Identity::rejected);
        return identity(authenticator.authenticate(context.orElseThrow()));
    }

    private Identity identity(PkiServerAuthenticationResult result) {
        if (!(result instanceof PkiServerAuthenticationResult.Authenticated authenticated)) {
            return Identity.rejected();
        }
        return new Identity(true, authenticated.transportPrincipalId(),
                Optional.of(realm.principal(authenticated.endClientPrincipalId())));
    }

    private Optional<PkiServerAuthenticationContext> tlsContext(HttpExchange exchange, String requestId,
            Map<String, List<String>> headers) {
        if (!(exchange instanceof HttpsExchange https)) return Optional.empty();
        try {
            Certificate[] peer = https.getSSLSession().getPeerCertificates();
            List<X509Certificate> chain = new ArrayList<>();
            for (Certificate certificate : peer) {
                if (!(certificate instanceof X509Certificate x509)) return Optional.empty();
                chain.add(x509);
            }
            return Optional.of(new PkiServerAuthenticationContext(chain, https.getSSLSession().getProtocol(),
                    https.getSSLSession().getCipherSuite(), requestId, realm.configuration().realmId(), headers));
        } catch (SSLPeerUnverifiedException failure) {
            return Optional.empty();
        }
    }

    private PublicRepositoryGateway.Access access(Headers headers, Identity identity, String requestId) {
        List<String> values = headers.get("Authorization");
        if (headers.containsKey("Cookie")) throw new AuthenticationFailure();
        Optional<String> bearer = Optional.empty();
        if (values != null) {
            if (values.size() != 1 || !values.getFirst().matches("Bearer cap-[0-9a-f]{32}\\.[A-Za-z0-9_-]{43}")) {
                throw new AuthenticationFailure();
            }
            bearer = Optional.of(values.getFirst().substring("Bearer ".length()));
        }
        if (bearer.isPresent() && identity.principal().isPresent()) {
            throw new AuthenticationFailure();
        }
        return new PublicRepositoryGateway.Access(identity.principal(), bearer, requestId);
    }

    private Map<String, List<String>> authenticationHeaders(Headers headers) {
        java.util.Set<String> accepted = new java.util.TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        accepted.add(ForwardedClientCertificateParser.RFC_CERTIFICATE_HEADER);
        accepted.add(ForwardedClientCertificateParser.RFC_CHAIN_HEADER);
        accepted.add(ForwardedClientCertificateParser.DIRECT_REJECTED_NGINX_HEADER);
        configuration.authentication().forwardedCertificateHeaderName().ifPresent(accepted::add);
        configuration.authentication().forwardedCertificateChainHeaderName().ifPresent(accepted::add);
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (accepted.contains(entry.getKey())) result.put(entry.getKey(), List.copyOf(entry.getValue()));
        }
        return Map.copyOf(result);
    }

    private void requireHeadersBounded(Headers headers) {
        int total = 0;
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            total = Math.addExact(total, entry.getKey().getBytes(StandardCharsets.UTF_8).length);
            for (String value : entry.getValue()) {
                total = Math.addExact(total, value.getBytes(StandardCharsets.UTF_8).length);
                if (total > configuration.maximumHeaderBytes()) {
                    throw new IllegalArgumentException("Public request headers are oversized");
                }
            }
        }
    }

    private void cache(Headers headers, PublicRepositoryGateway.CacheClass value) {
        switch (value) {
            case PUBLIC_IMMUTABLE -> headers.set("Cache-Control", "public, max-age="
                    + configuration.publicImmutableCache().toSeconds() + ", immutable");
            case PUBLIC_ALIAS -> headers.set("Cache-Control", "public, max-age="
                    + configuration.publicAliasCache().toSeconds());
            case PRIVATE_AUTHENTICATED -> headers.set("Cache-Control", "private, no-store");
            case NO_STORE_CAPABILITY -> {
                headers.set("Cache-Control", "private, no-store");
                headers.set("Pragma", "no-cache");
                headers.set("Referrer-Policy", "no-referrer");
            }
        }
    }

    private static boolean accepts(Headers headers, String mediaType) {
        List<String> values = headers.get("Accept");
        return values == null || values.size() == 1 && ("*/*".equals(values.getFirst())
                || mediaType.equalsIgnoreCase(values.getFirst()));
    }

    private static boolean notModified(HttpExchange exchange, String etag) {
        List<String> values = exchange.getRequestHeaders().get("If-None-Match");
        return values != null && values.size() == 1 && etag.equals(values.getFirst());
    }

    private void sendFailure(HttpExchange exchange, String requestId, int status, String code) throws IOException {
        byte[] body = HttpResponses.failure(status, requestId, "public.repository", "REPOSITORY_FAILURE",
                code, code, false, false).body();
        exchange.getResponseHeaders().set("Content-Type", JSON);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set(RequestIds.HEADER, requestId);
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream output = exchange.getResponseBody()) { output.write(body); }
    }

    private static PkiId id(String value) {
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")) throw unavailable();
        return new PkiId(value);
    }

    private static IllegalArgumentException unavailable() {
        return new IllegalArgumentException("Public repository resource unavailable");
    }

    private static final class AuthenticationFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    private static final class MalformedRequest extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    private static final class StreamDeadlineExceeded extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    private record AuthorityPage(Optional<PkiId> after, int limit) { }

    private record Identity(boolean accepted, Optional<String> transportPrincipal,
            Optional<SecurityPrincipal> principal) {
        private static Identity anonymous() { return new Identity(true, Optional.empty(), Optional.empty()); }
        private static Identity rejected() { return new Identity(false, Optional.empty(), Optional.empty()); }
    }
}
