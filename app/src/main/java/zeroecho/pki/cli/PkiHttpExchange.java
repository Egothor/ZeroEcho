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
import java.util.Objects;
import java.util.Optional;
import java.time.Duration;

/**
 * Minimal request/response seam over the admin HTTP API.
 *
 * <p>Isolating the HTTP layer behind this interface keeps
 * {@link RemotePkiOperationTransport} free of JDK {@code HttpClient} details and
 * lets its protocol logic (envelope encoding, status interpretation, bounded-wait
 * polling, exit-code mapping) be unit-tested with a scripted in-memory exchange.</p>
 */
@FunctionalInterface
interface PkiHttpExchange extends AutoCloseable {

    /**
     * Sends one request against the configured base URL and returns its response.
     *
     * @param request method, path, and optional JSON body
     * @return decoded status, optional {@code Location} header, and body bytes
     * @throws IOException on connection, timeout, or TLS failure
     */
    Response send(Request request) throws IOException;

    @Override
    default void close() throws Exception {
        // No resource by default.
    }

    /** A bounded response violated the protocol before decoding. */
    final class InvalidResponseException extends IOException {
        private static final long serialVersionUID = 1L;
        /* default */ InvalidResponseException(String message) { super(message); }
    }

    /** Supported request methods. */
    enum Method {
        /** Retrieve a resource. */
        GET,
        /** Submit an operation envelope. */
        POST
    }

    /**
     * One admin-API request.
     *
     * @param method request method
     * @param path absolute request path, resolved against the base URL
     * @param body JSON request body for {@code POST}, empty for {@code GET}
     */
    record Request(Method method, String path, Optional<byte[]> body, Duration timeout) {
        /** Validates the request. */
        public Request {
            Objects.requireNonNull(method, "method");
            Objects.requireNonNull(timeout, "timeout");
            if (timeout.isZero() || timeout.isNegative()) { throw new IllegalArgumentException("timeout must be positive"); }
            if (path == null || path.isBlank()) {
                throw new IllegalArgumentException("path must not be blank");
            }
            Objects.requireNonNull(body, "body");
        }

        /**
         * Creates a body-less {@code GET} request.
         *
         * @param path absolute request path
         * @return the request
         */
        public static Request get(String path) {
            return new Request(Method.GET, path, Optional.empty(), Duration.ofSeconds(60));
        }

        /**
         * Creates a {@code POST} request with a JSON body.
         *
         * @param path absolute request path
         * @param body JSON body bytes
         * @return the request
         */
        public static Request post(String path, byte[] body) {
            return new Request(Method.POST, path, Optional.of(body.clone()), Duration.ofSeconds(60));
        }
    }

    /**
     * One admin-API response.
     *
     * @param statusCode HTTP status code
     * @param location value of the {@code Location} header, when present
     * @param body response body bytes (possibly empty, never {@code null})
     */
    record Response(int statusCode, Optional<String> location, byte[] body) {
        /** Validates the response. */
        public Response {
            Objects.requireNonNull(location, "location");
            body = Objects.requireNonNull(body, "body").clone();
        }

        @Override
        public byte[] body() {
            return body.clone();
        }
    }
}
