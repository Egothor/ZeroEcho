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
import java.io.IOException;
import java.util.Map;
import zeroecho.pki.server.ServerRealmContext;

/**
 * Delivers administrative responses, clears response-body bytes and records capability delivery.
 */
final class AdminResponseDelivery {
    private static final String TEXT_SYSTEM = "system";
    private static final String TEXT_REQUEST = "request";
    private static final String TEXT_CONTENT_TYPE = "Content-Type";
    private final ServerRealmContext realm;
    /* default */ AdminResponseDelivery(ServerRealmContext realm) { this.realm = realm; }
    // The explicit exchange-finally keeps body erasure, audit and close-failure precedence unchanged.
    @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.UseTryWithResources"})
    /* default */ void send(HttpExchange exchange, String requestId, HttpResponses.Response response)
            throws IOException {
        byte[] body = response.body();
        exchange.getResponseHeaders().set(TEXT_CONTENT_TYPE, response.contentType());
        response.attachmentFileName().ifPresent(value -> exchange.getResponseHeaders().set("Content-Disposition","attachment; filename=\""+value+"\""));
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        if (response.oneTimeSensitive()) {
            exchange.getResponseHeaders().set("Pragma", "no-cache");
            exchange.getResponseHeaders().set("Referrer-Policy", "no-referrer");
        }
        exchange.getResponseHeaders().set(RequestIds.HEADER, requestId);
        response.statusLocation().ifPresent(value -> exchange.getResponseHeaders().set("Location", value));
        exchange.sendResponseHeaders(response.statusCode(), body.length);
        try (java.io.OutputStream output = exchange.getResponseBody()) {
            output.write(body);
            classifyCapabilityDelivery(response, true, requestId);
        } catch (IOException failure) {
            if (response.oneTimeSensitive()) {
                try {
                    classifyCapabilityDelivery(response, false, requestId);
                } catch (RuntimeException classificationFailure) {
                    failure.addSuppressed(classificationFailure);
                }
                realm.auditTransport("CAPABILITY_DELIVERY_UNKNOWN", TEXT_SYSTEM,
                        Map.of(TEXT_REQUEST, requestId, "classification", "CAPABILITY_DELIVERY_UNKNOWN"));
            }
            throw failure;
        } finally {
            java.util.Arrays.fill(body, (byte) 0);
            response.clearSensitiveBody();
            exchange.close();
        }
    }
    // Classification failures retain the original delivery-dependent propagation and audit sequence.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private void classifyCapabilityDelivery(HttpResponses.Response response, boolean delivered,
            String requestId) {
        try {
            response.capabilityId().ifPresent(value -> realm.disclosure().classifyDelivery(value, delivered));
        } catch (RuntimeException failure) {
            realm.auditTransport("CAPABILITY_DELIVERY_UNKNOWN", TEXT_SYSTEM,
                    Map.of(TEXT_REQUEST, requestId, "classification", "CAPABILITY_DELIVERY_UNKNOWN"));
            if (!delivered) { throw failure; }
        }
    }
}
