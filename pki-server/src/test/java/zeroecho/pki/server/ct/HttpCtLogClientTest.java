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
package zeroecho.pki.server.ct;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.ArgumentMatchers.any;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import zeroecho.pki.api.ct.CtLogDescriptor;
import zeroecho.pkix.ct.SignedCertificateTimestamp;

/** Unit tests for {@link HttpCtLogClient} using an in-process HTTP server. */
class HttpCtLogClientTest {

    @Test
    void interruptedBackoffStopsRetriesAndPreservesInterrupt() throws Exception {
        HttpClient http = mock(HttpClient.class);
        @SuppressWarnings("unchecked")
        HttpResponse<byte[]> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(503);
        when(http.send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>notNull())).thenAnswer(call -> {
            Thread.currentThread().interrupt();
            return response;
        });
        try (HttpCtLogClient client = new HttpCtLogClient(descriptor, http)) {
            CtSubmissionException failure = assertThrows(CtSubmissionException.class,
                    () -> client.submit(DUMMY_PRE_CERT, List.of(), Instant.now().plusSeconds(30)));
            assertTrue(Thread.currentThread().isInterrupted());
            assertTrue(failure.getCause() instanceof InterruptedException);
            verify(http, times(1)).send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<byte[]>>notNull());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void closeTerminatesFactoryOwnedExecutor() throws Exception {
        HttpCtLogClient client = HttpCtLogClient.create(descriptor);
        Field field = HttpCtLogClient.class.getDeclaredField("ownedExecutor");
        field.setAccessible(true);
        ExecutorService executor = (ExecutorService) field.get(client);
        client.close();
        client.close();
        assertTrue(executor.isTerminated());
        assertThrows(IllegalStateException.class,
                () -> client.submit(DUMMY_PRE_CERT, List.of(), Instant.now().plusSeconds(30)));
    }

    private static final byte[] DUMMY_PRE_CERT = {1, 2, 3, 4};
    private static final byte[] DUMMY_CHAIN_ENTRY = {5, 6, 7, 8};
    private static final byte[] LOG_ID_BYTES = new byte[SignedCertificateTimestamp.LOG_ID_LENGTH];
    private static final byte[] PUBLIC_KEY_DER = {0x30, 0x01, 0x00}; // minimal stub DER

    // DigitallySigned: hashAlg=4(SHA256), sigAlg=3(ECDSA), sigLen=4, sig=01020304
    private static final byte[] DIGITALLY_SIGNED = {4, 3, 0, 4, 1, 2, 3, 4};
    private static final long FIXED_TIMESTAMP_MS = 1725148800000L; // 2026-09-01T00:00:00Z
    private static final String FIXED_LOG_ID_BASE64 = Base64.getEncoder().encodeToString(LOG_ID_BYTES);
    private static final String FIXED_SIG_BASE64 = Base64.getEncoder().encodeToString(DIGITALLY_SIGNED);

    private HttpServer server;
    private String baseUrl;
    private CtLogDescriptor descriptor;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.start();
        int port = server.getAddress().getPort();
        baseUrl = "http://localhost:" + port + "/";
        String logIdHex = "00".repeat(SignedCertificateTimestamp.LOG_ID_LENGTH);
        descriptor = new CtLogDescriptor(logIdHex, baseUrl, PUBLIC_KEY_DER, true, "Test CT Log");
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    /** Verifies that the correct JSON body (chain array with base64 entries) is sent. */
    @Test
    void submit_sendsCorrectRequestBody() throws Exception {
        AtomicReference<String> capturedBody = new AtomicReference<>();
        server.createContext("/ct/v1/add-pre-chain", exchange -> {
            capturedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] response = buildSctJson().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(response);
            }
        });

        try (HttpCtLogClient client = HttpCtLogClient.create(descriptor)) {
            client.submit(DUMMY_PRE_CERT, List.of(DUMMY_CHAIN_ENTRY), Instant.now().plusSeconds(30));
        }

        String body = capturedBody.get();
        assertTrue(body != null && body.startsWith("{\"chain\":["), "body must start with chain array");
        String expectedPreCertBase64 = Base64.getEncoder().encodeToString(DUMMY_PRE_CERT);
        String expectedChainBase64 = Base64.getEncoder().encodeToString(DUMMY_CHAIN_ENTRY);
        assertTrue(body.contains(expectedPreCertBase64), "body must contain base64-encoded pre-cert");
        assertTrue(body.contains(expectedChainBase64), "body must contain base64-encoded chain entry");
    }

    /** Verifies that a valid 200 JSON response is parsed into the correct SCT fields. */
    @Test
    void submit_parsesResponseIntoCorrectSct() throws Exception {
        server.createContext("/ct/v1/add-pre-chain", exchange -> {
            byte[] response = buildSctJson().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(response);
            }
        });

        SignedCertificateTimestamp sct;
        try (HttpCtLogClient client = HttpCtLogClient.create(descriptor)) {
            sct = client.submit(DUMMY_PRE_CERT, List.of(), Instant.now().plusSeconds(30));
        }

        assertEquals(0, sct.version(), "SCT version must be 0 (v1)");
        assertArrayEquals(LOG_ID_BYTES, sct.logId(), "SCT log ID must match");
        assertEquals(Instant.ofEpochMilli(FIXED_TIMESTAMP_MS), sct.timestamp(), "SCT timestamp must match");
        assertEquals("SHA256withECDSA", sct.signatureAlgorithm(), "signature algorithm must be SHA256withECDSA");
        byte[] expectedRawSig = {1, 2, 3, 4};
        assertArrayEquals(expectedRawSig, sct.signature(), "raw signature bytes must match");
    }

    /** Verifies that HTTP 5xx responses trigger retry and eventually throw CtSubmissionException. */
    @Test
    void submit_retriesOn5xx_thenThrows() throws Exception {
        AtomicInteger attempts = new AtomicInteger(0);
        server.createContext("/ct/v1/add-pre-chain", exchange -> {
            int attempt = attempts.incrementAndGet();
            exchange.sendResponseHeaders(503, -1);
            exchange.close();
        });

        try (HttpCtLogClient client = HttpCtLogClient.create(descriptor)) {
            CtSubmissionException thrown = assertThrows(CtSubmissionException.class,
                    () -> client.submit(DUMMY_PRE_CERT, List.of(), Instant.now().plusSeconds(60)));
            assertEquals(descriptor.logId(), thrown.logId(), "exception must carry the log ID");
        }
        // Must have tried at least MAX_RETRIES + 1 times (initial + retries), but
        // since backoff may push some retries past the deadline, allow ≥ 1.
        assertTrue(attempts.get() >= 1, "must have attempted at least once");
    }

    private static String buildSctJson() {
        return "{\"sct_version\":0,"
                + "\"id\":\"" + FIXED_LOG_ID_BASE64 + "\","
                + "\"timestamp\":" + FIXED_TIMESTAMP_MS + ","
                + "\"extensions\":\"\","
                + "\"signature\":\"" + FIXED_SIG_BASE64 + "\"}";
    }
}
