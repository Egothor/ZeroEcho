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

package zeroecho.pki.server.est;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.server.enrollment.EnrollmentCoordinator;

/**
 * Immutable EST server-key-generation status with deferred encrypted delivery.
 * Pending and terminal failures contain no body. A successful result owns no
 * live resource until the transport opens a delivery immediately before sending
 * response headers; discarded or timed-out worker results therefore hold no lease.
 * Delivery is reauthorized against the retained request and its expiry when opened.
 */
public final class EstServerKeygenResponse {
    private static final int SUCCESS_STATUS = 200;
    private final int status;
    private final Optional<Long> retry;
    private final EnrollmentCoordinator coordinator;
    private final EnrollmentCoordinator.Admission admission;
    private final String boundary;
    private final byte[] certificates;

    private EstServerKeygenResponse(int status, Optional<Long> retry, EnrollmentCoordinator coordinator,
            EnrollmentCoordinator.Admission admission, String boundary, byte[] certificates) {
        this.status = status; this.retry = retry; this.coordinator = coordinator;
        this.admission = admission; this.boundary = boundary; this.certificates = certificates.clone();
    }

    /* default */ static EstServerKeygenResponse pending(long retryAfterSeconds) {
        if (retryAfterSeconds <= 0) {
            throw new IllegalArgumentException("Invalid EST retry interval");
        }
        return new EstServerKeygenResponse(202, Optional.of(retryAfterSeconds), null, null, "", new byte[0]);
    }

    /* default */ static EstServerKeygenResponse terminal(int status) {
        if (status != 403 && status != 410 && status != 500) {
            throw new IllegalArgumentException("Invalid EST terminal status");
        }
        return new EstServerKeygenResponse(status, Optional.empty(), null, null, "", new byte[0]);
    }

    /* default */ static EstServerKeygenResponse issued(EnrollmentCoordinator coordinator, EnrollmentCoordinator.Admission admission,
            String artifactId, byte[] certificates) {
        if (!artifactId.matches("[0-9a-f]{64}") || certificates.length == 0) {
            throw new IllegalArgumentException("Invalid EST delivery");
        }
        return new EstServerKeygenResponse(200, Optional.empty(), Objects.requireNonNull(coordinator), Objects.requireNonNull(admission),
                "zeroecho-est-" + artifactId, certificates);
    }

    /** Returns the protocol outcome.
     * @return HTTP status: 200, 202, 403, 410 or 500
     */
    public int status() { return status; }
    /** Returns the polling delay.
     * @return retry delay in seconds, present exactly for 202
     */
    public Optional<Long> retryAfterSeconds() { return retry; }
    /** Returns the transport media type.
     * @return complete media type with deterministic boundary on success
     */
    public String contentType() { return status == 200 ? "multipart/mixed; boundary=\"" + boundary + "\"" : "text/plain"; }

    /**
     * Acquires delivery inside the transport's owned deadline execution and before HTTP headers.
     * The caller must close the returned body even when sending headers fails.
     * A lease pins ciphertext while expiry or shutdown proceeds.
     * @return independently owned, single-stream delivery lease
     * @throws IllegalStateException for a non-success result
     * @throws EstProtocolException with 410 for expired delivery or 503 for unavailable custody
     */
    public Body openDelivery() throws EstProtocolException {
        if (status != SUCCESS_STATUS) {
            throw new IllegalStateException("EST response has no delivery");
        }
        try { return new Body(coordinator.keygenDelivery(admission), boundary, certificates); }
        catch (IllegalStateException unavailable) {
            boolean expired;
            try {
                expired = coordinator.findKeygen(admission).filter(value -> value.state()
                        == zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.EXPIRED).isPresent();
            } catch (IllegalStateException fenced) {
                expired = false; // A fenced lookup cannot establish expiry; report unavailable custody.
            }
            throw new EstProtocolException(expired ? 410 : 503, expired ? "EST key delivery expired" : "EST key delivery unavailable"); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    /** @return status only, without request or artifact data */
    @Override public String toString() { return "EstServerKeygenResponse[status=" + status + "]"; }

    /**
     * Thread-confined encrypted multipart delivery. Writing uses a fixed 64 KiB
     * transfer buffer plus base64 encoding state. Close releases custody and is
     * idempotent; it never deletes the retained artifact or acknowledges receipt.
     */
    public static final class Body implements AutoCloseable { // NOPMD ShortClassName - Preserves the public delivery-body type's source and binary compatibility.
        private final EnrollmentCoordinator.KeygenDelivery delivery;
        private final String boundary;
        private final byte[] certificates;
        private boolean closed;
        private boolean written;

        private Body(EnrollmentCoordinator.KeygenDelivery delivery, String boundary, byte[] certificates) {
            this.delivery = delivery; this.boundary = boundary; this.certificates = certificates;
        }

        /**
         * Writes one complete base64 multipart response without closing the caller's
         * stream. Ciphertext is streamed from the leased durable artifact.
         * @param output caller-owned HTTP response stream
         * @param cancellation checked before and during delivery
         * @throws IOException if ciphertext or transport I/O fails
         * @throws IllegalStateException if closed or already written
         */
        public void writeTo(OutputStream output, CancellationSignal cancellation) throws IOException {
            Objects.requireNonNull(output, "output"); Objects.requireNonNull(cancellation, "cancellation");
            if (closed || written) {
                throw new IllegalStateException("EST delivery is unavailable");
            }
            written = true;
            cancellation.throwIfCancelled();
            ascii(output, "--" + boundary + "\r\nContent-Type: application/pkcs7-mime; smime-type=server-generated-key\r\n"
                    + "Content-Transfer-Encoding: base64\r\n\r\n");
            try (InputStream input = delivery.openStream(); OutputStream encoded = Base64.getMimeEncoder(76,
                    new byte[] {'\r', '\n'}).wrap(new FilterOutputStream(output) {
                        @Override public void close() throws IOException { flush(); }
                    })) {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    cancellation.throwIfCancelled();
                    encoded.write(buffer, 0, read);
                }
            }
            cancellation.throwIfCancelled();
            ascii(output, "\r\n--" + boundary + "\r\nContent-Type: application/pkcs7-mime; smime-type=certs-only\r\n"
                    + "Content-Transfer-Encoding: base64\r\n\r\n");
            output.write(certificates);
            ascii(output, "\r\n--" + boundary + "--\r\n");
        }

        /** Releases the ciphertext lease; safe to call repeatedly. */
        @Override public void close() throws IOException {
            if (!closed) { delivery.close(); closed = true; }
        }

        private static void ascii(OutputStream output, String text) throws IOException {
            output.write(text.getBytes(StandardCharsets.US_ASCII));
        }
    }
}
