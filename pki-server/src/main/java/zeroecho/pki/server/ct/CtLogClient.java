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

import java.time.Instant;
import java.util.List;

import zeroecho.pkix.ct.SignedCertificateTimestamp;

/**
 * Client for a single Certificate Transparency log endpoint.
 *
 * <p>Implementations submit pre-certificates to their configured CT log endpoint and
 * return the resulting SCT. Submission is blocking within the caller-supplied deadline;
 * the implementation is responsible for retrying transient failures within that window.</p>
 *
 * <h2>Thread safety</h2>
 * <p>Implementations must be thread-safe; concurrent {@link #submit} calls are allowed.</p>
 *
 * @since 1.0
 */
public interface CtLogClient extends AutoCloseable {

    /**
     * Returns the stable CT log identifier (64-character hex SHA-256 of the log's public key).
     *
     * @return hex log ID
     */
    String logId();

    /**
     * Submits a pre-certificate and its issuer chain to the CT log and blocks until an SCT
     * is received or the deadline elapses.
     *
     * @param preCert  DER-encoded pre-certificate; must not be {@code null}
     * @param chain    DER-encoded issuer chain, issuer certificate first; must not be {@code null}
     * @param deadline latest time by which the submission must complete; must not be {@code null}
     * @return the SCT received from the log
     * @throws CtSubmissionException if the submission fails, times out, or the response is invalid
     * @throws NullPointerException  if any argument is {@code null}
     */
    SignedCertificateTimestamp submit(byte[] preCert, List<byte[]> chain, Instant deadline)
            throws CtSubmissionException;

    /**
     * Releases resources held by this client (e.g., the underlying HTTP connection pool).
     *
     * <p>After {@code close()}, calls to {@link #submit} throw {@link IllegalStateException}.
     * Closing an already-closed client is a no-op.</p>
     */
    @Override
    void close();
}
