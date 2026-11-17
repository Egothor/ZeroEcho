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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.acme.AcmeState;

/**
 * Streams the exact retained certificate chain with the listener's existing
 * deadline/cancellation rules.
 */
final class AcmeCertificateStream {
    private static final int TRANSFER_BUFFER = 8_192;
    private final ServerRealmContext realm;
    private final Clock clock;
    /* default */ AcmeCertificateStream(ServerRealmContext realm, Clock clock) {
        this.realm = realm;
        this.clock = clock;
    }
    /* default */ void writePemChain(OutputStream output, AcmeState.Order order,
            ServerRuntime.CancellationToken cancellation, Instant deadline) throws IOException {
        writePem(output, order.credentialId().orElseThrow(), cancellation, deadline);
        IssuerChainPath path = realm.session().repository().chainPath(order.issuancePathId())
                .orElseThrow(() -> new IllegalStateException("ACME issuance path unavailable"));
        if (!path.pathCommitment().equals(order.issuancePathCommitment())) {
            throw new IllegalStateException("ACME issuance path changed");
        }
        for (PkiId credentialId : path.orderedCredentialIds()) {
            writePem(output, credentialId, cancellation, deadline);
        }
    }
    private void writePem(OutputStream output, PkiId credentialId,
            ServerRuntime.CancellationToken cancellation, Instant deadline) throws IOException {
        requireStreamActive(cancellation, deadline);
        output.write("-----BEGIN CERTIFICATE-----\n".getBytes(StandardCharsets.US_ASCII));
        try (PkiRepositoryContent content = realm.session().repository().openCredential(credentialId);
                InputStream input = content.openStream();
                OutputStream encoded = Base64.getMimeEncoder(64, new byte[] {'\n'}).wrap(new NonClosingOutput(output))) {
            byte[] buffer = new byte[TRANSFER_BUFFER];
            int count;
        while ((count = input.read(buffer)) >= 0) {
                requireStreamActive(cancellation, deadline);
                if (count != 0) {
                    encoded.write(buffer, 0, count);
                }
            }
        }
        output.write("\n-----END CERTIFICATE-----\n".getBytes(StandardCharsets.US_ASCII));
    }
    private void requireStreamActive(ServerRuntime.CancellationToken cancellation, Instant deadline)
            throws IOException {
        if (cancellation.isCancelled() || !clock.instant().isBefore(deadline)) {
            throw new IOException("ACME certificate stream cancelled");
        }
    }
    /**
     * An output-stream wrapper that flushes on close without closing the underlying stream.
     */
    private static final class NonClosingOutput extends java.io.FilterOutputStream {
        private NonClosingOutput(OutputStream output) { super(output); }
        /**
         * Flushes the borrowed destination without closing it.
         *
         * @throws IOException if flushing the destination fails
         */
        @Override public void close() throws IOException { flush(); }
    }
}
