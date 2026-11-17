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

import java.util.Objects;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.application.OcspResponseService;
import zeroecho.pki.server.ServerOperationGateway;
import zeroecho.pki.server.acme.AcmeService;

/**
 * Package-internal boundary that preserves the exact transport cancellation signal.
 */
/* default */ final class TransportCancellationGateway {
    private TransportCancellationGateway() { }

    /**
     * Executes administrative admission with the exact transport cancellation signal.
     *
     * @param gateway realm-owned authorized operation gateway
     * @param request administrative request and trusted transport identity
     * @param cancellation exact transport cancellation signal
     * @return gateway execution, denial or approval-required outcome
     * @throws NullPointerException if any argument is null
     */
    /* default */ static ServerOperationGateway.Outcome executeAdmin(ServerOperationGateway gateway,
            ServerOperationGateway.Request request, CancellationSignal cancellation) {
        return Objects.requireNonNull(gateway, "gateway").execute(Objects.requireNonNull(request, "request"),
                Objects.requireNonNull(cancellation, "cancellation"));
    }

    /**
     * Finalizes the retained ACME order with the exact transport cancellation signal.
     *
     * @param service realm-owned ACME service
     * @param accountId authenticated account identity
     * @param accountCommitment exact observed account commitment
     * @param orderId retained order identity
     * @param csrDer supplied certificate-signing request DER
     * @param cancellation exact transport cancellation signal
     * @return authoritative order state after finalization admission
     * @throws NullPointerException if the service, CSR or cancellation signal is null
     */
    /* default */ static zeroecho.pki.server.acme.AcmeState.Order finalizeAcme(AcmeService service, String accountId,
            String accountCommitment,
            String orderId, byte[] csrDer, CancellationSignal cancellation) {
        return Objects.requireNonNull(service, "service").finalizeOrder(accountId, accountCommitment, orderId,
                Objects.requireNonNull(csrDer, "csrDer"), Objects.requireNonNull(cancellation, "cancellation"));
    }

    /**
     * Generates a native OCSP response with the exact transport cancellation signal.
     *
     * @param service realm-owned OCSP response service
     * @param command validated native OCSP query and responder selection
     * @param cancellation exact transport cancellation signal
     * @return native OCSP response
     * @throws NullPointerException if any argument is null
     */
    /* default */ static OcspResponseService.Response respondOcsp(OcspResponseService service,
            OcspResponseService.Command command, CancellationSignal cancellation) {
        return Objects.requireNonNull(service, "service").respond(Objects.requireNonNull(command, "command"),
                Objects.requireNonNull(cancellation, "cancellation"));
    }
    /**
     * Generates hybrid-SDK OCSP evidence with the exact transport cancellation signal.
     *
     * @param service realm-owned OCSP response service
     * @param command native OCSP query with SDK evidence binding
     * @param cancellation exact transport cancellation signal
     * @return complete SDK OCSP evidence
     * @throws NullPointerException if any argument is null
     */
    /* default */ static zeroecho.pki.api.hybrid.sdk.SdkOcspEvidence respondSdkOcsp(OcspResponseService service,
            OcspResponseService.SdkCommand command,CancellationSignal cancellation) {
        return Objects.requireNonNull(service,"service").respondSdk(Objects.requireNonNull(command,"command"),
                Objects.requireNonNull(cancellation,"cancellation"));
    }

}
