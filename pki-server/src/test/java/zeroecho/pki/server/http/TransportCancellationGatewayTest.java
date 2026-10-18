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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.jupiter.api.Test;

import zeroecho.pki.application.OcspResponseService;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.server.ServerOperationGateway;
import zeroecho.pki.server.acme.AcmeService;

final class TransportCancellationGatewayTest {
    @Test
    void preservesOneRuntimeTokenAcrossEverySigningTransportBoundary() {
        ServerRuntime.CancellationToken cancellation = new ServerRuntime.CancellationToken();
        ServerOperationGateway admin = mock(ServerOperationGateway.class);
        ServerOperationGateway.Request request = mock(ServerOperationGateway.Request.class);
        ServerOperationGateway.Outcome adminOutcome = new ServerOperationGateway.Outcome.Executed(
                new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())));
        when(admin.execute(request, cancellation)).thenReturn(adminOutcome);
        AcmeService acme = mock(AcmeService.class);
        zeroecho.pki.server.acme.AcmeState.Order order =
                mock(zeroecho.pki.server.acme.AcmeState.Order.class);
        byte[] csr = { 1, 2, 3 };
        when(acme.finalizeOrder("account", "commitment", "order", csr, cancellation)).thenReturn(order);
        OcspResponseService ocsp = mock(OcspResponseService.class);
        OcspResponseService.Command command = mock(OcspResponseService.Command.class);
        OcspResponseService.Response response = mock(OcspResponseService.Response.class);
        when(ocsp.respond(command, cancellation)).thenReturn(response);

        assertEquals(adminOutcome, TransportCancellationGateway.executeAdmin(admin, request, cancellation));
        assertEquals(order, TransportCancellationGateway.finalizeAcme(acme, "account", "commitment", "order",
                csr, cancellation));
        assertEquals(response, TransportCancellationGateway.respondOcsp(ocsp, command, cancellation));

        verify(admin).execute(request, cancellation);
        verify(acme).finalizeOrder("account", "commitment", "order", csr, cancellation);
        verify(ocsp).respond(command, cancellation);
    }
}
