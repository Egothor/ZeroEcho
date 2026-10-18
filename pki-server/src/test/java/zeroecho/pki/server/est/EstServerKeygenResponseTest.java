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

package zeroecho.pki.server.est;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.server.enrollment.EnrollmentCoordinator;

class EstServerKeygenResponseTest {
    @Test void lazyLeaseStreamsExactEncryptedMultipartAndClosesWithoutClosingCallerStream() throws Exception {
        EnrollmentCoordinator coordinator = mock(EnrollmentCoordinator.class);
        EnrollmentCoordinator.Admission admission = mock(EnrollmentCoordinator.Admission.class);
        EnrollmentCoordinator.KeygenDelivery lease = mock(EnrollmentCoordinator.KeygenDelivery.class);
        byte[] ciphertext = new byte[131_079];
        new java.util.Random(7).nextBytes(ciphertext);
        when(coordinator.keygenDelivery(admission)).thenReturn(lease);
        when(lease.openStream()).thenReturn(new ByteArrayInputStream(ciphertext));
        byte[] certificatePart = Base64.getEncoder().encode(new byte[] { 1, 2, 3 });
        EstServerKeygenResponse response = EstServerKeygenResponse.issued(coordinator, admission, "a".repeat(64), certificatePart);
        verify(coordinator, never()).keygenDelivery(admission);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (EstServerKeygenResponse.Body body = response.openDelivery()) {
            body.writeTo(output, CancellationSignal.NONE);
            assertThrows(IllegalStateException.class, () -> body.writeTo(output, CancellationSignal.NONE));
        }
        verify(lease).close();
        String wire = output.toString(StandardCharsets.US_ASCII);
        assertTrue(wire.contains("Content-Type: application/pkcs7-mime; smime-type=server-generated-key\r\n"));
        assertTrue(wire.contains("Content-Type: application/pkcs7-mime; smime-type=certs-only\r\n"));
        int content = wire.indexOf("\r\n\r\n") + 4;
        int end = wire.indexOf("\r\n--zeroecho-est-", content);
        assertArrayEquals(ciphertext, Base64.getMimeDecoder().decode(wire.substring(content, end)));
        assertTrue(wire.endsWith("--zeroecho-est-" + "a".repeat(64) + "--\r\n"));
        assertEquals(response.contentType(), EstServerKeygenResponse.issued(coordinator, admission, "a".repeat(64), certificatePart).contentType());
    }

    @Test void cancellationAndFailedTransportReleaseLeaseAndPendingNeverOpensOne() throws Exception {
        assertEquals(202, EstServerKeygenResponse.pending(5).status());
        assertEquals(5L, EstServerKeygenResponse.pending(5).retryAfterSeconds().orElseThrow());
        assertThrows(IllegalStateException.class, () -> EstServerKeygenResponse.pending(5).openDelivery());
        for (boolean cancel : new boolean[] {false, true}) {
            EnrollmentCoordinator coordinator = mock(EnrollmentCoordinator.class);
            EnrollmentCoordinator.Admission admission = mock(EnrollmentCoordinator.Admission.class);
            EnrollmentCoordinator.KeygenDelivery lease = mock(EnrollmentCoordinator.KeygenDelivery.class);
            when(coordinator.keygenDelivery(admission)).thenReturn(lease);
            when(lease.openStream()).thenReturn(new ByteArrayInputStream(new byte[100]));
            EstServerKeygenResponse response = EstServerKeygenResponse.issued(coordinator, admission, "b".repeat(64), new byte[] {65});
            OutputStream failed = new OutputStream() {
                @Override public void write(int value) throws IOException { throw new IOException("transport closed"); }
            };
            assertThrows(IOException.class, () -> {
                try (EstServerKeygenResponse.Body body = response.openDelivery()) { body.writeTo(failed, () -> cancel); }
            });
            verify(lease).close();
        }
    }
}

