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
package zeroecho.pki.server.ct;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import zeroecho.pkix.ct.SignedCertificateTimestamp;

/**
 * Unit tests for {@link SctVerifier}.
 *
 * <p>Cryptographic SCT signature verification requires a real CT log key pair and is
 * tested through integration tests. These unit tests cover the pre-verification filters:
 * future-timestamp rejection, unknown-log rejection, and minimum-SCT policy enforcement.</p>
 */
class SctVerifierTest {

    private static final byte[] DUMMY_PRE_CERT = new byte[]{0x30, 0x01, 0x00};

    private static SignedCertificateTimestamp sctWithTimestamp(byte[] logId, Instant timestamp) {
        return new SignedCertificateTimestamp(0, logId.clone(), timestamp, new byte[0],
                "SHA256withECDSA", new byte[]{0x30, 0x01, 0x00});
    }

    @Test
    void emptyInputWithZeroMinSctsReturnsEmpty() throws CtSubmissionException {
        List<SignedCertificateTimestamp> result = SctVerifier.verifyAll(
                List.of(), Map.of(), DUMMY_PRE_CERT, 0);
        assertTrue(result.isEmpty());
    }

    @Test
    void emptyInputWithPositiveMinSctsThrows() {
        CtSubmissionException ex = assertThrows(CtSubmissionException.class,
                () -> SctVerifier.verifyAll(List.of(), Map.of(), DUMMY_PRE_CERT, 2));
        assertTrue(ex.getMessage().contains("2"));
    }

    @Test
    void futureTimestampBeyondDriftIsRejected() {
        byte[] logId = new byte[32];
        Arrays.fill(logId, (byte) 0x01);
        Instant farFuture = Instant.now()
                .plus(Duration.ofMinutes(SctVerifier.MAX_FUTURE_DRIFT_MINUTES + 1));
        SignedCertificateTimestamp sct = sctWithTimestamp(logId, farFuture);

        CtSubmissionException ex = assertThrows(CtSubmissionException.class,
                () -> SctVerifier.verifyAll(List.of(sct), Map.of(), DUMMY_PRE_CERT, 1));
        assertTrue(ex.getMessage().contains("0"));
    }

    @Test
    void sctFromUnknownLogIsDiscarded() {
        byte[] logId = new byte[32];
        Arrays.fill(logId, (byte) 0x02);
        SignedCertificateTimestamp sct = sctWithTimestamp(logId, Instant.now());

        // logPublicKeys is empty — log is not trusted
        CtSubmissionException ex = assertThrows(CtSubmissionException.class,
                () -> SctVerifier.verifyAll(List.of(sct), Map.of(), DUMMY_PRE_CERT, 1));
        assertTrue(ex.getMessage().contains("0"));
    }

    @Test
    void nullArgumentsThrow() {
        assertThrows(NullPointerException.class,
                () -> SctVerifier.verifyAll(null, Map.of(), DUMMY_PRE_CERT, 0));
        assertThrows(NullPointerException.class,
                () -> SctVerifier.verifyAll(List.of(), null, DUMMY_PRE_CERT, 0));
        assertThrows(NullPointerException.class,
                () -> SctVerifier.verifyAll(List.of(), Map.of(), null, 0));
    }

    @Test
    void policyExceptionMessageContainsBothCounts() {
        byte[] logId = new byte[32];
        Arrays.fill(logId, (byte) 0x03);
        // Timestamp in the future (within allowed drift) but from an unknown log
        SignedCertificateTimestamp sct = sctWithTimestamp(logId, Instant.now());

        CtSubmissionException ex = assertThrows(CtSubmissionException.class,
                () -> SctVerifier.verifyAll(List.of(sct), Map.of(), DUMMY_PRE_CERT, 3));
        String message = ex.getMessage();
        assertTrue(message.contains("3"), "Message should contain minScts: " + message);
        assertTrue(message.contains("0"), "Message should contain verified count: " + message);
    }

    @Test
    void policyExceptionLogIdIsSentinelForAggregatedFailure() {
        CtSubmissionException ex = assertThrows(CtSubmissionException.class,
                () -> SctVerifier.verifyAll(List.of(), Map.of(), DUMMY_PRE_CERT, 1));
        assertEquals("", ex.logId(), "Aggregated policy failure should use empty sentinel log ID");
    }
}
