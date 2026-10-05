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

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import zeroecho.pkix.ct.SignedCertificateTimestamp;

/**
 * Unit tests for {@link CtLogSubmitter}.
 *
 * <p>Uses in-memory {@link CtLogClient} stubs; no network required.</p>
 */
class CtLogSubmitterTest {

    private static final byte[] DUMMY_PRE_CERT = new byte[]{0x30, 0x01, 0x00};
    private static final List<byte[]> DUMMY_CHAIN = List.of(new byte[]{0x30, 0x01, 0x01});
    private static final byte[] DUMMY_LOG_ID = new byte[32];
    private static final Instant FAR_FUTURE = Instant.now().plusSeconds(60);

    static {
        Arrays.fill(DUMMY_LOG_ID, (byte) 0x01);
    }

    private static SignedCertificateTimestamp dummySct(byte[] logId) {
        byte[] id = logId.clone();
        return new SignedCertificateTimestamp(0, id, Instant.now(), new byte[0],
                "SHA256withECDSA", new byte[]{0x30, 0x01, 0x00});
    }

    @Test
    void emptyLogsReturnsEmptyList() {
        List<SignedCertificateTimestamp> result = CtLogSubmitter.submitAll(
                DUMMY_PRE_CERT, DUMMY_CHAIN, List.of(), FAR_FUTURE);
        assertTrue(result.isEmpty());
    }

    @Test
    void successfulSubmissionCollectsAllScts() {
        byte[] id1 = new byte[32];
        byte[] id2 = new byte[32];
        Arrays.fill(id1, (byte) 0x01);
        Arrays.fill(id2, (byte) 0x02);

        CtLogClient log1 = new StubCtLogClient("0101010101010101010101010101010101010101010101010101010101010101",
                dummySct(id1));
        CtLogClient log2 = new StubCtLogClient("0202020202020202020202020202020202020202020202020202020202020202",
                dummySct(id2));

        List<SignedCertificateTimestamp> result = CtLogSubmitter.submitAll(
                DUMMY_PRE_CERT, DUMMY_CHAIN, List.of(log1, log2), FAR_FUTURE);

        assertEquals(2, result.size());
    }

    @Test
    void failingLogIsSkippedAndDoesNotBlockOthers() {
        byte[] id1 = new byte[32];
        Arrays.fill(id1, (byte) 0x01);

        CtLogClient failing = new FailingCtLogClient("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        CtLogClient succeeding = new StubCtLogClient(
                "0101010101010101010101010101010101010101010101010101010101010101",
                dummySct(id1));

        List<SignedCertificateTimestamp> result = CtLogSubmitter.submitAll(
                DUMMY_PRE_CERT, DUMMY_CHAIN, List.of(failing, succeeding), FAR_FUTURE);

        assertEquals(1, result.size());
    }

    @Test
    void nullPreCertThrows() {
        assertThrows(NullPointerException.class,
                () -> CtLogSubmitter.submitAll(null, DUMMY_CHAIN, List.of(), FAR_FUTURE));
    }

    // -------------------------------------------------------------------------
    // Stubs
    // -------------------------------------------------------------------------

    private static final class StubCtLogClient implements CtLogClient {
        private final String logId;
        private final SignedCertificateTimestamp sct;

        StubCtLogClient(String logId, SignedCertificateTimestamp sct) {
            this.logId = logId;
            this.sct = sct;
        }

        @Override
        public String logId() {
            return logId;
        }

        @Override
        public SignedCertificateTimestamp submit(byte[] preCert, List<byte[]> chain, Instant deadline)
                throws CtSubmissionException {
            return sct;
        }

        @Override
        public void close() {
        }
    }

    private static final class FailingCtLogClient implements CtLogClient {
        private final String logId;

        FailingCtLogClient(String logId) {
            this.logId = logId;
        }

        @Override
        public String logId() {
            return logId;
        }

        @Override
        public SignedCertificateTimestamp submit(byte[] preCert, List<byte[]> chain, Instant deadline)
                throws CtSubmissionException {
            throw new CtSubmissionException("Simulated log failure", logId);
        }

        @Override
        public void close() {
        }
    }
}
