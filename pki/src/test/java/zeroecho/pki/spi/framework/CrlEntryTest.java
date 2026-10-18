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
package zeroecho.pki.spi.framework;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.revocation.RevocationReason;

final class CrlEntryTest {
    private static final Instant TIME = Instant.parse("2026-07-30T12:00:00.987654321Z");

    @Test
    void acceptsEveryExplicitActiveReasonAndFullPositiveSerialDomain() {
        BigInteger largestFeasibleX509Serial = BigInteger.ONE.shiftLeft(159).subtract(BigInteger.ONE);
        BigInteger[] serials = { BigInteger.ONE, BigInteger.valueOf(Long.MAX_VALUE),
                BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE), largestFeasibleX509Serial };
        for (RevocationReason reason : activeReasons()) {
            for (BigInteger serial : serials) {
                CrlEntry entry = new CrlEntry(serial, TIME, reason);
                assertEquals(serial, entry.serialNumber());
                assertEquals(TIME, entry.transitionTime());
                assertEquals(reason, entry.reason());
            }
        }
    }

    @Test
    void rejectsInvalidSerialTimeAndReason() {
        assertThrows(IllegalArgumentException.class,
                () -> new CrlEntry(BigInteger.ZERO, TIME, RevocationReason.UNSPECIFIED));
        assertThrows(IllegalArgumentException.class,
                () -> new CrlEntry(BigInteger.valueOf(-1L), TIME, RevocationReason.UNSPECIFIED));
        assertThrows(NullPointerException.class,
                () -> new CrlEntry(BigInteger.ONE, null, RevocationReason.UNSPECIFIED));
        assertThrows(NullPointerException.class, () -> new CrlEntry(BigInteger.ONE, TIME, null));
        assertEquals(RevocationReason.REMOVE_FROM_CRL,
                new CrlEntry(BigInteger.ONE, TIME, RevocationReason.REMOVE_FROM_CRL).reason());
    }

    private static RevocationReason[] activeReasons() {
        return Arrays.stream(RevocationReason.values()).filter(reason -> reason != RevocationReason.REMOVE_FROM_CRL)
                .toArray(RevocationReason[]::new);
    }
}
