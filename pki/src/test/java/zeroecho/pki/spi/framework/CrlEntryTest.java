/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
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
        assertThrows(IllegalArgumentException.class,
                () -> new CrlEntry(BigInteger.ONE, TIME, RevocationReason.REMOVE_FROM_CRL));
    }

    private static RevocationReason[] activeReasons() {
        return Arrays.stream(RevocationReason.values()).filter(reason -> reason != RevocationReason.REMOVE_FROM_CRL)
                .toArray(RevocationReason[]::new);
    }
}
