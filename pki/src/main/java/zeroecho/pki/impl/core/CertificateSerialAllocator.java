/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.impl.core;

import java.math.BigInteger;
import java.util.Arrays;

import zeroecho.core.util.RandomSupport;

/**
 * Allocates positive issuer-controlled X.509 serial numbers.
 */
final class CertificateSerialAllocator {
    private static final int SERIAL_BYTES = 20;

    private CertificateSerialAllocator() {
    }

    /* package */ static BigInteger allocate() {
        byte[] encoded = new byte[SERIAL_BYTES];
        try {
            do {
                RandomSupport.generateRandom(encoded);
                encoded[0] &= 0x7f;
            } while (isZero(encoded));
            return new BigInteger(1, encoded);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static boolean isZero(byte[] bytes) {
        int aggregate = 0;
        for (byte value : bytes) {
            aggregate |= value;
        }
        return aggregate == 0;
    }
}
