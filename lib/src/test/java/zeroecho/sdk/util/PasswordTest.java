/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.sdk.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;

class PasswordTest {
    @Test
    void canonicalRandomFacadeValidatesNullAndAcceptsEmptyArrays() {
        System.out.print("Password/random-boundaries...");
        assertThrows(NullPointerException.class, () -> Password.generateRandom(null));
        byte[] empty = new byte[0];
        assertSame(empty, Password.generateRandom(empty));
        assertThrows(IllegalArgumentException.class, () -> Password.generatePrintablePasswordChars(0));
        assertThrows(IllegalArgumentException.class, () -> Password.generatePrintablePasswordChars(-1));

        char[] printable = Password.generatePrintablePasswordChars(128);
        assertEquals(128, printable.length);
        for (char character : printable) {
            assertTrue(character >= '!' && character <= '~');
        }
        System.out.println("ok");
    }

    @Test
    void sharedSourceSupportsParallelUse() throws Exception {
        System.out.print("RandomSupport/concurrent...");
        SecureRandom source = RandomSupport.getRandom();
        assertSame(source, RandomSupport.getRandom());
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<byte[]>> futures = new ArrayList<>();
            for (int i = 0; i < 64; i++) {
                futures.add(executor.submit(() -> {
                    assertSame(source, RandomSupport.getRandom());
                    return Password.generateRandom(new byte[32]);
                }));
            }
            byte[] first = futures.get(0).get();
            boolean differentOutputObserved = false;
            for (int i = 1; i < futures.size(); i++) {
                byte[] output = futures.get(i).get();
                if (!java.util.Arrays.equals(first, output)) {
                    differentOutputObserved = true;
                }
            }
            assertTrue(differentOutputObserved);
            assertNotEquals(0, first.length);
        } finally {
            executor.shutdownNow();
        }
        System.out.println("ok");
    }
}
