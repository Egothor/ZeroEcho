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

import zeroecho.core.util.RandomSupport;

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
