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
package zeroecho.pki.spi.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

final class SigningProviderConfigurationCommitmentTest {

    @Test
    void valueIsImmutableConstantTimeComparableAndRedacted() {
        byte[] source = new byte[SigningProvider.ConfigurationCommitment.BYTE_LENGTH];
        Arrays.fill(source, (byte) 0x5a);
        SigningProvider.ConfigurationCommitment first =
                new SigningProvider.ConfigurationCommitment(source);
        source[0] = 0;

        byte[] expected = new byte[SigningProvider.ConfigurationCommitment.BYTE_LENGTH];
        Arrays.fill(expected, (byte) 0x5a);
        assertArrayEquals(expected, first.bytes());
        byte[] returned = first.bytes();
        assertNotSame(returned, first.bytes());
        returned[1] = 0;
        assertArrayEquals(expected, first.bytes());

        SigningProvider.ConfigurationCommitment equal =
                new SigningProvider.ConfigurationCommitment(expected);
        byte[] differentBytes = expected.clone();
        differentBytes[differentBytes.length - 1] ^= 1;
        SigningProvider.ConfigurationCommitment different =
                new SigningProvider.ConfigurationCommitment(differentBytes);
        assertTrue(first.matches(equal));
        assertFalse(first.matches(different));
        assertFalse(first.matches(null));
        assertEquals(first, equal);
        assertEquals(first.hashCode(), equal.hashCode());
        assertFalse(first.equals(different));
        assertEquals("ConfigurationCommitment[redacted]", first.toString());

        assertThrows(NullPointerException.class,
                () -> new SigningProvider.ConfigurationCommitment(null));
        assertThrows(IllegalArgumentException.class,
                () -> new SigningProvider.ConfigurationCommitment(new byte[31]));
        assertThrows(IllegalArgumentException.class,
                () -> new SigningProvider.ConfigurationCommitment(new byte[33]));
    }
}
