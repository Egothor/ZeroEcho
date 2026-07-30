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
package zeroecho.sdk.hybrid.kex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.MessageAgreementContext;

/**
 * Verifies provider-independent hybrid frame validation and size boundaries.
 */
class HybridKexFrameCodecTest {

    @Test
    void acceptsZeroLengthComponents() throws Exception {
        String name = start("acceptsZeroLengthComponents");
        byte[] frame = HybridKexContext.encode(new byte[0], new byte[0]);
        HybridKexContext.Parts parts = HybridKexContext.decode(frame);

        assertEquals(8, frame.length);
        assertArrayEquals(new byte[0], parts.classicPart());
        assertArrayEquals(new byte[0], parts.pqcPart());
        progress("frameBytes=" + frame.length);
        ok(name);
    }

    @Test
    void acceptsInclusiveMaximumFrame() throws Exception {
        String name = start("acceptsInclusiveMaximumFrame");
        byte[] classic = new byte[HybridKexContext.MAX_FRAME_BYTES - 8];
        byte[] frame = HybridKexContext.encode(classic, new byte[0]);

        assertEquals(HybridKexContext.MAX_FRAME_BYTES, frame.length);
        assertEquals(classic.length, HybridKexContext.decode(frame).classicPart().length);
        progress("frameBytes=" + frame.length);
        ok(name);
    }

    @Test
    void rejectsOversizedEncoding() {
        String name = start("rejectsOversizedEncoding");
        byte[] classic = new byte[HybridKexContext.MAX_FRAME_BYTES - 7];

        assertThrows(IOException.class, () -> HybridKexContext.encode(classic, new byte[0]));
        progress("classicBytes=" + classic.length);
        ok(name);
    }

    @Test
    void rejectsMalformedFrames() {
        String name = start("rejectsMalformedFrames");
        byte[][] malformed = { new byte[7], ints(-1, 0), ints(0, -1), ints(1, 0), ints(0, 1),
                append(ints(0, 0), (byte) 0x7f), new byte[HybridKexContext.MAX_FRAME_BYTES + 1],
                ints(0, HybridKexContext.MAX_FRAME_BYTES), ints(Integer.MAX_VALUE, 0) };

        for (byte[] frame : malformed) {
            assertThrows(IOException.class, () -> HybridKexContext.decode(frame));
        }
        progress("cases=" + malformed.length);
        ok(name);
    }

    @Test
    void publicApiMapsMalformedFrame() {
        String name = start("publicApiMapsMalformedFrame");
        AgreementContext classic = mock(AgreementContext.class);
        MessageAgreementContext pqc = mock(MessageAgreementContext.class);
        HybridKexContext context = new HybridKexContext(HybridKexProfile.defaultProfile(32), classic, pqc);

        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> context.setPeerMessage(ints(Integer.MAX_VALUE, 0)));

        assertInstanceOf(IOException.class, failure.getCause());
        verifyNoInteractions(classic, pqc);
        progress("mapped=IllegalArgument");
        ok(name);
    }

    @Test
    void clearsComponentSecretsAfterSuccessfulDerivation() {
        String name = start("clearsComponentSecretsAfterSuccessfulDerivation");
        byte[] classicSecret = { 1, 2, 3 };
        byte[] pqcSecret = { 4, 5, 6 };
        AgreementContext classic = mock(AgreementContext.class);
        MessageAgreementContext pqc = mock(MessageAgreementContext.class);
        when(classic.deriveSecret()).thenReturn(classicSecret);
        when(pqc.deriveSecret()).thenReturn(pqcSecret);
        HybridKexContext context = new HybridKexContext(HybridKexProfile.defaultProfile(16), classic, pqc);

        byte[] result = context.deriveSecret();

        assertEquals(16, result.length);
        assertZeroized(classicSecret);
        assertZeroized(pqcSecret);
        progress("resultBytes=" + result.length);
        ok(name);
    }

    @Test
    void clearsClassicSecretWhenSecondLegFails() {
        String name = start("clearsClassicSecretWhenSecondLegFails");
        byte[] classicSecret = { 1, 2, 3 };
        IllegalStateException expected = new IllegalStateException("controlled second-leg failure");
        AgreementContext classic = mock(AgreementContext.class);
        MessageAgreementContext pqc = mock(MessageAgreementContext.class);
        when(classic.deriveSecret()).thenReturn(classicSecret);
        when(pqc.deriveSecret()).thenThrow(expected);
        HybridKexContext context = new HybridKexContext(HybridKexProfile.defaultProfile(16), classic, pqc);

        assertSame(expected, assertThrows(IllegalStateException.class, context::deriveSecret));
        assertZeroized(classicSecret);
        progress("failure=secondLeg");
        ok(name);
    }

    @Test
    void clearsAllTemporarySecretsWhenKdfFails() {
        String name = start("clearsAllTemporarySecretsWhenKdfFails");
        byte[] classicSecret = { 1, 2, 3 };
        byte[] pqcSecret = { 4, 5, 6 };
        byte[][] observedInput = new byte[1][];
        AgreementContext classic = mock(AgreementContext.class);
        MessageAgreementContext pqc = mock(MessageAgreementContext.class);
        when(classic.deriveSecret()).thenReturn(classicSecret);
        when(pqc.deriveSecret()).thenReturn(pqcSecret);
        HybridKexContext context = new HybridKexContext(HybridKexProfile.defaultProfile(16), classic, pqc,
                (ikm, salt, info, outputLength) -> {
                    observedInput[0] = ikm;
                    throw new GeneralSecurityException("controlled KDF failure");
                });

        IllegalStateException failure = assertThrows(IllegalStateException.class, context::deriveSecret);

        assertInstanceOf(GeneralSecurityException.class, failure.getCause());
        assertZeroized(classicSecret);
        assertZeroized(pqcSecret);
        assertZeroized(observedInput[0]);
        progress("failure=KDF");
        ok(name);
    }

    private static byte[] ints(int first, int second) {
        return ByteBuffer.allocate(8).putInt(first).putInt(second).array();
    }

    private static byte[] append(byte[] input, byte value) {
        byte[] output = new byte[input.length + 1];
        System.arraycopy(input, 0, output, 0, input.length);
        output[input.length] = value;
        return output;
    }

    private static void assertZeroized(byte[] value) {
        assertTrue(value != null && Arrays.equals(new byte[value.length], value));
    }

    private static String start(String routine) {
        String label = routine.length() <= 30 ? routine : routine.substring(0, 27) + "...";
        System.out.println(label);
        return label;
    }

    private static void progress(String detail) {
        System.out.println("..." + detail);
    }

    private static void ok(String name) {
        System.out.println(name + "...ok");
    }
}
