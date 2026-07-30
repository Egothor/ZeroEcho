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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.junit.jupiter.api.Test;

/**
 * A simple concrete subclass of OutputToInputStreamAdapter that increments each
 * byte of input by 1.
 */
class IncrementingAdapter extends OutputToInputStreamAdapter {

    public IncrementingAdapter(InputStream previousInput) {
        super(previousInput);
    }

    /**
     * Initializes transformationOut as an OutputStream that increments bytes by 1.
     */
    public void initialize() {
        this.transformationOut = new OutputStream() {
            @Override
            public void write(int b) {
                baos.write((b + 1) & 0xFF);
            }
        };
    }
}

@Deprecated
public class OutputToInputStreamAdapterTest {

    private static final int BUF_SIZE = 8192;

    private InputStream generateLongInputStream() {
        String phrase = "Hello World! ";
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        while (baos.size() <= 3 * BUF_SIZE) {
            try {
                baos.write(phrase.getBytes());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return new ByteArrayInputStream(baos.toByteArray());
    }

    @Deprecated
    @Test
    public void testIncrementingAdapter() throws IOException {
        System.out.println("testIncrementingAdapter");
        InputStream plainInput = generateLongInputStream();
        IncrementingAdapter adapter = new IncrementingAdapter(plainInput);
        adapter.initialize();

        ByteArrayOutputStream result = new ByteArrayOutputStream();

        byte[] buffer = new byte[1024];
        int read;
        while ((read = adapter.read(buffer)) != -1) {
            result.write(buffer, 0, read);
        }
        adapter.close();

        byte[] originalBytes = generateLongInputStream().readAllBytes();
        byte[] transformedBytes = result.toByteArray();

        System.out.println("..." + transformedBytes.length + " bytes processed");

        assertEquals(originalBytes.length, transformedBytes.length, "Lengths must be equal");

        for (int i = 0; i < originalBytes.length; i++) {
            int expected = ((originalBytes[i] & 0xFF) + 1) & 0xFF;
            int actual = transformedBytes[i] & 0xFF;
            assertEquals(expected, actual, "Byte at position " + i + " should be incremented by 1");
        }
        System.out.println("...ok");
    }
}
