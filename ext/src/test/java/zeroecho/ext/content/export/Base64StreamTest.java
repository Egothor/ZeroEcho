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
package zeroecho.ext.content.export;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import org.junit.jupiter.api.Test;

class Base64StreamTest {

    @Test
    void testEncodedOutputFrom4KBInput() throws Exception {
        System.out.println("testEncodedOutputFrom4KBInput");

        byte[] inputBytes = new byte[4096];
        new SecureRandom().nextBytes(inputBytes); // random 4KB data

        byte[] inputEncoded = Base64.getEncoder().encode(inputBytes);

        System.out.println("...encoded length should be: " + inputEncoded.length);

        int lineLength = 76;

        String[] prefixes = { "echo ", null };
        byte[][] lineSeparators = { "  >> file.tmp\r\n".getBytes(StandardCharsets.US_ASCII),
                "\n".getBytes(StandardCharsets.US_ASCII), null };

        for (String prefix : prefixes) {
            for (byte[] lineSep : lineSeparators) {
                System.out.printf("...***** testing with prefix=%s and lineSep=%s%n",
                        prefix == null ? "null" : "\"" + prefix + "\"",
                        lineSep == null ? "null" : "\"" + new String(lineSep, StandardCharsets.US_ASCII) + "\"");

                try (InputStream base64Stream = new Base64Stream(new ByteArrayInputStream(inputBytes),
                        prefix == null ? null : prefix.getBytes(StandardCharsets.US_ASCII), lineLength, lineSep)) {

                    String encodedOutput = new String(base64Stream.readAllBytes(), StandardCharsets.US_ASCII);
                    System.out.println(encodedOutput);

                    String[] lines = encodedOutput.split("\n");
                    for (int i = 0; i < lines.length; i++) {
                        int space = lines[i].indexOf(' ');
                        if (space > 0) {
                            lines[i] = lines[i].split(" ")[prefix == null ? 0 : 1];
                        }
                    }

                    if (lineSep != null) {
                        for (String line : lines) {
                            assertTrue(line.length() <= lineLength, "Line exceeds max length: " + line.length());
                        }
                    }

                    String joined = String.join("", lines);

                    System.out.println("...lines: " + lines.length);
                    System.out.println("......encoded length: " + joined.length());

                    if (lineSep == null && prefix != null) {
                        continue;
                    }

                    byte[] decoded = Base64.getDecoder().decode(joined);

                    System.out.println("...decoded length: " + decoded.length);

                    assertArrayEquals(inputBytes, decoded, "Decoded content does not match original input");
                }
            }
        }

        System.out.println("...ok");
    }
}
