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
package zeroecho;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class CovertCommandTest {

    @TempDir
    Path tempDir;

    private Path copyTestJpeg(String name) throws IOException {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(name)) {
            if (inputStream == null) {
                throw new IllegalArgumentException("Missing resource: " + name);
            }

            Path target = tempDir.resolve(name);
            Files.copy(inputStream, target, StandardCopyOption.REPLACE_EXISTING);
            return target;
        }
    }

    @Test
    void testEmbedAndExtractDefaultSlots() throws Exception {
        System.out.println("testEmbedAndExtractDefaultSlots");

        // Prepare input JPEG and payload
        Path jpeg = copyTestJpeg("test.jpg");
        Path payload = tempDir.resolve("secret.txt");
        Path stegoOutput = tempDir.resolve("stego.jpg");
        Path extractedOutput = tempDir.resolve("extracted.dat");

        String message = "SecretMessage123!";
        Files.write(payload, message.getBytes(StandardCharsets.UTF_8));

        // --- Embed ---
        Options embedOptions = new Options();
        int embedCode = CovertCommand.main(new String[] { "--embed", "--jpeg", jpeg.toString(), "--payload",
                payload.toString(), "--output", stegoOutput.toString() }, embedOptions);
        assertEquals(0, embedCode);
        assertTrue(Files.exists(stegoOutput));
        assertTrue(Files.size(stegoOutput) > Files.size(jpeg));

        // --- Extract ---
        Options extractOptions = new Options();
        int extractCode = CovertCommand.main(
                new String[] { "--extract", "--jpeg", stegoOutput.toString(), "--output", extractedOutput.toString() },
                extractOptions);
        assertEquals(0, extractCode);
        assertTrue(Files.exists(extractedOutput));

        // Verify content
        String extracted = Files.readString(extractedOutput);
        assertEquals(message, extracted);
        System.out.println("...ok");
    }

    @Test
    void testEmbedFailsWithoutPayload() {
        System.out.println("testEmbedFailsWithoutPayload");

        Exception thrown = assertThrows(ParseException.class, () -> {
            Options options = new Options();
            CovertCommand.main(new String[] { "--embed", "--jpeg", "input.jpg", "--output", "out.jpg" }, options);
        });

        assertTrue(thrown.getMessage().contains("--payload is required"));
        System.out.println("...ok");
    }

    @Test
    void testCustomSlotsEmbedding() throws Exception {
        System.out.println("testCustomSlotsEmbedding");

        Path jpeg = copyTestJpeg("test.jpg");
        Path payload = tempDir.resolve("msg.bin");
        Path stego = tempDir.resolve("custom_stego.jpg");
        Path extracted = tempDir.resolve("custom_extracted.bin");

        String secret = "This uses custom slots!";
        Files.write(payload, secret.getBytes(StandardCharsets.UTF_8));

        // Correctly defined custom slot string
        String slotString = "Exif.UserComment:2048;Exif.CustomDesc/tag=700,ascii,64,exif:1024";

        Options embedOptions = new Options();
        int code = CovertCommand.main(new String[] { "--embed", "--jpeg", jpeg.toString(), "--payload",
                payload.toString(), "--output", stego.toString(), "--slots", slotString }, embedOptions);
        assertEquals(0, code);
        assertTrue(Files.exists(stego));

        Options extractOptions = new Options();
        code = CovertCommand.main(new String[] { "--extract", "--jpeg", stego.toString(), "--output",
                extracted.toString(), "--slots", slotString }, extractOptions);
        assertEquals(0, code);

        String extractedMsg = Files.readString(extracted);
        assertEquals(secret, extractedMsg);
        System.out.println("...ok");
    }
}
