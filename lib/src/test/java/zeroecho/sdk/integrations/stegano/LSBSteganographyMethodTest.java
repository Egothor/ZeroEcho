/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.sdk.integrations.stegano;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import org.junit.jupiter.api.Test;

public class LSBSteganographyMethodTest {

    @Test
    void testEmbedAndExtract() throws Exception {
        SteganographyMethod method = new LSBSteganographyMethod();
        String message = "Hello from LSB!";
        InputStream imageIn = getClass().getResourceAsStream("/test.jpg");
        InputStream msgIn = new ByteArrayInputStream(message.getBytes());

        // Embed
        InputStream embedded = method.embed(imageIn, ImageFormat.PNG, msgIn);

        // Extract
        InputStream extracted = method.extract(embedded);
        String result = new String(extracted.readAllBytes());

        assertEquals(message, result);
    }

    @Test
    void testMetadata() {
        SteganographyMethod method = new LSBSteganographyMethod();
        StegoMetadata meta = method.getMetadata();

        assertEquals("LSB", meta.name());
        assertTrue(meta.fullName().contains("Least Significant"));
    }

    @Test
    void createSample() throws Exception {
        // for verification purposes
        SteganographyMethod method = new LSBSteganographyMethod();
        String message = "Hello from LSB!";
        InputStream imageIn = getClass().getResourceAsStream("/test.jpg");
        InputStream msgIn = new ByteArrayInputStream(message.getBytes());

        // Embed
        InputStream embedded = method.embed(imageIn, ImageFormat.PNG, msgIn);

        embedded.transferTo(Files.newOutputStream(Paths.get("/tmp/lsb-test.png"), StandardOpenOption.CREATE));
    }
}
