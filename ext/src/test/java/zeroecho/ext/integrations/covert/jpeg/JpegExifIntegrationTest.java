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
package zeroecho.ext.integrations.covert.jpeg;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import conflux.Ctx;
import conflux.CtxInterface;
import zeroecho.core.alg.aes.AesKeyGenSpec;
import zeroecho.core.alg.aes.AesSpec;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.core.DataContentChainBuilder;
import zeroecho.sdk.builders.core.PlainBytesBuilder;
import zeroecho.sdk.content.api.DataContent;

class JpegExifIntegrationTest {

    @TempDir
    Path tempDir;

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        in.transferTo(out);
        return out.toByteArray();
    }

    @Test
    void testEncryptEmbedExtractDecrypt() throws Exception {
        System.out.println("testEncryptEmbedExtractDecrypt");

        String inputText = "Hello, this is a secret message to embed in JPEG.";

        inputText = inputText + inputText;
        inputText = inputText + inputText;
        inputText = inputText + inputText;

        final byte[] inputBytes = inputText.getBytes(StandardCharsets.UTF_8);
        final byte[] aad = { 1, 2, 3 };

        System.out.println("...inputBytes.length=" + inputBytes.length);

        // AES encryption setup
        /*
         * SecretKey key = zeroEchoSession.keyBuilders().symmetric() .generate("AES",
         * AesKeyGenSpec.aes256()); AesSpec spec =
         * AesSpec.builder().mode(Mode.GCM).tagLenBits(128).header(null).build();
         * EncryptionContext enc = zeroEchoSession.createContext("AES",
         * KeyUsage.ENCRYPT, key, spec); CtxInterface session =
         * Ctx.INSTANCE.getContext("aes-ctx-" + System.nanoTime());
         * session.put(ConfluxKeys.aad("AES"), aad); ((ContextAware)
         * enc).setContext(session);
         */
        ZeroEchoSession zeroEchoSession = new ZeroEchoSession();
        SecretKey key = zeroEchoSession.keyBuilders().symmetric().generate("AES", AesKeyGenSpec.aes256());
        CtxInterface session = Ctx.INSTANCE.getContext("aes-ctx-" + System.nanoTime());

        byte[] encryptedBytes;
        DataContent dccb = DataContentChainBuilder.encrypt()
                // input
                .add(PlainBytesBuilder.builder().bytes(inputBytes))
                // encryption
                .add(AesDataContentBuilder.builder(zeroEchoSession).importKeyRaw(key.getEncoded())
                        // using general AES/GCM/128 without specified header
                        .spec(AesSpec.gcm128(null))
                        // but let the builder add the default header for storing AAD and IV
                        .withHeader().withAad(aad).context(session))
                // and create the pipeline
                .build();
        try (InputStream in = dccb.getStream()) {
            encryptedBytes = readAll(in);
        }

        System.out.println("...encryptedBytes.length=" + encryptedBytes.length);
        System.out.println("...-> " + Arrays.toString(encryptedBytes));

        // Prepare JPEG test image
        Path jpegOriginal = getResourcePath("test.jpg");
        Path jpegEmbedded = tempDir.resolve("stego.jpg");

        // Embed payload
        try (InputStream payloadInput = new ByteArrayInputStream(encryptedBytes);
                OutputStream jpegOutput = Files.newOutputStream(jpegEmbedded)) {

            JpegExifEmbedder embedder = new JpegExifEmbedder();
            embedder.setSlots(Slot.defaults());
            int embed_size = embedder.embed(jpegOriginal, payloadInput, jpegOutput);
            System.out.println("...embeddedStream.length=" + embed_size);
        }

        // Extract payload
        ByteArrayOutputStream extractedEncrypted = new ByteArrayOutputStream();
        JpegExifEmbedder embedder = new JpegExifEmbedder();
        embedder.setSlots(Slot.defaults());
        embedder.extract(jpegEmbedded, extractedEncrypted);

        byte[] extractedEncryptedBytes = extractedEncrypted.toByteArray();
        System.out.println("...extractedEncryptedBytes.length=" + extractedEncryptedBytes.length);
        System.out.println("...-> " + Arrays.toString(extractedEncryptedBytes));

        // Decrypt
        dccb = DataContentChainBuilder.decrypt()
                // input
                .add(PlainBytesBuilder.builder().bytes(extractedEncryptedBytes))
                // encryption
                .add(AesDataContentBuilder.builder(zeroEchoSession).importKeyRaw(key.getEncoded())
                        .spec(AesSpec.gcm128(null))
                        // let us use the default header for AAD and IV
                        .withHeader().withAad(aad).context(session))
                // and create the pipeline
                .build();
        byte[] pt1;
        try (InputStream in = dccb.getStream()) {
            pt1 = readAll(in);
        }
        /*
         * AesSpec spec =
         * AesSpec.builder().mode(Mode.GCM).tagLenBits(128).header(null).build();
         * EncryptionContext dec1 = zeroEchoSession.createContext("AES",
         * KeyUsage.DECRYPT, key, spec); ((ContextAware) dec1).setContext(session); //
         * same IV/AAD in ctx byte[] pt1 = readAll(dec1.attach(new
         * ByteArrayInputStream(extractedEncryptedBytes))); dec1.close();
         */
        String decrypted = new String(pt1, StandardCharsets.UTF_8);

        assertEquals(inputText, decrypted);
        System.out.println("...ok");
    }

    private Path getResourcePath(String resource) throws URISyntaxException {
        URL url = getClass().getClassLoader().getResource(resource);
        if (url == null) {
            throw new IllegalArgumentException("Missing resource: " + resource);
        }
        return Paths.get(url.toURI());
    }
}
