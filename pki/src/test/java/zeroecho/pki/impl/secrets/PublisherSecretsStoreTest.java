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
package zeroecho.pki.impl.secrets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import zeroecho.core.io.Util;
import zeroecho.sdk.Pbkdf2Limits;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.content.builtin.PlainBytes;
import zeroecho.sdk.guard.MultiRecipientContent;
import zeroecho.sdk.guard.MultiRecipientDataSourceBuilder;
import zeroecho.sdk.guard.UnlockMaterial;

@Timeout(30)
class PublisherSecretsStoreTest {
    @TempDir
    Path directory;

    @Test
    void opensVersionOneEnvelopeUsingOriginalWriterParameters() throws Exception {
        Path store = store(envelope(600_000));
        byte[] original = Files.readAllBytes(store);
        assertEquals(Map.of("alias", "fixture-secret"),
                PublisherSecretsStore.open(store, password()));
        assertArrayEquals(original, Files.readAllBytes(store));
    }

    @Test
    void rejectsValidEnvelopeAbovePublisherIterationPolicy() throws Exception {
        // This is a valid authenticated envelope, not a malformed password blob.
        Path store = store(envelope(600_001));
        byte[] original = Files.readAllBytes(store);
        assertThrows(IOException.class, () -> PublisherSecretsStore.open(store, password()));
        assertArrayEquals(original, Files.readAllBytes(store));
    }

    @ParameterizedTest
    @ValueSource(ints = {9_999, Integer.MAX_VALUE})
    void rejectsInvalidDecodedWorkFactors(int iterations) throws Exception {
        ByteArrayInputStream input = new ByteArrayInputStream(envelope(600_000));
        int count = Util.readPack7I(input);
        String id = Util.readUTF8(input, 256);
        ByteArrayInputStream blob = new ByteArrayInputStream(Util.read(input, 1 << 20));
        Util.readPack7I(blob);
        ByteArrayOutputStream alteredBlob = new ByteArrayOutputStream();
        Util.writePack7I(alteredBlob, iterations);
        blob.transferTo(alteredBlob);
        ByteArrayOutputStream altered = new ByteArrayOutputStream();
        Util.writePack7I(altered, count);
        Util.writeUTF8(altered, id);
        Util.write(altered, alteredBlob.toByteArray());
        input.transferTo(altered);
        Path store = store(altered.toByteArray());
        byte[] original = Files.readAllBytes(store);
        assertThrows(IOException.class, () -> PublisherSecretsStore.open(store, password()));
        assertArrayEquals(original, Files.readAllBytes(store));
    }

    @Test
    void rejectsTamperedCiphertextWithoutChangingStore() throws Exception {
        byte[] encrypted = envelope(600_000);
        encrypted[encrypted.length - 1] ^= 1;
        Path store = store(encrypted);
        byte[] original = Files.readAllBytes(store);
        assertThrows(IOException.class, () -> PublisherSecretsStore.open(store, password()));
        assertArrayEquals(original, Files.readAllBytes(store));
    }

    private static UnlockMaterial.Password password() {
        return new UnlockMaterial.Password("fixture-password".toCharArray());
    }

    private Path store(byte[] envelope) throws IOException {
        Path path = directory.resolve("publisher.pss");
        Files.writeString(path, "{\"version\":1,\"protection\":\"CLASSIC\",\"encryptedSecrets\":\""
                + Base64.getEncoder().encodeToString(envelope) + "\"}");
        return path;
    }

    private static byte[] envelope(int iterations) throws Exception {
        ZeroEchoSession session = new ZeroEchoSession()
                .withPbkdf2Limits(new Pbkdf2Limits(iterations, iterations));
        try (MultiRecipientDataSourceBuilder builder = MultiRecipientDataSourceBuilder.builder(session)) {
            builder.payloadKeyBytes(32)
                    .withAes(AesDataContentBuilder.builder(session).modeGcm(128).withHeader())
                    .addPasswordRecipient("fixture-password".toCharArray(), iterations, 32, 32);
            MultiRecipientContent content = builder.build(true);
            content.setInput(new PlainBytes("{\"alias\":\"fixture-secret\"}".getBytes(StandardCharsets.UTF_8)));
            try (InputStream input = content.getStream()) {
                return input.readAllBytes();
            }
        }
    }
}
