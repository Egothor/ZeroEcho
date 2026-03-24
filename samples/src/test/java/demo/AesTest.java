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
package demo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import conflux.Ctx;
import conflux.CtxInterface;
import zeroecho.core.ConfluxKeys;
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.aes.AesKeyGenSpec;
import zeroecho.core.alg.aes.AesSpec;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.spi.ContextAware;
import zeroecho.core.util.Strings;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.core.DataContentChainBuilder;
import zeroecho.sdk.builders.core.PlainBytesBuilder;
import zeroecho.sdk.content.api.DataContent;

class AesTest {
    private static final Logger LOG = Logger.getLogger(AesTest.class.getName());

    SecretKey generateAesKey() throws GeneralSecurityException {
        // Locate the AES algorithm in the catalog
        CryptoAlgorithm aes = CryptoAlgorithms.require("AES");
        SecretKey key = aes
                // Retrieve the builder that works with AesKeyGenSpec - the specification for
                // AES key generation
                .symmetricKeyBuilder(AesKeyGenSpec.class)
                // Generate a secret key according to the AES256 specification
                .generateSecret(AesKeyGenSpec.aes256());
        // Log the generated key (truncated to short hex for readability)
        LOG.log(Level.INFO, "AES256 key generated: {0}", Strings.toShortHexString(key.getEncoded()));

        // or just: CryptoAlgorithms.generateSecret("AES", AesKeyGenSpec.aes256())

        return key;
    }

    @Test
    void aesEncryptCoreLevelAPI() throws GeneralSecurityException, IOException {
        // Sample message to encrypt
        byte[] msg = randomBytes(100);

        // AES-GCM specification with a 128-bit authentication tag
        // The null parameter indicates that no header codec is used (more on this
        // below)
        AesSpec spec = AesSpec.gcm128(null);
        // Encryption will generate a random IV for us. Normally it would be saved
        // through the header codec, but since we do not use it here, the IV and other
        // values are stored in a "context" instead. The "context" is a key-value
        // in-memory store; we create a private context with a unique name for this
        // session.
        CtxInterface session = Ctx.INSTANCE.getContext("aes-ctx-" + System.nanoTime());

        SecretKey key = generateAesKey();
        byte[] encrypted;
        // Request an encryption context using the key and AES-GCM-128 specification
        try (EncryptionContext enc = CryptoAlgorithms.create("AES", KeyUsage.ENCRYPT, key, spec)) {
            // This context implements ContextAware, allowing us to associate our session
            ((ContextAware) enc).setContext(session);
            // Get an encrypted stream that processes the plaintext on-the-fly
            try (InputStream encryptedStream = enc.attach(new ByteArrayInputStream(msg))) {
                // In this sample we consume the encrypted stream fully into memory
                encrypted = readAll(encryptedStream);
            }
        }

        LOG.log(Level.INFO, "Core: AES256/GCM128 IV={0} AAD={1} encrypted={2}", new Object[] {
                // The IV was generated automatically (we could have provided one, but
                // if omitted, it is created for us)
                Strings.toShortHexString(session.get(ConfluxKeys.iv("AES"))),
                // AAD is an additional parameter for GCM; again, automatically generated
                // because we did not provide it
                Strings.toShortHexString(session.get(ConfluxKeys.aad("AES"))),
                // The final ciphertext
                Strings.toShortHexString(encrypted) });
    }

    @Test
    void aesEncryptSdkLevelAPI() throws GeneralSecurityException, IOException {
        // Sample message to encrypt
        byte[] msg = randomBytes(100);

        SecretKey key = generateAesKey();
        AesSpec spec = AesSpec.gcm128(null);

        // Separate context again to hold IV and AAD values so we can inspect them later
        CtxInterface session = Ctx.INSTANCE.getContext("aes-ctx-" + System.nanoTime());
        AesDataContentBuilder aesBuilder = AesDataContentBuilder.builder()
                // Use the generated AES key
                .importKeyRaw(key.getEncoded())
                // Specify AES-GCM-128 mode
                .spec(spec)
                // Provide the context to capture IV and AAD
                .context(session);

        DataContent dccb = DataContentChainBuilder
                // Build an encryption pipeline
                .encrypt()
                // Input: the sample byte array
                .add(PlainBytesBuilder.builder().bytes(msg))
                // Process through AES encryption
                .add(aesBuilder)
                // Finalize the pipeline
                .build();

        byte[] encrypted;
        try (InputStream encryptedStream = dccb.getStream()) {
            // Consume the encrypted data into memory
            encrypted = readAll(encryptedStream);
        }

        LOG.log(Level.INFO, "SDK: AES256/GCM128 IV={0} AAD={1} encrypted={2}", new Object[] {
                // IV generated for us (we could provide one; if omitted, a random IV is
                // created)
                Strings.toShortHexString(session.get(ConfluxKeys.iv("AES"))),
                // AAD generated automatically (not explicitly provided)
                Strings.toShortHexString(session.get(ConfluxKeys.aad("AES"))),
                // Final ciphertext
                Strings.toShortHexString(encrypted) });
    }

    @Test
    void aesEncryptSmarterSdkLevelAPI() throws GeneralSecurityException, IOException {
        // Sample message to encrypt
        byte[] msg = randomBytes(100);

        AesDataContentBuilder aesBuilder = AesDataContentBuilder.builder()
                // Automatically generate a 256-bit AES key
                .generateKey(256)
                // Store ad-hoc generated parameters (IV, AAD) in the stream header
                .withHeader()
                // Use AES-GCM with a 128-bit authentication tag
                .modeGcm(128);

        // The builder stores all generated attributes inside the stream header
        DataContent dccb = DataContentChainBuilder
                // Build an encryption pipeline
                .encrypt()
                // Input: the sample byte array
                .add(PlainBytesBuilder.builder().bytes(msg))
                // Process through AES encryption
                .add(aesBuilder)
                // Finalize the pipeline
                .build();

        LOG.log(Level.INFO, "SDK-smart: AES256 key generated {0}",
                // The key is generated within dccb's `build` method, not earlier
                Strings.toShortHexString(aesBuilder.generatedKey().getEncoded()));

        byte[] encrypted;
        try (InputStream encryptedStream = dccb.getStream()) {
            // Consume the encrypted data into memory
            encrypted = readAll(encryptedStream);
        }

        LOG.log(Level.INFO, "SDK-smart: AES256/GCM128 IV=builtin AAD=builtin encrypted={0}",
                // The ciphertext, with IV and AAD already embedded in the header
                Strings.toShortHexString(encrypted));
    }

    @Test
    void aesRoundSmarterSdkLevelAPI() throws GeneralSecurityException, IOException {
        // Sample message to encrypt
        byte[] msg = randomBytes(100);

        AesDataContentBuilder aesBuilder = AesDataContentBuilder.builder().generateKey(256).modeGcm(128).withHeader();

        // The builder stores generated IV and AAD inside the stream header
        DataContent dccb = DataContentChainBuilder.encrypt().add(PlainBytesBuilder.builder().bytes(msg)).add(aesBuilder)
                .build();

        SecretKey key = aesBuilder.generatedKey();
        LOG.log(Level.INFO, "SDK-smart: AES256 key generated {0}", Strings.toShortHexString(key.getEncoded()));

        byte[] encrypted;
        try (InputStream encryptedStream = dccb.getStream()) {
            // Consume the encrypted data into memory
            encrypted = readAll(encryptedStream);
        }

        dccb = DataContentChainBuilder.decrypt().add(PlainBytesBuilder.builder().bytes(encrypted))
                // Use the same AES key for decryption; IV and AAD are restored from the header
                .add(AesDataContentBuilder.builder().importKeyRaw(key.getEncoded()).modeGcm(128).withHeader())
                // Build the pipeline
                .build();
        byte[] decrypted;
        try (InputStream decryptedStream = dccb.getStream()) {
            // Consume the decrypted data into memory
            decrypted = readAll(decryptedStream);
        }

        LOG.log(Level.INFO, "original message={0} after AES roundtrip={1}",
                new Object[] { Strings.toShortHexString(msg), Strings.toShortHexString(decrypted) });
    }

    // helpers

    private static byte[] randomBytes(int len) {
        byte[] data = new byte[len];
        new SecureRandom().nextBytes(data);
        return data;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            in.transferTo(out);
            out.flush();
            return out.toByteArray();
        }
    }
}
