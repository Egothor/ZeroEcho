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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import zeroecho.core.alg.rsa.RsaKeyGenSpec;
import zeroecho.core.alg.rsa.RsaSigSpec;
import zeroecho.core.tag.TagEngine;
import zeroecho.core.tag.TagEngineBuilder;
import zeroecho.core.util.Strings;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.TagTrailerDataContentBuilder;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.core.DataContentChainBuilder;
import zeroecho.sdk.builders.core.PlainBytesBuilder;
import zeroecho.sdk.content.api.DataContent;

@Tag("sample")
class SigningAesTest {
    private final ZeroEchoSession session = new ZeroEchoSession();
    private static final Logger LOG = Logger.getLogger(SigningAesTest.class.getName());

    KeyPair generateRsaKeys() throws GeneralSecurityException {
        KeyPair kp = session.keyBuilders().asymmetric().generateKeyPair("RSA", RsaKeyGenSpec.rsa4096());

        LOG.log(Level.INFO, "RSA key public={0} private={1}",
                new Object[] { Strings.toShortHexString(kp.getPublic().getEncoded()),
                        Strings.toShortHexString(kp.getPrivate().getEncoded()) });

        return kp;
    }

    @Test
    void aesRoundStESdkLevelAPI() throws GeneralSecurityException, IOException {
        LOG.info("aesRoundSmarterSdkLevelAPI - Sign then Encrypt");

        // Create a random sample message to be encrypted
        byte[] msg = randomBytes(100);
        // Configure AES in GCM mode with a 128-bit authentication tag. A fresh 256-bit
        // AES key will be generated automatically, and runtime parameters (IV, AAD)
        // will be written into the header.
        AesDataContentBuilder aesBuilder = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                .generateKey(256).modeGcm(128).withHeader();

        // Generate RSA-4096 key pair (retrieved via algorithm registry for convenience)
        KeyPair rsa = generateRsaKeys();

        // Configure PSS signature parameters: SHA-256 hash, salt length = 32 bytes
        RsaSigSpec pss = RsaSigSpec.pss(RsaSigSpec.Hash.SHA256, 32);
        // Create signing engine (RSA-PSS with private key)
        TagEngine<Signature> tagEnc = TagEngineBuilder
                .rsaSign(new zeroecho.sdk.ZeroEchoSession(), rsa.getPrivate(), pss).get();
        // Create verification engine (RSA-PSS with public key)
        TagEngine<Signature> tagDec = TagEngineBuilder
                .rsaVerify(new zeroecho.sdk.ZeroEchoSession(), rsa.getPublic(), pss).get();

        // Build the encryption pipeline
        DataContent dccb = DataContentChainBuilder.encrypt()
                // Input: raw message bytes
                .add(PlainBytesBuilder.builder().bytes(msg))
                // Sign the data with RSA-PSS (trailer attached to the stream)
                .add(new TagTrailerDataContentBuilder<>(tagEnc).bufferSize(8192))
                // Encrypt everything using AES-GCM (IV + AAD stored in the header)
                .add(aesBuilder).build();

        // Retrieve and log the generated AES key in hex (for demonstration only)
        SecretKey key = aesBuilder.generatedKey();
        // In production, keys should never be logged or exposed
        LOG.log(Level.INFO, "SDK-smart: AES256 key generated {0}", Strings.toShortHexString(key.getEncoded()));

        byte[] encrypted;
        try (InputStream encryptedStream = dccb.getStream()) {
            // Consume the encrypted data into memory
            encrypted = readAll(encryptedStream);
        }

        // Build the decryption pipeline
        dccb = DataContentChainBuilder.decrypt()
                // Input: encrypted byte array
                .add(PlainBytesBuilder.builder().bytes(encrypted))
                // AES-GCM decryption using the same key; IV and AAD are restored automatically
                // from the header
                .add(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).importKeyRaw(key.getEncoded())
                        .modeGcm(128).withHeader())
                // Verify the RSA-PSS signature trailer at the end of the stream (configured to
                // throw on mismatch)
                .add(new TagTrailerDataContentBuilder<>(tagDec).bufferSize(8192).throwOnMismatch())
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

    @Test
    void aesRoundEtSSdkLevelAPI() throws GeneralSecurityException, IOException {
        LOG.info("aesRoundSmarterSdkLevelAPI - Encrypt then Sign");

        // Create a random sample message to be encrypted
        byte[] msg = randomBytes(100);

        AesDataContentBuilder aesBuilder = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                .generateKey(256).modeGcm(128).withHeader();

        // Generate RSA-4096 key pair (retrieved via algorithm registry for convenience)
        KeyPair rsa = generateRsaKeys();

        // Configure PSS signature parameters: SHA-256 hash, salt length = 32 bytes
        RsaSigSpec pss = RsaSigSpec.pss(RsaSigSpec.Hash.SHA256, 32);
        TagEngine<Signature> tagEnc = TagEngineBuilder
                .rsaSign(new zeroecho.sdk.ZeroEchoSession(), rsa.getPrivate(), pss).get();
        TagEngine<Signature> tagDec = TagEngineBuilder
                .rsaVerify(new zeroecho.sdk.ZeroEchoSession(), rsa.getPublic(), pss).get();

        // Build the encryption pipeline
        DataContent dccb = DataContentChainBuilder.encrypt()
                // Input: raw message bytes
                .add(PlainBytesBuilder.builder().bytes(msg))
                // Encrypt everything using AES-GCM (IV + AAD stored in the header)
                .add(aesBuilder)
                // Sign the encrypted data with RSA-PSS (trailer attached to the stream)
                .add(new TagTrailerDataContentBuilder<>(tagEnc).bufferSize(8192))
                // Build the pipeline
                .build();

        SecretKey key = aesBuilder.generatedKey();
        LOG.log(Level.INFO, "SDK-smart: AES256 key generated {0}", Strings.toShortHexString(key.getEncoded()));

        byte[] encrypted;
        try (InputStream encryptedStream = dccb.getStream()) {
            // Consume the encrypted data into memory
            encrypted = readAll(encryptedStream);
        }

        // Build the decryption pipeline
        dccb = DataContentChainBuilder.decrypt()
                // Input: encrypted byte array
                .add(PlainBytesBuilder.builder().bytes(encrypted))
                // Verify the RSA-PSS signature trailer at the end of the stream.
                // The pipeline is configured to throw an exception if verification fails.
                // Verification happens while the data continues flowing into the decryptor,
                // so the consumer can fully process plaintext only if the signature is valid.
                .add(new TagTrailerDataContentBuilder<>(tagDec).bufferSize(8192).throwOnMismatch())
                // AES-GCM decryption using the same key; IV and AAD are restored automatically
                // from the header
                .add(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).importKeyRaw(key.getEncoded())
                        .modeGcm(128).withHeader())
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
