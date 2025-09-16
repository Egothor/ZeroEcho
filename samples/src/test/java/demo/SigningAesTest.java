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

import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.alg.aes.AesKeyGenSpec;
import zeroecho.core.alg.rsa.RsaKeyGenSpec;
import zeroecho.core.alg.rsa.RsaSigSpec;
import zeroecho.core.tag.TagEngine;
import zeroecho.core.tag.TagEngineBuilder;
import zeroecho.core.util.Strings;
import zeroecho.sdk.builders.TagTrailerDataContentBuilder;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.core.DataContentChainBuilder;
import zeroecho.sdk.builders.core.PlainBytesBuilder;
import zeroecho.sdk.content.api.DataContent;

class SigningAesTest {
    private static final Logger LOG = Logger.getLogger(SigningAesTest.class.getName());

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

    KeyPair generateRsaKeys() throws GeneralSecurityException {
        KeyPair kp = CryptoAlgorithms.generateKeyPair("RSA", RsaKeyGenSpec.rsa4096());

        LOG.log(Level.INFO, "RSA key public={0} private={1}",
                new Object[] { Strings.toShortHexString(kp.getPublic().getEncoded()),
                        Strings.toShortHexString(kp.getPrivate().getEncoded()) });

        return kp;
    }

    @Test
    void aesRoundStESdkLevelAPI() throws GeneralSecurityException, IOException {
        LOG.info("aesRoundSmarterSdkLevelAPI - Sign then Encrypt");

        // Sample message to encrypt
        byte[] msg = randomBytes(100);

        AesDataContentBuilder aesBuilder = AesDataContentBuilder.builder().generateKey(256).modeGcm(128).withHeader();

        // RSA-2048 keys (use registry for convenience)
        KeyPair rsa = generateRsaKeys();

        // Tag engines (SHA-256, saltLen=32)
        RsaSigSpec pss = RsaSigSpec.pss(RsaSigSpec.Hash.SHA256, 32);
        TagEngine<Signature> tagEnc = TagEngineBuilder.rsaSign(rsa.getPrivate(), pss).get();
        TagEngine<Signature> tagDec = TagEngineBuilder.rsaVerify(rsa.getPublic(), pss).get();

        // The builder stores generated IV and AAD inside the stream header
        DataContent dccb = DataContentChainBuilder.encrypt().add(PlainBytesBuilder.builder().bytes(msg))
                // sign the data
                .add(new TagTrailerDataContentBuilder<>(tagEnc).bufferSize(8192))
                // and then encrypt
                .add(aesBuilder).build();

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
                // the decrypted stream must be verified
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

        // Sample message to encrypt
        byte[] msg = randomBytes(100);

        AesDataContentBuilder aesBuilder = AesDataContentBuilder.builder().generateKey(256).modeGcm(128).withHeader();

        // RSA-2048 keys (use registry for convenience)
        KeyPair rsa = generateRsaKeys();

        // Tag engines (SHA-256, saltLen=32)
        RsaSigSpec pss = RsaSigSpec.pss(RsaSigSpec.Hash.SHA256, 32);
        TagEngine<Signature> tagEnc = TagEngineBuilder.rsaSign(rsa.getPrivate(), pss).get();
        TagEngine<Signature> tagDec = TagEngineBuilder.rsaVerify(rsa.getPublic(), pss).get();

        // The builder stores generated IV and AAD inside the stream header
        DataContent dccb = DataContentChainBuilder.encrypt().add(PlainBytesBuilder.builder().bytes(msg))
                // encrypt
                .add(aesBuilder)
                // and then sign
                .add(new TagTrailerDataContentBuilder<>(tagEnc).bufferSize(8192))
                //
                .build();

        SecretKey key = aesBuilder.generatedKey();
        LOG.log(Level.INFO, "SDK-smart: AES256 key generated {0}", Strings.toShortHexString(key.getEncoded()));

        byte[] encrypted;
        try (InputStream encryptedStream = dccb.getStream()) {
            // Consume the encrypted data into memory
            encrypted = readAll(encryptedStream);
        }

        dccb = DataContentChainBuilder.decrypt().add(PlainBytesBuilder.builder().bytes(encrypted))
                // the stream must be verified, but encryption still runs as data flows through
                .add(new TagTrailerDataContentBuilder<>(tagDec).bufferSize(8192).throwOnMismatch())
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
