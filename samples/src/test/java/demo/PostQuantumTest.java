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
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import zeroecho.core.alg.kyber.KyberKeyGenSpec;
import zeroecho.core.util.Strings;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.alg.KemDataContentBuilder;
import zeroecho.sdk.builders.core.DataContentChainBuilder;
import zeroecho.sdk.builders.core.PlainBytesBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.util.BouncyCastleActivator;

@Tag("sample")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PostQuantumTest {
    private final ZeroEchoSession session = new ZeroEchoSession();
    private static final Logger LOG = Logger.getLogger(PostQuantumTest.class.getName());

    @BeforeAll
    void setupProviders() {
        BouncyCastleActivator.init();
    }

    KeyPair generateKyberKeys() throws GeneralSecurityException {
        KeyPair kp = session.keyBuilders().asymmetric()
                .generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber1024());

        LOG.log(Level.INFO, "ML-KEM key public={0} private={1}",
                new Object[] { Strings.toShortHexString(kp.getPublic().getEncoded()),
                        Strings.toShortHexString(kp.getPrivate().getEncoded()) });

        return kp;
    }

    @Test
    void pqcSdkLevelAPI() throws GeneralSecurityException, IOException {
        // Create a random sample message to be encrypted
        byte[] msg = randomBytes(100);
        // Generate a post-quantum key pair (Kyber, here wrapped as ML-KEM)
        KeyPair kp = generateKyberKeys();

        DataContent dccb = DataContentChainBuilder.encrypt()
                // Start the chain with a plain byte array as input
                .add(PlainBytesBuilder.builder().bytes(msg))
                // Add a KEM (Key Encapsulation Mechanism) stage
                .add(KemDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                        // Select a KEM-capable algorithm: ML-KEM (Kyber variant)
                        .kem("ML-KEM")
                        // Encrypt to this recipient’s public key
                        .recipientPublic(kp.getPublic())
                        // Derive a shared secret and expand/obfuscate it using HKDF-SHA256
                        .hkdfSha256("KEM-demo".getBytes(StandardCharsets.US_ASCII))
                        // Use the derived secret as a key for AES
                        .withAes(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                                // Configure AES in GCM mode with a 128-bit authentication tag
                                .modeGcm(128)
                                // Store auxiliary parameters (e.g., random IV) inside the stream header
                                .withHeader()))
                .build();

        byte[] encrypted;
        try (InputStream encryptedStream = dccb.getStream()) {
            // Consume the encrypted output stream into memory
            encrypted = readAll(encryptedStream);
        }

        // Now decrypt the message
        dccb = DataContentChainBuilder.decrypt()
                // Start with the encrypted byte array as input
                .add(PlainBytesBuilder.builder().bytes(encrypted))
                // Add the KEM stage again, matching the encryption parameters
                .add(KemDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                        // Use the same KEM algorithm that was used for encryption
                        .kem("ML-KEM")
                        // Provide the recipient’s private key for decapsulation
                        .recipientPrivate(kp.getPrivate())
                        // Re-derive the shared secret with the same HKDF-SHA256 label
                        .hkdfSha256("KEM-demo".getBytes(StandardCharsets.US_ASCII))
                        // Use the secret to unlock AES payload decryption
                        .withAes(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                                // AES in GCM mode with a 128-bit tag, consistent with encryption
                                .modeGcm(128)
                                // Read auxiliary parameters (IV, etc.) back from the header
                                .withHeader()))
                .build();

        byte[] decrypted;
        try (InputStream decryptedStream = dccb.getStream()) {
            // Consume the decrypted data into memory
            decrypted = readAll(decryptedStream);
        }

        LOG.log(Level.INFO, "original message={0} after ML-KEM(Kyber)+AES/GCM128 roundtrip={1}",
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
