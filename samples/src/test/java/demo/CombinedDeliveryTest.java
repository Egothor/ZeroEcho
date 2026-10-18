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
package demo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import zeroecho.core.KeyUsage;
import zeroecho.core.alg.elgamal.ElgamalParamSpec;
import zeroecho.core.alg.kyber.KyberKeyGenSpec;
import zeroecho.core.alg.rsa.RsaKeyGenSpec;
import zeroecho.core.util.Strings;
import zeroecho.sdk.Pbkdf2Limits;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.core.DataContentChainBuilder;
import zeroecho.sdk.builders.core.PlainBytesBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.guard.MultiRecipientDataSourceBuilder;
import zeroecho.sdk.guard.UnlockMaterial;
import zeroecho.sdk.util.BouncyCastleActivator;

@Tag("sample")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CombinedDeliveryTest {
    private static final Logger LOG = Logger.getLogger(CombinedDeliveryTest.class.getName());
    private final ZeroEchoSession session = new ZeroEchoSession()
            .withPbkdf2Limits(new Pbkdf2Limits(1_000_000, 1_000_000));

    @BeforeAll
    void setupProviders() {
        BouncyCastleActivator.init();
    }

    KeyPair generateKyberKeys() throws GeneralSecurityException {
        KeyPair kp = session.keyBuilders().asymmetric().generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber1024());
        LOG.log(Level.INFO, "ML-KEM key pair generated");

        return kp;
    }

    KeyPair generateRsaKeys() throws GeneralSecurityException {
        KeyPair kp = session.keyBuilders().asymmetric().generateKeyPair("RSA", RsaKeyGenSpec.rsa4096());
        LOG.log(Level.INFO, "RSA key pair generated");

        return kp;
    }

    KeyPair generateElGamalKeys() throws GeneralSecurityException {
        KeyPair kp = session.keyBuilders().asymmetric().generateKeyPair("ElGamal", ElgamalParamSpec.ffdhe2048());
        LOG.log(Level.INFO, "ElGamal key pair generated");

        return kp;
    }

    @Test
    void combinedSdkLevelAPI() throws GeneralSecurityException, IOException {
        // Sample message to encrypt
        byte[] msg = randomBytes(100);

        KeyPair kem = generateKyberKeys();
        KeyPair rsa = generateRsaKeys();
        KeyPair elg = generateElGamalKeys();
        char[] password = "p@ssw07d".toCharArray();

        KeyPair decoy1rsa = generateRsaKeys();
        KeyPair decoy2rsa = generateRsaKeys();

        AesDataContentBuilder payload = AesDataContentBuilder.builder(session).modeCbcPkcs5().withHeader();

        MultiRecipientDataSourceBuilder multi = MultiRecipientDataSourceBuilder.builder(session)
                // AES-256 - 32 bytes of key material
                .payloadKeyBytes(32).withAes(payload)
                // add recipients - the context initialized with the public key
                .addRecipient(session.createContext("ElGamal", KeyUsage.ENCRYPT, elg.getPublic()))
                .addRecipient(session.createContext("RSA", KeyUsage.ENCRYPT, rsa.getPublic()))
                // ML-KEM PostQuantum uses AES for the inner payload
                .addRecipient(session.createContext("ML-KEM", KeyUsage.ENCAPSULATE, kem.getPublic()),
                        /* AES256 key size */
                        32,
                        /* salt size in hkdf */
                        32)
                // Password (via KDF)
                .addPasswordRecipient(password, /* iterations */ 200_000, /* saltLen */ 16, /* kekBytes */ 32)
                // and some decoys
                .addRecipientDecoy(session.createContext("RSA", KeyUsage.ENCRYPT, decoy1rsa.getPublic()))
                .addRecipientDecoy(session.createContext("RSA", KeyUsage.ENCRYPT, decoy2rsa.getPublic()));

        // shuffle all the recipients
        multi.shuffle();

        DataContent dccb = DataContentChainBuilder.encrypt().add(PlainBytesBuilder.builder().bytes(msg))
                // encrypt for multi recipients of various types
                .add(multi).build();

        byte[] encrypted;
        try (InputStream encryptedStream = dccb.getStream()) {
            // Consume the encrypted data into memory
            encrypted = readAll(encryptedStream);
        }

        recipientProcessing("ElGamal-ffdhe2048", msg, encrypted, new UnlockMaterial.Private(elg.getPrivate()));
        recipientProcessing("RSA4096", msg, encrypted, new UnlockMaterial.Private(rsa.getPrivate()));
        recipientProcessing("Kyber-1024", msg, encrypted, new UnlockMaterial.Private(kem.getPrivate()));
        recipientProcessing("Password", msg, encrypted, new UnlockMaterial.Password(password));
    }

    private void recipientProcessing(String method, byte[] msg, byte[] encrypted, UnlockMaterial unlock)
            throws IOException {
        AesDataContentBuilder payload = AesDataContentBuilder.builder(session).modeCbcPkcs5().withHeader();
        MultiRecipientDataSourceBuilder multi = MultiRecipientDataSourceBuilder.builder(session)
                // define our payload
                .payloadKeyBytes(32).withAes(payload)
                // one recipient
                .unlockWith(unlock);

        // Decryption
        DataContent dccb = DataContentChainBuilder.decrypt().add(PlainBytesBuilder.builder().bytes(encrypted))
                // decrypt via multi
                .add(multi).build();

        byte[] decrypted;
        try (InputStream decryptedStream = dccb.getStream()) {
            // Consume the decrypted data into memory
            decrypted = readAll(decryptedStream);
        }

        LOG.log(Level.INFO, "original message={0} after {2}/AES256/CBC/PKCS5 roundtrip={1}",
                new Object[] { Strings.toShortHexString(msg), Strings.toShortHexString(decrypted), method });
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
