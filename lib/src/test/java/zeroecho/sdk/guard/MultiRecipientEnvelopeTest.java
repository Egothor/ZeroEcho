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
package zeroecho.sdk.guard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.function.Supplier;
import java.util.random.RandomGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.ed25519.Ed25519KeyGenSpec;
import zeroecho.core.alg.elgamal.ElgamalParamSpec;
import zeroecho.core.alg.kyber.KyberKeyGenSpec;
import zeroecho.core.alg.rsa.RsaKeyGenSpec;
import zeroecho.core.alg.sphincsplus.SphincsPlusKeyGenSpec;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.context.KemContext;
import zeroecho.core.tag.TagEngineBuilder;
import zeroecho.sdk.Pbkdf2Limits;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.TagTrailerDataContentBuilder;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.builders.core.DataContentChainBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;

/**
 * JDK21+ JUnit (no 'var') that prints sizes immediately after each stage: -
 * Password guardian - Single RSA recipient - Multi-recipient (Password + RSA +
 * ML-KEM) + optional ElGamal - AES-GCM and AES-CBC/PKCS7 Prints method name
 * (with params if any) at start, "...ok" at the end.
 */
public class MultiRecipientEnvelopeTest {

    @BeforeAll
    static void addProviders() {
        Security.addProvider(new BouncyCastlePQCProvider()); // ML-KEM
        Security.addProvider(new BouncyCastleProvider()); // extras
    }

    // ------------------------------------------------------------------------------------
    // Password guardian
    // ------------------------------------------------------------------------------------

    @Test
    @DisplayName("Password guardian + AES-256-GCM")
    void testPasswordGuardian_Aes256Gcm() throws Exception {
        final String method = "testPasswordGuardian_Aes256Gcm()";
        System.out.println(method);

        final byte[] input = randomInput(128 * 1024 + 7);
        System.out.println("... input size: " + input.length);

        final char[] password = "CorrectHorseBatteryStaple".toCharArray();

        // AES-256-GCM with header so IV/tag are persisted in-band
        Supplier<AesDataContentBuilder> aesGcm = () -> AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128).withHeader();

        // Encrypt
        MultiRecipientDataSourceBuilder enc = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get())
                .payloadKeyBytes(32)
                .addPasswordRecipient(password, /* iterations */ 10000, /* saltLen */ 16, /* kekBytes */ 32);

        DataContent encryptor = enc.build(true);
        encryptor.setInput(new BytesContent(input));

        byte[] encrypted;
        try (InputStream es = encryptor.getStream()) {
            encrypted = readAllBytesAndPrint(es, "... encrypted size");
        }

        // Decrypt
        UnlockMaterial.Password unlockMaterial = new UnlockMaterial.Password(password);
        MultiRecipientDataSourceBuilder dec = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get())
                .payloadKeyBytes(32).unlockWith(unlockMaterial);

        DataContent decryptor = dec.build(false);
        decryptor.setInput(new BytesContent(encrypted));

        byte[] decrypted;
        try (InputStream ds = decryptor.getStream()) {
            decrypted = readAllBytesAndPrint(ds, "... decrypted size");
        }

        assertArrayEquals(input, decrypted);
        assertFalse(unlockMaterial.isDestroyed());
        unlockMaterial.destroy();
        assertTrue(unlockMaterial.isDestroyed());
        System.out.println("... borrowed unlock material retained by caller");
        System.out.println("...ok");
    }

    @Test
    void passwordRecipientWithAes128KekRoundTrips() throws Exception {
        System.out.println("passwordRecipientWithAes128KekRoundTrips");
        byte[] input = randomInput(257);
        char[] password = "controlled-password".toCharArray();
        ZeroEchoSession session = new ZeroEchoSession()
                .withPbkdf2Limits(new Pbkdf2Limits(1_000_000, 1_000_000));
        byte[] encrypted;

        try (MultiRecipientDataSourceBuilder builder = MultiRecipientDataSourceBuilder.builder(session)
                .withAes(AesDataContentBuilder.builder(session).modeGcm(128).withHeader())
                .payloadKeyBytes(32)
                .addPasswordRecipient(password, 10_000, 16, 16);
                MultiRecipientContent content = builder.build(true)) {
            content.setInput(new BytesContent(input));
            try (InputStream stream = content.getStream()) {
                encrypted = stream.readAllBytes();
            }
        }

        UnlockMaterial.Password unlock = new UnlockMaterial.Password(password);
        byte[] decrypted;
        try (MultiRecipientDataSourceBuilder builder = MultiRecipientDataSourceBuilder.builder(session)
                .withAes(AesDataContentBuilder.builder(session).modeGcm(128).withHeader())
                .payloadKeyBytes(32)
                .unlockWith(unlock);
                MultiRecipientContent content = builder.build(false)) {
            content.setInput(new BytesContent(encrypted));
            try (InputStream stream = content.getStream()) {
                decrypted = stream.readAllBytes();
            }
        } finally {
            unlock.destroy();
            Arrays.fill(password, '\0');
        }

        assertArrayEquals(input, decrypted);
        System.out.println("...kekBytes=16");
        System.out.println("passwordRecipientWithAes128KekRoundTrips...ok");
    }

    @Test
    @DisplayName("Password guardian + AES-256-CBC/PKCS7")
    void testPasswordGuardian_Aes256Cbc() throws Exception {
        final String method = "testPasswordGuardian_Aes256Cbc()";
        System.out.println(method);

        final byte[] input = randomInput(128 * 1024 + 7);
        System.out.println("... input size: " + input.length);

        final char[] password = "Tr0ub4dor&3".toCharArray();

        // AES-256-CBC with PKCS7 padding, header persists IV
        Supplier<AesDataContentBuilder> aesCbc = () -> AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeCbcPkcs5().withHeader();

        MultiRecipientDataSourceBuilder enc = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesCbc.get())
                .payloadKeyBytes(32)
                .addPasswordRecipient(password, /* iterations */ 10000, /* saltLen */ 16, /* kekBytes */ 32);

        DataContent encryptor = enc.build(true);
        encryptor.setInput(new BytesContent(input));

        byte[] encrypted;
        try (InputStream es = encryptor.getStream()) {
            encrypted = readAllBytesAndPrint(es, "... encrypted size");
        }

        MultiRecipientDataSourceBuilder dec = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesCbc.get())
                .payloadKeyBytes(32).unlockWith(new UnlockMaterial.Password(password));

        DataContent decryptor = dec.build(false);
        decryptor.setInput(new BytesContent(encrypted));

        byte[] decrypted;
        try (InputStream ds = decryptor.getStream()) {
            decrypted = readAllBytesAndPrint(ds, "... decrypted size");
        }

        assertArrayEquals(input, decrypted);
        System.out.println("...ok");
    }

    // ------------------------------------------------------------------------------------
    // Single ElGamal recipient (via EncryptionContext)
    // ------------------------------------------------------------------------------------

    @Test
    @DisplayName("Single ElGamal(PKCS1 default) recipient + AES-256-GCM")
    void testSingleElgamalGuardian_Aes256Gcm() throws Exception {
        final String method = "testSingleElgamalGuardian_Aes256Gcm()";
        System.out.println(method);

        final byte[] input = randomInput(128 * 1024 + 7);
        System.out.println("... input size: " + input.length);

        KeyPair elg = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ElGamal", ElgamalParamSpec.ffdhe2048());
        EncryptionContext elgEnc = new zeroecho.sdk.ZeroEchoSession().createContext("ElGamal", KeyUsage.ENCRYPT, elg.getPublic());

        Supplier<AesDataContentBuilder> aesGcm = () -> AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128).withHeader();

        MultiRecipientDataSourceBuilder enc = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get())
                .payloadKeyBytes(32).addRecipient(elgEnc);

        DataContent encryptor = enc.build(true);
        encryptor.setInput(new BytesContent(input));

        byte[] encrypted;
        try (InputStream es = encryptor.getStream()) {
            encrypted = readAllBytesAndPrint(es, "... encrypted size");
        }

        MultiRecipientDataSourceBuilder dec = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get())
                .payloadKeyBytes(32).unlockWith(new UnlockMaterial.Private(elg.getPrivate()));

        DataContent decryptor = dec.build(false);
        decryptor.setInput(new BytesContent(encrypted));

        byte[] decrypted;
        try (InputStream ds = decryptor.getStream()) {
            decrypted = readAllBytesAndPrint(ds, "... decrypted size");
        }

        assertArrayEquals(input, decrypted);
        System.out.println("...ok");
    }

    @Test
    @DisplayName("Single ElGamal(PKCS1 default) recipient + AES-256-CBC")
    void testSingleElgamalGuardian_Aes256Cbc() throws Exception {
        final String method = "testSingleElgamalGuardian_Aes256Cbc()";
        System.out.println(method);

        final byte[] input = randomInput(128 * 1024 + 13); // cross blocks
        System.out.println("... input size: " + input.length);

        KeyPair elg = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ElGamal", ElgamalParamSpec.ffdhe2048());
        EncryptionContext elgEnc = new zeroecho.sdk.ZeroEchoSession().createContext("ElGamal", KeyUsage.ENCRYPT, elg.getPublic());

        Supplier<AesDataContentBuilder> aesCbc = () -> AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeCbcPkcs5().withHeader();

        MultiRecipientDataSourceBuilder enc = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesCbc.get())
                .payloadKeyBytes(32).addRecipient(elgEnc);

        DataContent encryptor = enc.build(true);
        encryptor.setInput(new BytesContent(input));

        byte[] encrypted;
        try (InputStream es = encryptor.getStream()) {
            encrypted = readAllBytesAndPrint(es, "... encrypted size");
        }

        MultiRecipientDataSourceBuilder dec = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesCbc.get())
                .payloadKeyBytes(32).unlockWith(new UnlockMaterial.Private(elg.getPrivate()));

        DataContent decryptor = dec.build(false);
        decryptor.setInput(new BytesContent(encrypted));

        byte[] pt;
        try (InputStream ds = decryptor.getStream()) {
            pt = readAllBytesAndPrint(ds, "... decrypted size");
        }

        assertArrayEquals(input, pt);
        System.out.println("...ok");
    }

    // ------------------------------------------------------------------------------------
    // Single RSA recipient (via EncryptionContext)
    // ------------------------------------------------------------------------------------

    @Test
    @DisplayName("Single RSA-OAEP(default) recipient + AES-256-GCM")
    void testSingleRsaGuardian_Aes256Gcm() throws Exception {
        final String method = "testSingleRsaGuardian_Aes256Gcm()";
        System.out.println(method);

        final byte[] input = randomInput(128 * 1024 + 7);
        System.out.println("... input size: " + input.length);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(3072, new SecureRandom());
        KeyPair rsa = kpg.generateKeyPair();

        EncryptionContext rsaEnc = new zeroecho.sdk.ZeroEchoSession().createContext("RSA", KeyUsage.ENCRYPT, rsa.getPublic());

        Supplier<AesDataContentBuilder> aesGcm = () -> AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128).withHeader();

        MultiRecipientDataSourceBuilder enc = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get())
                .payloadKeyBytes(32).addRecipient(rsaEnc);

        DataContent encryptor = enc.build(true);
        encryptor.setInput(new BytesContent(input));

        byte[] encrypted;
        try (InputStream es = encryptor.getStream()) {
            encrypted = readAllBytesAndPrint(es, "... encrypted size");
        }

        MultiRecipientDataSourceBuilder dec = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get())
                .payloadKeyBytes(32).unlockWith(new UnlockMaterial.Private(rsa.getPrivate()));

        DataContent decryptor = dec.build(false);
        decryptor.setInput(new BytesContent(encrypted));

        byte[] decrypted;
        try (InputStream ds = decryptor.getStream()) {
            decrypted = readAllBytesAndPrint(ds, "... decrypted size");
        }

        assertArrayEquals(input, decrypted);
        System.out.println("...ok");
    }

    @Test
    @DisplayName("Single RSA-OAEP(default) recipient + AES-256-CBC/PKCS7")
    void testSingleRsaGuardian_Aes256Cbc() throws Exception {
        final String method = "testSingleRsaGuardian_Aes256Cbc()";
        System.out.println(method);

        final byte[] input = randomInput(128 * 1024 + 7);
        System.out.println("... input size: " + input.length);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(3072, new SecureRandom());
        KeyPair rsa = kpg.generateKeyPair();

        EncryptionContext rsaEnc = new zeroecho.sdk.ZeroEchoSession().createContext("RSA", KeyUsage.ENCRYPT, rsa.getPublic());

        Supplier<AesDataContentBuilder> aesCbc = () -> AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeCbcPkcs5().withHeader();

        MultiRecipientDataSourceBuilder enc = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesCbc.get())
                .payloadKeyBytes(32).addRecipient(rsaEnc);

        DataContent encryptor = enc.build(true);
        encryptor.setInput(new BytesContent(input));

        byte[] encrypted;
        try (InputStream es = encryptor.getStream()) {
            encrypted = readAllBytesAndPrint(es, "... encrypted size");
        }

        MultiRecipientDataSourceBuilder dec = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesCbc.get())
                .payloadKeyBytes(32).unlockWith(new UnlockMaterial.Private(rsa.getPrivate()));

        DataContent decryptor = dec.build(false);
        decryptor.setInput(new BytesContent(encrypted));

        byte[] decrypted;
        try (InputStream ds = decryptor.getStream()) {
            decrypted = readAllBytesAndPrint(ds, "... decrypted size");
        }

        assertArrayEquals(input, decrypted);
        System.out.println("...ok");
    }

    // ------------------------------------------------------------------------------------
    // Multi-recipient (Password + RSA + KEM/ML-KEM + ElGamal) via contexts
    // ------------------------------------------------------------------------------------

    @Test
    void testKemRecipientWith128BitKekRoundTrip() throws Exception {
        System.out.println("testKemRecipientWith128BitKekRoundTrip");
        byte[] input = randomInput(257);
        KeyPair keyPair = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric()
                .generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber512());

        byte[] encrypted = encryptKemRecipients(input, new KeyPair[] { keyPair }, new int[] { 16 });
        decryptAndAssert("...128-bit KEK", aesGcmSupplier(), new UnlockMaterial.Private(keyPair.getPrivate()),
                input, encrypted);

        System.out.println("...encryptedLength=" + encrypted.length);
        System.out.println("testKemRecipientWith128BitKekRoundTrip...ok");
    }

    @Test
    void testMixedKemRecipientKekSizesRoundTrip() throws Exception {
        System.out.println("testMixedKemRecipientKekSizesRoundTrip");
        zeroecho.sdk.ZeroEchoSession session = new zeroecho.sdk.ZeroEchoSession();
        KeyPair first = session.keyBuilders().asymmetric()
                .generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber512());
        KeyPair second = session.keyBuilders().asymmetric()
                .generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber512());
        byte[] input = randomInput(513);

        byte[] encrypted = encryptKemRecipients(input, new KeyPair[] { first, second }, new int[] { 16, 32 });
        decryptAndAssert("...mixed 16-byte KEK", aesGcmSupplier(),
                new UnlockMaterial.Private(first.getPrivate()), input, encrypted);
        decryptAndAssert("...mixed 32-byte KEK", aesGcmSupplier(),
                new UnlockMaterial.Private(second.getPrivate()), input, encrypted);

        System.out.println("...recipientCount=2");
        System.out.println("testMixedKemRecipientKekSizesRoundTrip...ok");
    }

    @Test
    void defaultKemOpenerContinuesAfterSameAlgorithmDecoy() throws Exception {
        System.out.println("defaultKemOpenerContinuesAfterSameAlgorithmDecoy");
        ZeroEchoSession session = new ZeroEchoSession();
        KeyPair decoy = session.keyBuilders().asymmetric()
                .generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber512());
        KeyPair legitimate = session.keyBuilders().asymmetric()
                .generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber512());
        byte[] input = randomInput(385);
        byte[] encrypted;

        KemContext decoyContext =
                session.createContext("ML-KEM", KeyUsage.ENCAPSULATE, decoy.getPublic());
        KemContext legitimateContext =
                session.createContext("ML-KEM", KeyUsage.ENCAPSULATE, legitimate.getPublic());
        try (MultiRecipientDataSourceBuilder builder = MultiRecipientDataSourceBuilder.builder(session)
                .withAes(AesDataContentBuilder.builder(session).modeGcm(128).withHeader())
                .payloadKeyBytes(32)
                .addRecipient(decoyContext, 32, 16)
                .addRecipient(legitimateContext, 32, 16);
                MultiRecipientContent content = builder.build(true)) {
            content.setInput(new BytesContent(input));
            try (InputStream stream = content.getStream()) {
                encrypted = stream.readAllBytes();
            }
        }

        byte[] decrypted;
        try (MultiRecipientDataSourceBuilder builder = MultiRecipientDataSourceBuilder.builder(session)
                .withAes(AesDataContentBuilder.builder(session).modeGcm(128).withHeader())
                .payloadKeyBytes(32)
                .unlockWith(new UnlockMaterial.Private(legitimate.getPrivate()));
                MultiRecipientContent content = builder.build(false)) {
            content.setInput(new BytesContent(encrypted));
            try (InputStream stream = content.getStream()) {
                decrypted = stream.readAllBytes();
            }
        }

        assertArrayEquals(input, decrypted);
        System.out.println("...sameAlgorithmEntries=2");
        System.out.println("defaultKemOpenerContinuesAfterSameAlgorithmDecoy...ok");
    }

    @Test
    void defaultEncryptionOpenerContinuesAfterSameAlgorithmDecoy() throws Exception {
        System.out.println("defaultEncryptionOpenerContinuesAfterSameAlgorithmDecoy");
        ZeroEchoSession session = new ZeroEchoSession();
        KeyPair decoy = session.keyBuilders().asymmetric()
                .generateKeyPair("RSA", RsaKeyGenSpec.rsa2048());
        KeyPair legitimate = session.keyBuilders().asymmetric()
                .generateKeyPair("RSA", RsaKeyGenSpec.rsa2048());
        byte[] input = randomInput(385);
        byte[] encrypted;

        EncryptionContext decoyContext =
                session.createContext("RSA", KeyUsage.ENCRYPT, decoy.getPublic());
        EncryptionContext legitimateContext =
                session.createContext("RSA", KeyUsage.ENCRYPT, legitimate.getPublic());
        try (MultiRecipientDataSourceBuilder builder = MultiRecipientDataSourceBuilder.builder(session)
                .withAes(AesDataContentBuilder.builder(session).modeGcm(128).withHeader())
                .payloadKeyBytes(32)
                .addRecipient(decoyContext)
                .addRecipient(legitimateContext);
                MultiRecipientContent content = builder.build(true)) {
            content.setInput(new BytesContent(input));
            try (InputStream stream = content.getStream()) {
                encrypted = stream.readAllBytes();
            }
        }

        byte[] decrypted;
        try (MultiRecipientDataSourceBuilder builder = MultiRecipientDataSourceBuilder.builder(session)
                .withAes(AesDataContentBuilder.builder(session).modeGcm(128).withHeader())
                .payloadKeyBytes(32)
                .unlockWith(new UnlockMaterial.Private(legitimate.getPrivate()));
                MultiRecipientContent content = builder.build(false)) {
            content.setInput(new BytesContent(encrypted));
            try (InputStream stream = content.getStream()) {
                decrypted = stream.readAllBytes();
            }
        }

        assertArrayEquals(input, decrypted);
        System.out.println("...sameAlgorithmEntries=2");
        System.out.println("defaultEncryptionOpenerContinuesAfterSameAlgorithmDecoy...ok");
    }

    @Test
    @DisplayName("Multi recipients (PWD+RSA+ML-KEM kyber512+ElGamal) + AES-256-GCM")
    void testMultiRecipients_Kyber512_Aes256Gcm_AllUnlocks() throws Exception {
        final String method = "testMultiRecipients_Kyber512_Aes256Gcm_AllUnlocks()";
        System.out.println(method);

        final byte[] input = randomInput(128 * 1024 + 7);
        System.out.println("... input size: " + input.length);

        final char[] password = "group-secret".toCharArray();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(3072, new SecureRandom());
        KeyPair rsa = kpg.generateKeyPair();

        KeyPair kyber = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber512());
        KeyPair elg = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ElGamal", ElgamalParamSpec.ffdhe2048());

        EncryptionContext rsaEnc = new zeroecho.sdk.ZeroEchoSession().createContext("RSA", KeyUsage.ENCRYPT, rsa.getPublic());
        EncryptionContext elgEnc = new zeroecho.sdk.ZeroEchoSession().createContext("ElGamal", KeyUsage.ENCRYPT, elg.getPublic());
        KemContext kybKem = new zeroecho.sdk.ZeroEchoSession().createContext("ML-KEM", KeyUsage.ENCAPSULATE, kyber.getPublic());

        Supplier<AesDataContentBuilder> aesGcm = () -> AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128).withHeader();

        MultiRecipientDataSourceBuilder enc = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get())
                .payloadKeyBytes(32)
                .addPasswordRecipient(password, /* iterations */ 10000, /* saltLen */ 16, /* kekBytes */ 32)
                .addRecipient(rsaEnc).addRecipient(elgEnc).addRecipient(kybKem, /* kekBytes */ 32, /* saltLen */ 32);

        DataContent encryptor = enc.build(true);
        encryptor.setInput(new BytesContent(input));

        byte[] encrypted;
        try (InputStream es = encryptor.getStream()) {
            encrypted = readAllBytesAndPrint(es, "... encrypted size");
        }

        // Each unlock prints its decrypted size immediately
        decryptAndAssert("... decrypt via password", aesGcm, new UnlockMaterial.Password(password), input, encrypted);
        decryptAndAssert("... decrypt via RSA", aesGcm, new UnlockMaterial.Private(rsa.getPrivate()), input, encrypted);
        decryptAndAssert("... decrypt via ML-KEM", aesGcm, new UnlockMaterial.Private(kyber.getPrivate()), input,
                encrypted);
        decryptAndAssert("... decrypt via ElGamal", aesGcm, new UnlockMaterial.Private(elg.getPrivate()), input,
                encrypted);

        System.out.println("...ok");
    }

    @Test
    @DisplayName("Multi recipients (PWD+RSA+ML-KEM kyber768+ElGamal) + AES-256-CBC/PKCS7")
    void testMultiRecipients_Kyber768_Aes256Cbc_AllUnlocks() throws Exception {
        final String method = "testMultiRecipients_Kyber768_Aes256Cbc_AllUnlocks()";
        System.out.println(method);

        final byte[] input = randomInput(128 * 1024 + 7);
        System.out.println("... input size: " + input.length);

        final char[] password = "another-group-secret".toCharArray();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(3072, new SecureRandom());
        KeyPair rsa = kpg.generateKeyPair();

        rsa = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("RSA", RsaKeyGenSpec.rsa2048());
        KeyPair kyber = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());
        KeyPair elg = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ElGamal", ElgamalParamSpec.ffdhe2048());

        EncryptionContext rsaEnc = new zeroecho.sdk.ZeroEchoSession().createContext("RSA", KeyUsage.ENCRYPT, rsa.getPublic());
        EncryptionContext elgEnc = new zeroecho.sdk.ZeroEchoSession().createContext("ElGamal", KeyUsage.ENCRYPT, elg.getPublic());
        KemContext kybKem = new zeroecho.sdk.ZeroEchoSession().createContext("ML-KEM", KeyUsage.ENCAPSULATE, kyber.getPublic());

        Supplier<AesDataContentBuilder> aesCbc = () -> AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeCbcPkcs5().withHeader();

        MultiRecipientDataSourceBuilder enc = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesCbc.get())
                .payloadKeyBytes(32)
                .addPasswordRecipient(password, /* iterations */ 10000, /* saltLen */ 16, /* kekBytes */ 32)
                .addRecipient(rsaEnc).addRecipient(elgEnc).addRecipient(kybKem, /* kekBytes */ 32, /* saltLen */ 32);

        DataContent encryptor = enc.build(true);
        encryptor.setInput(new BytesContent(input));

        byte[] encrypted;
        try (InputStream es = encryptor.getStream()) {
            encrypted = readAllBytesAndPrint(es, "... encrypted size");
        }

        decryptAndAssert("... decrypt via password", aesCbc, new UnlockMaterial.Password(password), input, encrypted);
        decryptAndAssert("... decrypt via RSA", aesCbc, new UnlockMaterial.Private(rsa.getPrivate()), input, encrypted);
        decryptAndAssert("... decrypt via ML-KEM", aesCbc, new UnlockMaterial.Private(kyber.getPrivate()), input,
                encrypted);
        decryptAndAssert("... decrypt via ElGamal", aesCbc, new UnlockMaterial.Private(elg.getPrivate()), input,
                encrypted);

        System.out.println("...ok");
    }

    // ====================================================================================
    // Signed payload inside multi-recipient AES/GCM envelope (Ed25519 & SPHINCS+)
    // ====================================================================================

    @Test
    @DisplayName("Signed payload (Ed25519) → Multi-recipient envelope (RSA + ML-KEM + PWD + ElGamal) → AES-256-GCM")
    void testSignedPayload_Ed25519_MultiRecipients_AesGcm() throws Exception {
        final String method = "testSignedPayload_Ed25519_MultiRecipients_AesGcm()";
        System.out.println(method);

        final byte[] msg = randomInput(96 * 1024 + 13);
        System.out.println("... input size: " + msg.length);

        // Recipients
        final char[] password = "signed-group-secret".toCharArray();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(3072, new SecureRandom());
        KeyPair rsa = kpg.generateKeyPair();
        KeyPair kyber = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());
        KeyPair elg = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ElGamal", ElgamalParamSpec.ffdhe2048());

        // Sender signature keys (Ed25519)
        KeyPair ed = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("Ed25519", Ed25519KeyGenSpec.defaultSpec());

        // AES-256-GCM payload builder
        Supplier<AesDataContentBuilder> aesGcm = () -> AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128).withHeader();

        // Context recipients
        EncryptionContext rsaEnc = new zeroecho.sdk.ZeroEchoSession().createContext("RSA", KeyUsage.ENCRYPT, rsa.getPublic());
        EncryptionContext elgEnc = new zeroecho.sdk.ZeroEchoSession().createContext("ElGamal", KeyUsage.ENCRYPT, elg.getPublic());
        KemContext kybKem = new zeroecho.sdk.ZeroEchoSession().createContext("ML-KEM", KeyUsage.ENCAPSULATE, kyber.getPublic());

        // Envelope (encrypt)
        MultiRecipientDataSourceBuilder envEnc = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get())
                .payloadKeyBytes(32).addRecipient(rsaEnc).addRecipient(elgEnc)
                .addRecipient(kybKem, /* kekBytes */ 32, /* saltLen */ 16)
                .addPasswordRecipient(password, /* iterations */ 100_000, /* saltLen */ 16, /* kekBytes */ 32);

        // Tag trailer for SIGNING (Ed25519)
        TagTrailerDataContentBuilder<Signature> signTrailer = new TagTrailerDataContentBuilder<>(
                TagEngineBuilder.ed25519Sign(new zeroecho.sdk.ZeroEchoSession(), ed.getPrivate())).bufferSize(8192);

        // Encrypt chain
        DataContent encryptChain = DataContentChainBuilder.encrypt().add(BytesSourceBuilder.of(msg)).add(signTrailer)
                .add(envEnc).build();

        byte[] ciphertext;
        try (InputStream es = encryptChain.getStream()) {
            ciphertext = readAllBytesAndPrint(es, "... ciphertext size");
        }

        // Verify after each unlock
        TagTrailerDataContentBuilder<Signature> verifyTrailer;

        // via Password
        verifyTrailer = new TagTrailerDataContentBuilder<>(TagEngineBuilder.ed25519Verify(new zeroecho.sdk.ZeroEchoSession(), ed.getPublic()))
                .bufferSize(8192).throwOnMismatch();
        DataContent decPwd = DataContentChainBuilder
                .decrypt().add(BytesSourceBuilder.of(ciphertext)).add(MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000)))
                        .withAes(aesGcm.get()).payloadKeyBytes(32).unlockWith(new UnlockMaterial.Password(password)))
                .add(verifyTrailer).build();
        byte[] ptPwd;
        try (InputStream ds = decPwd.getStream()) {
            ptPwd = readAllBytesAndPrint(ds, "... decrypted via password");
        }
        assertArrayEquals(msg, ptPwd);

        // via RSA
        verifyTrailer = new TagTrailerDataContentBuilder<>(TagEngineBuilder.ed25519Verify(new zeroecho.sdk.ZeroEchoSession(), ed.getPublic()))
                .bufferSize(8192).throwOnMismatch();
        DataContent decRsa = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(ciphertext))
                .add(MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get()).payloadKeyBytes(32)
                        .unlockWith(new UnlockMaterial.Private(rsa.getPrivate())))
                .add(verifyTrailer).build();
        byte[] ptRsa;
        try (InputStream ds = decRsa.getStream()) {
            ptRsa = readAllBytesAndPrint(ds, "... decrypted via RSA");
        }
        assertArrayEquals(msg, ptRsa);

        // via ElGamal
        verifyTrailer = new TagTrailerDataContentBuilder<>(TagEngineBuilder.ed25519Verify(new zeroecho.sdk.ZeroEchoSession(), ed.getPublic()))
                .bufferSize(8192).throwOnMismatch();
        DataContent decElgamal = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(ciphertext))
                .add(MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get()).payloadKeyBytes(32)
                        .unlockWith(new UnlockMaterial.Private(elg.getPrivate())))
                .add(verifyTrailer).build();
        byte[] ptElgamal;
        try (InputStream ds = decElgamal.getStream()) {
            ptElgamal = readAllBytesAndPrint(ds, "... decrypted via ElGamal");
        }
        assertArrayEquals(msg, ptElgamal);

        // via ML-KEM
        verifyTrailer = new TagTrailerDataContentBuilder<>(TagEngineBuilder.ed25519Verify(new zeroecho.sdk.ZeroEchoSession(), ed.getPublic()))
                .bufferSize(8192).throwOnMismatch();
        DataContent decKem = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(ciphertext))
                .add(MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get()).payloadKeyBytes(32)
                        .unlockWith(new UnlockMaterial.Private(kyber.getPrivate())))
                .add(verifyTrailer).build();
        byte[] ptKem;
        try (InputStream ds = decKem.getStream()) {
            ptKem = readAllBytesAndPrint(ds, "... decrypted via ML-KEM");
        }
        assertArrayEquals(msg, ptKem);

        System.out.println("...ok");
    }

    @Test
    @DisplayName("Signed payload (SPHINCS+) → Multi-recipient envelope (RSA + ML-KEM + PWD + ElGamal) → AES-256-GCM")
    void testSignedPayload_SphincsPlus_MultiRecipients_AesGcm() throws Exception {
        final String method = "testSignedPayload_SphincsPlus_MultiRecipients_AesGcm()";
        System.out.println(method);

        final byte[] msg = randomInput(64 * 1024 + 19);
        System.out.println("... input size: " + msg.length);

        // Recipients
        final char[] password = "signed-group-secret-2".toCharArray();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(3072, new SecureRandom());
        KeyPair rsa = kpg.generateKeyPair();
        KeyPair kyber = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber512());
        KeyPair elg = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ElGamal", ElgamalParamSpec.ffdhe2048());

        // Sender signature keys (SPHINCS+, default/best)
        KeyPair spx = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("SPHINCS+", SphincsPlusKeyGenSpec.defaultSpec());

        Supplier<AesDataContentBuilder> aesGcm = () -> AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128).withHeader();

        // Context recipients
        EncryptionContext rsaEnc = new zeroecho.sdk.ZeroEchoSession().createContext("RSA", KeyUsage.ENCRYPT, rsa.getPublic());
        EncryptionContext elgEnc = new zeroecho.sdk.ZeroEchoSession().createContext("ElGamal", KeyUsage.ENCRYPT, elg.getPublic());
        KemContext kybKem = new zeroecho.sdk.ZeroEchoSession().createContext("ML-KEM", KeyUsage.ENCAPSULATE, kyber.getPublic());

        // Envelope recipients
        MultiRecipientDataSourceBuilder envEnc = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get())
                .payloadKeyBytes(32).addRecipient(rsaEnc).addRecipient(elgEnc)
                .addRecipient(kybKem, /* kekBytes */ 32, /* saltLen */ 16)
                .addPasswordRecipient(password, /* iterations */ 120_000, /* saltLen */ 16, /* kekBytes */ 32);

        // Tag trailer for SIGNING (SPHINCS+)
        TagTrailerDataContentBuilder<Signature> signTrailer = new TagTrailerDataContentBuilder<>(
                TagEngineBuilder.sphincsPlusSign(new zeroecho.sdk.ZeroEchoSession(), spx.getPrivate())).bufferSize(8192);

        // Encrypt chain
        DataContent encryptChain = DataContentChainBuilder.encrypt().add(BytesSourceBuilder.of(msg)).add(signTrailer)
                .add(envEnc).build();
        byte[] ciphertext;
        try (InputStream es = encryptChain.getStream()) {
            ciphertext = readAllBytesAndPrint(es, "... ciphertext size");
        }

        // Verify trailer with SPHINCS+ public key after each unlock
        TagTrailerDataContentBuilder<Signature> verifyTrailer;

        // via Password
        verifyTrailer = new TagTrailerDataContentBuilder<>(TagEngineBuilder.sphincsPlusVerify(new zeroecho.sdk.ZeroEchoSession(), spx.getPublic()))
                .bufferSize(8192).throwOnMismatch();
        DataContent decPwd = DataContentChainBuilder
                .decrypt().add(BytesSourceBuilder.of(ciphertext)).add(MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000)))
                        .withAes(aesGcm.get()).payloadKeyBytes(32).unlockWith(new UnlockMaterial.Password(password)))
                .add(verifyTrailer).build();
        byte[] ptPwd;
        try (InputStream ds = decPwd.getStream()) {
            ptPwd = readAllBytesAndPrint(ds, "... decrypted via password");
        }
        assertArrayEquals(msg, ptPwd);

        // via RSA
        verifyTrailer = new TagTrailerDataContentBuilder<>(TagEngineBuilder.sphincsPlusVerify(new zeroecho.sdk.ZeroEchoSession(), spx.getPublic()))
                .bufferSize(8192).throwOnMismatch();
        DataContent decRsa = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(ciphertext))
                .add(MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get()).payloadKeyBytes(32)
                        .unlockWith(new UnlockMaterial.Private(rsa.getPrivate())))
                .add(verifyTrailer).build();
        byte[] ptRsa;
        try (InputStream ds = decRsa.getStream()) {
            ptRsa = readAllBytesAndPrint(ds, "... decrypted via RSA");
        }
        assertArrayEquals(msg, ptRsa);

        // via ElGamal
        verifyTrailer = new TagTrailerDataContentBuilder<>(TagEngineBuilder.sphincsPlusVerify(new zeroecho.sdk.ZeroEchoSession(), spx.getPublic()))
                .bufferSize(8192).throwOnMismatch();
        DataContent decElgamal = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(ciphertext))
                .add(MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get()).payloadKeyBytes(32)
                        .unlockWith(new UnlockMaterial.Private(elg.getPrivate())))
                .add(verifyTrailer).build();
        byte[] ptElgamal;
        try (InputStream ds = decElgamal.getStream()) {
            ptElgamal = readAllBytesAndPrint(ds, "... decrypted via ElGamal");
        }
        assertArrayEquals(msg, ptElgamal);

        // via ML-KEM
        verifyTrailer = new TagTrailerDataContentBuilder<>(TagEngineBuilder.sphincsPlusVerify(new zeroecho.sdk.ZeroEchoSession(), spx.getPublic()))
                .bufferSize(8192).throwOnMismatch();
        DataContent decKem = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(ciphertext))
                .add(MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesGcm.get()).payloadKeyBytes(32)
                        .unlockWith(new UnlockMaterial.Private(kyber.getPrivate())))
                .add(verifyTrailer).build();
        byte[] ptKem;
        try (InputStream ds = decKem.getStream()) {
            ptKem = readAllBytesAndPrint(ds, "... decrypted via ML-KEM");
        }
        assertArrayEquals(msg, ptKem);

        System.out.println("...ok");
    }

    // ------------------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------------------

    private static byte[] encryptKemRecipients(byte[] input, KeyPair[] keyPairs, int[] kekSizes)
            throws Exception {
        zeroecho.sdk.ZeroEchoSession session = new zeroecho.sdk.ZeroEchoSession();
        MultiRecipientDataSourceBuilder builder = MultiRecipientDataSourceBuilder.builder(session)
                .withAes(aesGcmSupplier().get()).payloadKeyBytes(32);
        for (int index = 0; index < keyPairs.length; index++) {
            KemContext context = session.createContext("ML-KEM", KeyUsage.ENCAPSULATE,
                    keyPairs[index].getPublic());
            builder.addRecipient(context, kekSizes[index], 16);
        }
        DataContent encryptor = builder.build(true);
        encryptor.setInput(new BytesContent(input));
        try (InputStream stream = encryptor.getStream()) {
            return stream.readAllBytes();
        }
    }

    private static Supplier<AesDataContentBuilder> aesGcmSupplier() {
        return () -> AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                .modeGcm(128).withHeader();
    }

    /** Minimal source builder so we can compose pull-style chains. */
    private static final class BytesSourceBuilder implements DataContentBuilder<PlainContent> {
        private final byte[] data;

        private BytesSourceBuilder(byte[] data) {
            this.data = data.clone();
        }

        static BytesSourceBuilder of(byte[] data) {
            return new BytesSourceBuilder(data);
        }

        @Override
        public PlainContent build(boolean encrypt) {
            return new PlainContent() {
                @Override
                public void setInput(DataContent input) {
                    /* source: no upstream */ }

                @Override
                public InputStream getStream() {
                    return new ByteArrayInputStream(data);
                }
            };
        }
    }

    private static void decryptAndAssert(String banner, Supplier<AesDataContentBuilder> aesFactory,
            UnlockMaterial material, byte[] original, byte[] encrypted) throws IOException {
        MultiRecipientDataSourceBuilder dec = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesFactory.get())
                .payloadKeyBytes(32).unlockWith(material);

        DataContent decryptor = dec.build(false);
        decryptor.setInput(new BytesContent(encrypted));

        byte[] decrypted;
        try (InputStream ds = decryptor.getStream()) {
            decrypted = readAllBytesAndPrint(ds, banner + " -> size");
        }
        assertArrayEquals(original, decrypted);
    }

    /** Reads all bytes and prints the size in a finally block. */
    private static byte[] readAllBytesAndPrint(InputStream in, String label) throws IOException {
        byte[] result = new byte[0];
        try {
            result = in.readAllBytes();
            return result;
        } finally {
            System.out.println(label + ": " + result.length);
        }
    }

    private static byte[] randomInput(int size) {
        byte[] data = new byte[size];
        RandomGenerator rng = RandomGenerator.of("L64X256MixRandom");
        rng.nextBytes(data);
        return data;
    }

    /** Minimal PlainContent over a byte[]. */
    private static final class BytesContent implements PlainContent {
        private final byte[] data;

        BytesContent(byte[] data) {
            this.data = data;
        }

        @Override
        public InputStream getStream() throws IOException {
            return new ByteArrayInputStream(data);
        }
    }
}
