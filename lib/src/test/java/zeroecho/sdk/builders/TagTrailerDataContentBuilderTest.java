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
package zeroecho.sdk.builders;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.aes.AesKeyGenSpec;
import zeroecho.core.alg.digest.DigestSpec;
import zeroecho.core.alg.ed25519.Ed25519KeyGenSpec;
import zeroecho.core.alg.kyber.KyberKeyGenSpec;
import zeroecho.core.alg.rsa.RsaEncSpec;
import zeroecho.core.alg.rsa.RsaKeyGenSpec;
import zeroecho.core.alg.rsa.RsaSigSpec;
import zeroecho.core.alg.sphincsplus.SphincsPlusKeyGenSpec;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.context.KemContext;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.KeyOperation;
import zeroecho.core.KeyOperationInfo;
import zeroecho.core.spi.AsymmetricKeyPairGenerator;
import zeroecho.core.spi.SymmetricKeyGenerator;
import zeroecho.core.tag.TagEngine;
import zeroecho.core.tag.TagEngineBuilder;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.alg.KemDataContentBuilder;
import zeroecho.sdk.builders.alg.RsaEncDataContentBuilder;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.builders.core.DataContentChainBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;
import zeroecho.sdk.guard.MultiRecipientDataSourceBuilder;
import zeroecho.sdk.guard.UnlockMaterial;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * Round-trip tests for TagTrailerDataContentBuilder placed INSIDE AES, RSA, and
 * KEM payloads using DataContentChainBuilder.
 *
 * Layout (ENCRYPT): Source -> TagTrailer(SHA-256) -> [AES|RSA|KEM payload]
 * Layout (DECRYPT): Source -> [AES|RSA|KEM payload] -> TagTrailer(verify)
 */
public class TagTrailerDataContentBuilderTest {

    // ---------- boilerplate logging ----------
    private static void logBegin(Object... params) {
        String thisClass = TagTrailerDataContentBuilderTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = TagTrailerDataContentBuilderTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logEnd"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "...ok");
    }

    @BeforeAll
    static void setup() {
        // Optional: enable BC if you use BC-only modes in KEM payloads (EAX/OCB/CCM,
        // etc.)
        try {
            BouncyCastleActivator.init();
        } catch (Throwable ignore) {
            // keep tests runnable without BC if not present
        }
    }

    // ---------- helpers ----------
    private static byte[] random(int n) {
        byte[] b = new byte[n];
        new Random().nextBytes(b);
        return b;
    }

    private static byte[] readAll(InputStream in) throws Exception {
        try (in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int r;
            while ((r = in.read(buf)) != -1) {
                out.write(buf, 0, r);
            }
            return out.toByteArray();
        }
    }

    /** Minimal source builder for tests. */
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
                    /* no upstream for sources */ }

                @Override
                public InputStream getStream() {
                    return new ByteArrayInputStream(data);
                }
            };
        }
    }

    // ---------- AES/GCM with TagTrailer (Ed25519 SIGNATURE) ----------
    @Test
    void tag_inside_aes_gcm_with_ed25519_signature_roundtrip() throws Exception {
        final int SIZE = 64 * 1024 + 11;
        logBegin("AES/GCM + TagTrailer(Ed25519)", SIZE);

        byte[] msg = random(SIZE);
        System.out.println("...msg=" + msg.length + " bytes");

        // AES key
        SecretKey aesKey = CryptoAlgorithms.require("AES").symmetricKeyGenerator(AesKeyGenSpec.class)
                .generateSecret(AesKeyGenSpec.aes256());

        // Ed25519 keys (JCA)
        KeyPair ed = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("Ed25519", Ed25519KeyGenSpec.defaultSpec());

        TagEngine<Signature> tagEnc = TagEngineBuilder.ed25519Sign(new zeroecho.sdk.ZeroEchoSession(), ed.getPrivate()).get();
        TagEngine<Signature> tagDec = TagEngineBuilder.ed25519Verify(new zeroecho.sdk.ZeroEchoSession(), ed.getPublic()).get();

        // ENCRYPT: body -> [body||signature] -> AES-GCM
        DataContent enc = DataContentChainBuilder.encrypt().add(BytesSourceBuilder.of(msg))
                .add(new TagTrailerDataContentBuilder<>(tagEnc).bufferSize(8192))
                .add(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withKey(aesKey).modeGcm(128).withHeader()).build();

        byte[] ct = readAll(enc.getStream());
        System.out.println("...ct=" + ct.length + " bytes");

        // DECRYPT: AES-GCM -> strip trailer -> verify Ed25519 at EOF
        DataContent dec = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(ct))
                .add(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withKey(aesKey).modeGcm(128).withHeader())
                .add(new TagTrailerDataContentBuilder<>(tagDec).bufferSize(8192).throwOnMismatch()).build();

        byte[] pt = readAll(dec.getStream());
        assertArrayEquals(msg, pt, "AES/GCM tag-in-payload (Ed25519) roundtrip mismatch");
        logEnd();
    }

    // ---------- AES/GCM with TagTrailer (SPHINCS+ SIGNATURE) ----------
    @Test
    void tag_inside_aes_gcm_with_sphincsplus_signature_roundtrip() throws Exception {
        final int SIZE = 64 * 1024 + 17;
        logBegin("AES/GCM + TagTrailer(SPHINCS+)", SIZE);

        byte[] msg = random(SIZE);
        System.out.println("...msg=" + msg.length + " bytes");

        // AES key
        SecretKey aesKey = CryptoAlgorithms.require("AES").symmetricKeyGenerator(AesKeyGenSpec.class)
                .generateSecret(AesKeyGenSpec.aes256());

        // SPHINCS+ key pair via registry (uses default param set from
        // SphincsPlusKeyGenSpec)
        KeyPair spx = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("SPHINCS+", SphincsPlusKeyGenSpec.defaultSpec());

        // Tag engines (SPHINCS+)
        TagEngine<Signature> tagEnc = TagEngineBuilder.sphincsPlusSign(new zeroecho.sdk.ZeroEchoSession(), spx.getPrivate()).get();
        TagEngine<Signature> tagDec = TagEngineBuilder.sphincsPlusVerify(new zeroecho.sdk.ZeroEchoSession(), spx.getPublic()).get();

        // ENCRYPT: body -> [body||spxSig] -> AES-GCM
        DataContent enc = DataContentChainBuilder.encrypt().add(BytesSourceBuilder.of(msg))
                .add(new TagTrailerDataContentBuilder<>(tagEnc).bufferSize(8192))
                .add(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withKey(aesKey).modeGcm(128).withHeader()).build();

        byte[] ct = readAll(enc.getStream());
        System.out.println("...ct=" + ct.length + " bytes");

        // DECRYPT: AES-GCM -> strip trailer -> verify SPHINCS+ at EOF
        DataContent dec = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(ct))
                .add(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withKey(aesKey).modeGcm(128).withHeader())
                .add(new TagTrailerDataContentBuilder<>(tagDec).bufferSize(8192).throwOnMismatch()).build();

        byte[] pt = readAll(dec.getStream());
        assertArrayEquals(msg, pt, "AES/GCM tag-in-payload (SPHINCS+) roundtrip mismatch");
        logEnd();
    }

    // ---------- AES/GCM with TagTrailer (RSA-PSS SIGNATURE) ----------
    @Test
    void tag_inside_aes_gcm_with_rsapss_signature_roundtrip() throws Exception {
        final int SIZE = 96 * 1024 + 3;
        logBegin("AES/GCM + TagTrailer(RSA-PSS)", SIZE);

        byte[] msg = random(SIZE);
        System.out.println("...msg=" + msg.length + " bytes");

        // AES key
        SecretKey aesKey = CryptoAlgorithms.require("AES").symmetricKeyGenerator(AesKeyGenSpec.class)
                .generateSecret(AesKeyGenSpec.aes256());

        // RSA-2048 keys (use registry for convenience)
        KeyPair rsa = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("RSA", RsaKeyGenSpec.rsa2048());

        // Tag engines (SHA-256, saltLen=32)
        RsaSigSpec pss = RsaSigSpec.pss(RsaSigSpec.Hash.SHA256, 32);
        TagEngine<Signature> tagEnc = TagEngineBuilder.rsaSign(new zeroecho.sdk.ZeroEchoSession(), rsa.getPrivate(), pss).get();
        TagEngine<Signature> tagDec = TagEngineBuilder.rsaVerify(new zeroecho.sdk.ZeroEchoSession(), rsa.getPublic(), pss).get();

        // ENCRYPT: body -> [body||pssSig] -> AES-GCM
        DataContent enc = DataContentChainBuilder.encrypt().add(BytesSourceBuilder.of(msg))
                .add(new TagTrailerDataContentBuilder<>(tagEnc).bufferSize(8192))
                .add(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withKey(aesKey).modeGcm(128).withHeader()).build();

        byte[] ct = readAll(enc.getStream());
        System.out.println("...ct=" + ct.length + " bytes");

        // DECRYPT: AES-GCM -> strip trailer -> verify PSS at EOF
        DataContent dec = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(ct))
                .add(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withKey(aesKey).modeGcm(128).withHeader())
                .add(new TagTrailerDataContentBuilder<>(tagDec).bufferSize(8192).throwOnMismatch()).build();

        byte[] pt = readAll(dec.getStream());
        assertArrayEquals(msg, pt, "AES/GCM tag-in-payload (RSA-PSS) roundtrip mismatch");
        logEnd();
    }

    // ---------- AES/GCM with TagTrailer (SHA-256) ----------

    @Test
    void tag_inside_aes_gcm_roundtrip() throws Exception {
        final int SIZE = 48 * 1024 + 7;
        logBegin("AES/GCM + TagTrailer", SIZE);

        byte[] msg = random(SIZE);
        System.out.println("...msg=" + msg.length + " bytes");

        // AES key up-front so decrypt can reuse it
        SymmetricKeyGenerator<AesKeyGenSpec> gen = CryptoAlgorithms.require("AES")
                .symmetricKeyGenerator(AesKeyGenSpec.class);
        SecretKey aesKey = gen.generateSecret(AesKeyGenSpec.aes256());

        // ENCRYPT: [source] -> [tag trailer] -> [aes gcm]
        DataContent encChain = DataContentChainBuilder.encrypt().add(BytesSourceBuilder.of(msg))
                .add(new TagTrailerDataContentBuilder<>(TagEngineBuilder.digest(new zeroecho.sdk.ZeroEchoSession(), DigestSpec.sha256())).bufferSize(8192))
                .add(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withKey(aesKey).modeGcm(128).withHeader()) // writes IV/AAD headers
                                                                                                // into stream
                .build();

        byte[] ciphertext = readAll(encChain.getStream());
        System.out.println("...ct=" + ciphertext.length + " bytes");

        // DECRYPT: [source(ct)] -> [aes gcm] -> [tag trailer verify]
        DataContent decChain = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(ciphertext))
                .add(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withKey(aesKey).modeGcm(128).withHeader()) // reads IV/AAD headers
                                                                                                // back
                .add(new TagTrailerDataContentBuilder<>(TagEngineBuilder.digest(new zeroecho.sdk.ZeroEchoSession(), DigestSpec.sha256())).bufferSize(8192)
                        .throwOnMismatch())
                .build();

        byte[] plain = readAll(decChain.getStream());
        assertArrayEquals(msg, plain, "AES/GCM tag-in-payload roundtrip mismatch");
        logEnd();
    }

    // ---------- RSA/OAEP with TagTrailer (keep body small; RSA is not a bulk
    // stream cipher) ----------

    @Test
    void tag_inside_rsa_oaep_roundtrip() throws Exception {
        final int SIZE = 96; // safe under RSA-2048 OAEP SHA-256 limit even with a 32-byte tag appended
        logBegin("RSA/OAEP + TagTrailer", SIZE);

        byte[] msg = "hello-".getBytes(StandardCharsets.UTF_8);
        msg = Arrays.copyOf(msg, SIZE); // pad deterministic length for the test
        System.out.println("...msg=" + msg.length + " bytes");

        KeyPair kp = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("RSA", RsaKeyGenSpec.rsa2048());

        // ENCRYPT: [source] -> [tag trailer] -> [rsa/oaep]
        DataContent enc = DataContentChainBuilder.encrypt().add(BytesSourceBuilder.of(msg))
                .add(new TagTrailerDataContentBuilder<>(TagEngineBuilder.digest(new zeroecho.sdk.ZeroEchoSession(), DigestSpec.sha256())).bufferSize(8192))
                .add(RsaEncDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).oaep(RsaEncSpec.Hash.SHA256).withPublicKey(kp.getPublic()))
                .build();

        byte[] ct = readAll(enc.getStream());
        System.out.println("...ct=" + ct.length + " bytes");

        // DECRYPT: [source(ct)] -> [rsa/oaep] -> [tag verify]
        DataContent dec = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(ct))
                .add(RsaEncDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).oaep(RsaEncSpec.Hash.SHA256).withPrivateKey(kp.getPrivate()))
                .add(new TagTrailerDataContentBuilder<>(TagEngineBuilder.digest(new zeroecho.sdk.ZeroEchoSession(), DigestSpec.sha256())).bufferSize(8192)
                        .throwOnMismatch())
                .build();

        byte[] pt = readAll(dec.getStream());
        assertArrayEquals(msg, pt, "RSA/OAEP tag-in-payload roundtrip mismatch");
        logEnd();
    }

    // ---------- KEM → AES/GCM payload with TagTrailer (skip if no KEM registered)
    // ----------

    @Test
    void tag_inside_kem_payload_roundtrip() throws Exception {
        final int SIZE = 32 * 1024 + 3;
        logBegin("KEM→AES/GCM + TagTrailer", SIZE);

        // Find a KEM we can use (e.g., "ML-KEM") with a working default spec.
        String kemId = findKemIdOrNull();
        if (kemId == null) {
            System.out.println("...*** SKIP *** no KEM algorithm registered");
            return;
        }

        CryptoAlgorithm kemAlg = CryptoAlgorithms.require(kemId);
        KeyPair kemKeys = tryKeyPairWithDefaultSpec(kemAlg);
        if (kemKeys == null) {
            System.out.println("...*** SKIP *** cannot generate KEM key pair");
            return;
        }

        byte[] msg = random(SIZE);
        System.out.println("...msg=" + msg.length + " bytes");

        // ENCRYPT: [source] -> [tag trailer] -> [KEM envelope with AES/GCM payload]
        AesDataContentBuilder aesEnc = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128) // 128-bit tag
                .withHeader(); // carry IV etc.

        DataContent enc = DataContentChainBuilder.encrypt().add(BytesSourceBuilder.of(msg))
                .add(new TagTrailerDataContentBuilder<>(TagEngineBuilder.digest(new zeroecho.sdk.ZeroEchoSession(), DigestSpec.sha256())).bufferSize(8192))
                .add(KemDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).kem(kemId).recipientPublic(kemKeys.getPublic()).derivedKeyBytes(32) // AES-256
                                                                                                                         // key
                                                                                                                         // derived
                                                                                                                         // from
                                                                                                                         // KEM
                                                                                                                         // secret
                        .hkdfSha256("KEM-tag-demo".getBytes(java.nio.charset.StandardCharsets.US_ASCII))
                        .withAes(aesEnc))
                .build();

        byte[] envelope = readAll(enc.getStream());
        System.out.println("...envelope=" + envelope.length + " bytes");

        // DECRYPT: [source(envelope)] -> [KEM] -> [tag verify]
        AesDataContentBuilder aesDec = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128).withHeader();

        DataContent dec = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(envelope))
                .add(KemDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).kem(kemId).recipientPrivate(kemKeys.getPrivate())
                        .derivedKeyBytes(32)
                        .hkdfSha256("KEM-tag-demo".getBytes(java.nio.charset.StandardCharsets.US_ASCII))
                        .withAes(aesDec))
                .add(new TagTrailerDataContentBuilder<>(TagEngineBuilder.digest(new zeroecho.sdk.ZeroEchoSession(), DigestSpec.sha256())).bufferSize(8192)
                        .throwOnMismatch())
                .build();

        byte[] pt = readAll(dec.getStream());
        assertArrayEquals(msg, pt, "KEM→GCM tag-in-payload roundtrip mismatch");
        logEnd();
    }

    // -------------------------------------------------------------------------
    // 1) AES-GCM payload, multi-recipient (RSA + Kyber + Password), tag trailer
    // -------------------------------------------------------------------------
    @Test
    void tag_trailer_inside_multi_recipient_aes_gcm_rsa_kem_password_roundtrip() throws Exception {
        final int SIZE = 96 * 1024 + 7;
        final char[] PASSWORD = "correct horse battery staple".toCharArray();

        logBegin(Integer.valueOf(SIZE), "AES-256/GCM + RSA + ML-KEM + password");

        // message
        byte[] msg = random(SIZE);
        System.out.println("...input=" + msg.length);

        // --- recipients ---
        // RSA
        KeyPair rsa = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("RSA", RsaKeyGenSpec.rsa2048());
        // ML-KEM (Kyber768 as a good mid-level)
        KeyPair kem = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        // --- symmetric payload (AES-256/GCM, tag 128) ---
        // IV length is handled internally (12 bytes for GCM) and persisted via header.
        AesDataContentBuilder aesEnc = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128).withHeader(); // write
                                                                                                  // IV/tagBits/AAD-hash
                                                                                                  // header for decrypt
                                                                                                  // side

        // --- tag trailer (SHA-256 digest as a trailer) ---
        TagTrailerDataContentBuilder<byte[]> tagEnc = new TagTrailerDataContentBuilder<>(
                TagEngineBuilder.digest(new zeroecho.sdk.ZeroEchoSession(), DigestSpec.sha256())).bufferSize(8192);

        EncryptionContext rsaEnc = new zeroecho.sdk.ZeroEchoSession().createContext("RSA", KeyUsage.ENCRYPT, rsa.getPublic());
        KemContext kybKem = new zeroecho.sdk.ZeroEchoSession().createContext("ML-KEM", KeyUsage.ENCAPSULATE, kem.getPublic());

        // --- envelope (ENCRYPT) with 3 recipients ---
        MultiRecipientDataSourceBuilder envEnc = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesEnc)
                // .addRsaOaepRecipient(rsa.getPublic()) // RSA-OAEP with SHA-256 MGF1
                // .addKemRecipient("ML-KEM", kem.getPublic(), 32 /* kekBytes */, 16 /*
                // hkdfSaltLen */)
                .addRecipient(rsaEnc) // new API call
                .addRecipient(kybKem, /* kekBytes */ 32, /* saltLen */ 32) // new API call
                .addPasswordRecipient(PASSWORD, 120_000 /* pbkdf2 iters */, 16 /* saltLen */, 32 /* kekBytes */);

        // Pipeline (encrypt): Bytes → Tag(trailer) → Multi-Recipient
        DataContent encTail = DataContentChainBuilder.encrypt().add(BytesSourceBuilder.of(msg)).add(tagEnc).add(envEnc)
                .build();

        byte[] encrypted = readAll(encTail.getStream());
        System.out.println("...encrypted=" + encrypted.length);

        // -------------- Decrypt three ways on the same ciphertext --------------

        // a) by RSA private key
        AesDataContentBuilder aesDecRsa = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128).withHeader(); // read header to
                                                                                                     // recover
                                                                                                     // IV/tagBits
        MultiRecipientDataSourceBuilder envDecRsa = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesDecRsa)
                .unlockWith(new UnlockMaterial.Private(rsa.getPrivate()));
        byte[] ptRsa = readAll(DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(encrypted)).add(envDecRsa)
                .add(new TagTrailerDataContentBuilder<>(TagEngineBuilder.digest(new zeroecho.sdk.ZeroEchoSession(), DigestSpec.sha256())).bufferSize(8192)
                        .throwOnMismatch())
                .build().getStream());
        System.out.println("...decrypted(RSA)=" + ptRsa.length);
        assertArrayEquals(msg, ptRsa, "RSA path failed to recover the original");

        // b) by KEM private key
        AesDataContentBuilder aesDecKem = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128).withHeader();
        MultiRecipientDataSourceBuilder envDecKem = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesDecKem)
                .unlockWith(new UnlockMaterial.Private(kem.getPrivate()));
        byte[] ptKem = readAll(DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(encrypted)).add(envDecKem)
                .add(new TagTrailerDataContentBuilder<>(TagEngineBuilder.digest(new zeroecho.sdk.ZeroEchoSession(), DigestSpec.sha256())).bufferSize(8192)
                        .throwOnMismatch())
                .build().getStream());
        System.out.println("...decrypted(KEM)=" + ptKem.length);
        assertArrayEquals(msg, ptKem, "KEM path failed to recover the original");

        // c) by password
        AesDataContentBuilder aesDecPwd = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128).withHeader();
        MultiRecipientDataSourceBuilder envDecPwd = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesDecPwd)
                .unlockWith(new UnlockMaterial.Password(PASSWORD));
        byte[] ptPwd = readAll(DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(encrypted)).add(envDecPwd)
                .add(new TagTrailerDataContentBuilder<>(TagEngineBuilder.digest(new zeroecho.sdk.ZeroEchoSession(), DigestSpec.sha256())).bufferSize(8192)
                        .throwOnMismatch())
                .build().getStream());
        System.out.println("...decrypted(PASSWORD)=" + ptPwd.length);
        assertArrayEquals(msg, ptPwd, "Password path failed to recover the original");

        logEnd();
    }

    // -------------------------------------------------------------------------
    // 2) AES-CBC payload (PKCS#7), RSA recipient only, tag trailer for integrity
    // -------------------------------------------------------------------------
    @Test
    void tag_trailer_inside_multi_recipient_aes_cbc_rsa_roundtrip() throws Exception {
        final int SIZE = 48 * 1024 + 321;

        logBegin(Integer.valueOf(SIZE), "AES-256/CBC + RSA");

        byte[] msg = random(SIZE);
        System.out.println("...input=" + msg.length);

        KeyPair rsa = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("RSA", RsaKeyGenSpec.rsa2048());

        // AES-256/CBC with header so IV/params are serialized by the AES stage
        AesDataContentBuilder aesCbc = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeCbcPkcs5().withHeader();

        TagTrailerDataContentBuilder<byte[]> tagEnc = new TagTrailerDataContentBuilder<>(
                TagEngineBuilder.digest(new zeroecho.sdk.ZeroEchoSession(), DigestSpec.sha256())).bufferSize(8192);

        TagTrailerDataContentBuilder<byte[]> tagDec = new TagTrailerDataContentBuilder<>(
                TagEngineBuilder.digest(new zeroecho.sdk.ZeroEchoSession(), DigestSpec.sha256())).bufferSize(8192)
                // explicit for clarity
                .throwOnMismatch();

        EncryptionContext rsaEnc = new zeroecho.sdk.ZeroEchoSession().createContext("RSA", KeyUsage.ENCRYPT, rsa.getPublic());

        // Envelope: recipient table (RSA-OAEP) + AES payload (CBC/PKCS7 with header)
        MultiRecipientDataSourceBuilder envEnc = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000))).withAes(aesCbc)
                // CEK length for AES-256
                .payloadKeyBytes(32)
                // .addRsaOaepRecipient(rsa.getPublic()); old API
                .addRecipient(rsaEnc);

        DataContent encTail = DataContentChainBuilder.encrypt().add(BytesSourceBuilder.of(msg))
                // append digest trailer BEFORE symmetric encryption
                .add(tagEnc).add(envEnc).build();

        byte[] encrypted = readAll(encTail.getStream());
        System.out.println("...encrypted=" + encrypted.length);

        MultiRecipientDataSourceBuilder envDec = MultiRecipientDataSourceBuilder.builder(new zeroecho.sdk.ZeroEchoSession().withPbkdf2Limits(new zeroecho.sdk.Pbkdf2Limits(1_000_000, 1_000_000)))
                .withAes(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeCbcPkcs5()
                        // must match encrypt side
                        .withHeader())
                .payloadKeyBytes(32).unlockWith(new UnlockMaterial.Private(rsa.getPrivate()));

        byte[] pt = readAll(DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(encrypted))
                // recover CEK via RSA-OAEP, then AES-CBC decrypt (reads header)
                .add(envDec)
                // strip & verify trailer
                .add(tagDec).build().getStream());

        System.out.println("...decrypted=" + pt.length);

        assertArrayEquals(msg, pt);
        logEnd();
    }

    // ---------- AES/GCM with TagTrailer (ECDSA P-256 SIGNATURE) ----------
    @Test
    void tag_inside_aes_gcm_with_ecdsa_p256_signature_roundtrip() throws Exception {
        final int SIZE = 64 * 1024 + 5;
        logBegin("AES/GCM + TagTrailer(ECDSA-P256)", SIZE);

        byte[] msg = random(SIZE);
        System.out.println("...msg=" + msg.length + " bytes");

        // AES key
        SecretKey aesKey = CryptoAlgorithms.require("AES").symmetricKeyGenerator(AesKeyGenSpec.class)
                .generateSecret(AesKeyGenSpec.aes256());

        // ECDSA P-256 keys (via your unified ECDSA algorithm)
        KeyPair ecdsa = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ECDSA", zeroecho.core.alg.ecdsa.EcdsaCurveSpec.P256);

        // Tag engines (ECDSA/P-256 using P1363 format, fixed 64-byte tag)
        TagEngine<Signature> tagEnc = TagEngineBuilder.ecdsaP256Sign(new zeroecho.sdk.ZeroEchoSession(), ecdsa.getPrivate()).get();
        TagEngine<Signature> tagDec = TagEngineBuilder.ecdsaP256Verify(new zeroecho.sdk.ZeroEchoSession(), ecdsa.getPublic()).get();

        // ENCRYPT: body -> [body||ecdsaSig] -> AES-GCM
        DataContent enc = DataContentChainBuilder.encrypt().add(BytesSourceBuilder.of(msg))
                .add(new TagTrailerDataContentBuilder<>(tagEnc).bufferSize(8192))
                .add(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withKey(aesKey).modeGcm(128).withHeader()).build();

        byte[] ct = readAll(enc.getStream());
        System.out.println("...ct=" + ct.length + " bytes");

        // DECRYPT: AES-GCM -> strip trailer -> verify ECDSA at EOF
        DataContent dec = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(ct))
                .add(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withKey(aesKey).modeGcm(128).withHeader())
                .add(new TagTrailerDataContentBuilder<>(tagDec).bufferSize(8192).throwOnMismatch()).build();

        byte[] pt = readAll(dec.getStream());
        assertArrayEquals(msg, pt, "AES/GCM tag-in-payload (ECDSA-P256) roundtrip mismatch");
        logEnd();
    }

    // ---------- small registry helpers ----------

    private static String findKemIdOrNull() {
        for (String id : CryptoAlgorithms.available()) {
            if (id.equalsIgnoreCase("ML-KEM") || id.equalsIgnoreCase("RSA-KEM") || id.toUpperCase().contains("KEM")) {
                return id;
            }
        }
        return null;
    }

    private static KeyPair tryKeyPairWithDefaultSpec(CryptoAlgorithm alg) {
        try {
            for (KeyOperationInfo bi : alg.keyOperations()) {
                if (bi.operation() != KeyOperation.ASYMMETRIC_KEY_PAIR_GENERATE || bi.defaultSpec() == null) {
                    continue;
                }
                @SuppressWarnings("unchecked")
                Class<AlgorithmKeySpec> specType = (Class<AlgorithmKeySpec>) bi.specType();
                AlgorithmKeySpec spec = bi.defaultSpec();
                AsymmetricKeyPairGenerator<AlgorithmKeySpec> b = alg.asymmetricKeyPairGenerator(specType);
                KeyPair kp = b.generateKeyPair(spec);
                if (kp != null) {
                    return kp;
                }
            }
        } catch (Throwable t) {
            // fall through → return null
        }
        return null;
    }
}
