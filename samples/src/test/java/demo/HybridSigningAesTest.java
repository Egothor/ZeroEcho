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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import zeroecho.core.alg.ed25519.Ed25519KeyGenSpec;
import zeroecho.core.alg.sphincsplus.SphincsPlusKeyGenSpec;
import zeroecho.core.context.SignatureContext;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.TagTrailerDataContentBuilder;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.core.DataContentChainBuilder;
import zeroecho.sdk.builders.core.PlainBytesBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.hybrid.signature.HybridSignatureContexts;
import zeroecho.sdk.hybrid.signature.HybridSignatureProfile;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * Demonstration of hybrid signing combined with AES-GCM encryption.
 *
 * <p>
 * This sample shows both canonical compositions:
 * <ul>
 * <li>StE: Sign-then-Encrypt</li>
 * <li>EtS: Encrypt-then-Sign</li>
 * </ul>
 * </p>
 *
 * <p>
 * Hybrid signature used here (popular practical choice): Ed25519 + SPHINCS+
 * with AND verification.
 * </p>
 */
@Tag("sample")
class HybridSigningAesTest {

    private static final Logger LOG = Logger.getLogger(HybridSigningAesTest.class.getName());

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

    @Test
    void aesRoundStE_withHybridSignature() throws GeneralSecurityException, IOException {
        LOG.info("aesRoundStE_withHybridSignature - Sign then Encrypt (Hybrid signature)");

        // Prepare plaintext
        byte[] msg = randomBytes(100);

        // AES-GCM with header, runtime params are stored in header
        AesDataContentBuilder aesBuilder = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                .generateKey(256).modeGcm(128).withHeader();

        // Hybrid signature: Ed25519 + SPHINCS+ (AND)
        HybridSignatureProfile profile = new HybridSignatureProfile("Ed25519", "SPHINCS+", null, null,
                HybridSignatureProfile.VerifyRule.AND);

        KeyPair ed = generateKeyPair("Ed25519");
        KeyPair spx = generateKeyPair("SPHINCS+");

        SignatureContext tagEnc = HybridSignatureContexts.sign(new zeroecho.sdk.ZeroEchoSession(), profile,
                ed.getPrivate(), spx.getPrivate(), 2 * 1024 * 1024);
        SignatureContext tagDec = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), profile,
                ed.getPublic(), spx.getPublic(), 2 * 1024 * 1024);

        // For verification, make mismatch behavior explicit (builder also supports
        // throwOnMismatch()).
        tagDec.setVerificationApproach(tagDec.getVerificationCore().getThrowOnMismatch());

        // Build StE pipeline: PLAIN -> SIGN(trailer) -> ENCRYPT
        DataContent dccb = DataContentChainBuilder.encrypt()
                // plaintext source
                .add(PlainBytesBuilder.builder().bytes(msg))
                // hybrid signature trailer
                .add(new TagTrailerDataContentBuilder<Signature>(tagEnc).bufferSize(8192))
                // AES-GCM encryption
                .add(aesBuilder).build();

        SecretKey aesKey = aesBuilder.generatedKey();
        LOG.log(Level.INFO, "StE: produced ciphertext, aesKeySizeBits={0}",
                Integer.valueOf(aesKey.getEncoded().length * 8));

        byte[] ciphertext;
        try (InputStream in = dccb.getStream()) {
            ciphertext = readAll(in);
        }
        LOG.log(Level.INFO, "StE: ciphertextSize={0}", Integer.valueOf(ciphertext.length));

        // Build decrypt pipeline: ENCRYPTED -> DECRYPT -> VERIFY(trailer)
        dccb = DataContentChainBuilder.decrypt()
                // encrypted input
                .add(PlainBytesBuilder.builder().bytes(ciphertext))
                // AES-GCM decryption
                .add(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).importKeyRaw(aesKey.getEncoded())
                        .modeGcm(128).withHeader())
                // hybrid signature verification
                .add(new TagTrailerDataContentBuilder<Signature>(tagDec).bufferSize(8192).throwOnMismatch()).build();

        byte[] decrypted;
        try (InputStream in = dccb.getStream()) {
            decrypted = readAll(in);
        }

        LOG.log(Level.INFO, "StE: roundtrip ok={0}", Boolean.valueOf(java.util.Arrays.equals(msg, decrypted)));
    }

    @Test
    void aesRoundEtS_withHybridSignature() throws GeneralSecurityException, IOException {
        LOG.info("aesRoundEtS_withHybridSignature - Encrypt then Sign (Hybrid signature)");

        // Prepare plaintext
        byte[] msg = randomBytes(100);

        // AES-GCM with header, runtime params are stored in header
        AesDataContentBuilder aesBuilder = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                .generateKey(256).modeGcm(128).withHeader();

        // Hybrid signature: Ed25519 + SPHINCS+ (AND)
        HybridSignatureProfile profile = new HybridSignatureProfile("Ed25519", "SPHINCS+", null, null,
                HybridSignatureProfile.VerifyRule.AND);

        KeyPair ed = generateKeyPair("Ed25519");
        KeyPair spx = generateKeyPair("SPHINCS+");

        SignatureContext tagEnc = HybridSignatureContexts.sign(new zeroecho.sdk.ZeroEchoSession(), profile,
                ed.getPrivate(), spx.getPrivate(), 2 * 1024 * 1024);
        SignatureContext tagDec = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), profile,
                ed.getPublic(), spx.getPublic(), 2 * 1024 * 1024);

        tagDec.setVerificationApproach(tagDec.getVerificationCore().getThrowOnMismatch());

        // Build EtS pipeline: PLAIN -> ENCRYPT -> SIGN(trailer)
        DataContent dccb = DataContentChainBuilder.encrypt()
                // plaintext source
                .add(PlainBytesBuilder.builder().bytes(msg))
                // AES-GCM encryption
                .add(aesBuilder)
                // hybrid signature trailer
                .add(new TagTrailerDataContentBuilder<Signature>(tagEnc).bufferSize(8192)).build();

        SecretKey aesKey = aesBuilder.generatedKey();
        LOG.log(Level.INFO, "EtS: produced ciphertext, aesKeySizeBits={0}",
                Integer.valueOf(aesKey.getEncoded().length * 8));

        byte[] ciphertext;
        try (InputStream in = dccb.getStream()) {
            ciphertext = readAll(in);
        }
        LOG.log(Level.INFO, "EtS: ciphertextSize={0}", Integer.valueOf(ciphertext.length));

        // Build decrypt pipeline: ENCRYPTED -> VERIFY(trailer) -> DECRYPT
        // Verification runs during streaming; consumer gets plaintext only if signature
        // matches.
        dccb = DataContentChainBuilder.decrypt()
                // encrypted input
                .add(PlainBytesBuilder.builder().bytes(ciphertext))
                // hybrid signature verification
                .add(new TagTrailerDataContentBuilder<Signature>(tagDec).bufferSize(8192).throwOnMismatch())
                // AES-GCM decryption
                .add(AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).importKeyRaw(aesKey.getEncoded())
                        .modeGcm(128).withHeader())
                .build();

        byte[] decrypted;
        try (InputStream in = dccb.getStream()) {
            decrypted = readAll(in);
        }

        LOG.log(Level.INFO, "EtS: roundtrip ok={0}", Boolean.valueOf(java.util.Arrays.equals(msg, decrypted)));
    }

    // helpers

    private static KeyPair generateKeyPair(String algId) throws GeneralSecurityException {
        ZeroEchoSession session = new ZeroEchoSession();
        return switch (algId) {
            case "Ed25519" ->
                session.keyBuilders().asymmetric().generateKeyPair(algId, Ed25519KeyGenSpec.defaultSpec());
            case "SPHINCS+" ->
                session.keyBuilders().asymmetric().generateKeyPair(algId, SphincsPlusKeyGenSpec.defaultSpec());
            default -> throw new IllegalArgumentException("Unsupported sample signature algorithm: " + algId);
        };
    }

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
