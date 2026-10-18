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
package zeroecho.sdk.hybrid.derived;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.alg.ChaChaDataContentBuilder;
import zeroecho.sdk.builders.alg.HmacDataContentBuilder;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.builders.core.DataContentChainBuilder;
import zeroecho.sdk.builders.core.PlainBytesBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.hybrid.kex.HybridKexExporter;

/**
 * Coverage tests for {@link HybridDerived} derived-material application
 * helpers.
 *
 * <p>
 * The tests use deterministic exporter inputs (fixed OKM and salt) to ensure
 * stable results.
 * </p>
 */
public class HybridDerivedTest {

    @Test
    void aes_gcm_applyTo_roundtrip() throws Exception {
        System.out.println("aes_gcm_applyTo_roundtrip()");
        HybridKexExporter exporter = testExporter();

        byte[] transcript = "demo-transcript".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "aad".getBytes(StandardCharsets.UTF_8);
        byte[] msg = fixedBytes(1024, (byte) 0x5A);

        AesDataContentBuilder encAes = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withHeader()
                .modeGcm(128);

        AesDataContentBuilder returnedEnc = HybridDerived.from(exporter).label("app/enc/aes").transcript(transcript)
                .aad(aad).applyToAesGcm(encAes, 256);

        System.out.println("...returnedEncSame=" + (returnedEnc == encAes));
        assertSame(encAes, returnedEnc);

        byte[] ciphertext = runEncrypt(encAes, msg);
        System.out.println("...ciphertextLen=" + ciphertext.length);
        System.out.println("...ciphertextPrefix=" + shortHex(ciphertext, 32));

        AesDataContentBuilder decAes = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withHeader()
                .modeGcm(128);

        HybridDerived.from(exporter).label("app/enc/aes").transcript(transcript).aad(aad).applyToAesGcm(decAes, 256);

        byte[] out = runDecrypt(decAes, ciphertext);
        System.out.println("...outPrefix=" + shortHex(out, 32));

        assertArrayEquals(msg, out);
        System.out.println("aes_gcm_applyTo_roundtrip...ok");
    }

    @Test
    void aes_gcm_applyTo_negative_label_mismatch() throws Exception {
        System.out.println("aes_gcm_applyTo_negative_label_mismatch()");
        HybridKexExporter exporter = testExporter();

        byte[] transcript = "demo-transcript".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "aad".getBytes(StandardCharsets.UTF_8);
        byte[] msg = fixedBytes(256, (byte) 0x1C);

        AesDataContentBuilder encAes = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withHeader()
                .modeGcm(128);

        HybridDerived.from(exporter).label("app/enc/aes").transcript(transcript).aad(aad).applyToAesGcm(encAes, 256);

        byte[] ciphertext = runEncrypt(encAes, msg);
        System.out.println("...ciphertextLen=" + ciphertext.length);

        AesDataContentBuilder decAesWrong = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                .withHeader().modeGcm(128);

        // ...label mismatch -> wrong key/iv/aad -> decryption must fail
        HybridDerived.from(exporter).label("app/enc/aes_WRONG").transcript(transcript).aad(aad)
                .applyToAesGcm(decAesWrong, 256);

        assertThrows(Exception.class, () -> runDecrypt(decAesWrong, ciphertext));

        System.out.println("aes_gcm_applyTo_negative_label_mismatch...ok");
    }

    @Test
    void chacha_aead_applyTo_roundtrip() throws Exception {
        System.out.println("chacha_aead_applyTo_roundtrip()");
        HybridKexExporter exporter = testExporter();

        byte[] transcript = "demo-transcript".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "aad".getBytes(StandardCharsets.UTF_8);
        byte[] msg = fixedBytes(777, (byte) 0x33);

        ChaChaDataContentBuilder encChaCha = ChaChaDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                .withHeader();

        ChaChaDataContentBuilder returnedEnc = HybridDerived.from(exporter).label("app/enc/chacha")
                .transcript(transcript).aad(aad).applyToChaChaAead(encChaCha, 256);

        System.out.println("...returnedEncSame=" + (returnedEnc == encChaCha));
        assertSame(encChaCha, returnedEnc);

        byte[] ciphertext = runEncrypt(encChaCha, msg);
        System.out.println("...ciphertextLen=" + ciphertext.length);
        System.out.println("...ciphertextPrefix=" + shortHex(ciphertext, 32));

        ChaChaDataContentBuilder decChaCha = ChaChaDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                .withHeader();

        HybridDerived.from(exporter).label("app/enc/chacha").transcript(transcript).aad(aad)
                .applyToChaChaAead(decChaCha, 256);

        byte[] out = runDecrypt(decChaCha, ciphertext);
        System.out.println("...outPrefix=" + shortHex(out, 32));

        assertArrayEquals(msg, out);
        System.out.println("chacha_aead_applyTo_roundtrip...ok");
    }

    @Test
    void hmac_applyTo_default_and_override() throws Exception {
        System.out.println("hmac_applyTo_default_and_override()");
        HybridKexExporter exporter = testExporter();

        byte[] transcript = "demo-transcript".getBytes(StandardCharsets.UTF_8);
        byte[] msg = fixedBytes(2048, (byte) 0x7E);

        // --------------------
        // Default key size path: applyToHmac(hmac) derives key using builder's
        // recommended bits
        // --------------------

        HmacDataContentBuilder macBuilder = HmacDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).sha256()
                .emitHexTag();

        int recommendedBits = macBuilder.recommendedKeyBits();
        System.out.println("...recommendedBits=" + recommendedBits);

        HybridDerived.from(exporter).label("app/mac/hmac-default").transcript(transcript).applyToHmac(macBuilder);

        String tagHex = runHmacHex(macBuilder, msg);
        System.out.println("...tagHexPrefix=" + shortText(tagHex, 64));

        HmacDataContentBuilder verifyBuilder = HmacDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                .sha256().expectedTagHex(tagHex).emitVerificationBoolean();

        HybridDerived.from(exporter).label("app/mac/hmac-default").transcript(transcript).applyToHmac(verifyBuilder);

        String ok = runHmacVerifyBool(verifyBuilder, msg);
        System.out.println("...verifyBool=" + ok);
        assertEquals("true", ok);

        // --------------------
        // Override key size path: applyToHmac(hmac, keyBits)
        // --------------------

        HmacDataContentBuilder macBuilderOv = HmacDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                .sha256().emitHexTag();

        // ...override to 512-bit keying material (still valid for HMAC; explicit expert
        // choice)
        HybridDerived.from(exporter).label("app/mac/hmac-override").transcript(transcript).applyToHmac(macBuilderOv,
                512);

        String tagHexOv = runHmacHex(macBuilderOv, msg);
        System.out.println("...tagHexOvPrefix=" + shortText(tagHexOv, 64));

        HmacDataContentBuilder verifyBuilderOv = HmacDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession())
                .sha256().expectedTagHex(tagHexOv).emitVerificationBoolean();

        HybridDerived.from(exporter).label("app/mac/hmac-override").transcript(transcript).applyToHmac(verifyBuilderOv,
                512);

        String okOv = runHmacVerifyBool(verifyBuilderOv, msg);
        System.out.println("...verifyBoolOv=" + okOv);
        assertEquals("true", okOv);

        // --------------------
        // Negative: wrong expected tag -> must emit "false"
        // --------------------

        HmacDataContentBuilder verifyBad = HmacDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).sha256()
                .expectedTagHex(tagHex.substring(0, Math.max(0, tagHex.length() - 2)) + "00").emitVerificationBoolean();

        HybridDerived.from(exporter).label("app/mac/hmac-default").transcript(transcript).applyToHmac(verifyBad);

        String bad = runHmacVerifyBool(verifyBad, msg);
        System.out.println("...verifyBoolBad=" + bad);
        assertEquals("false", bad);

        // sanity: ensure the two tags differ (default vs override label/key schedule)
        assertTrue(!tagHex.equals(tagHexOv));

        System.out.println("hmac_applyTo_default_and_override...ok");
    }

    // --------------------
    // helpers
    // --------------------

    private static HybridKexExporter testExporter() {
        byte[] okm = fixedBytes(32, (byte) 0x11);
        byte[] salt = fixedBytes(32, (byte) 0x22);
        return new HybridKexExporter(okm, salt);
    }

    private static byte[] runEncrypt(DataContentBuilder<DataContent> algorithmBuilder, byte[] plaintext)
            throws Exception {
        DataContent enc = DataContentChainBuilder.encrypt().add(PlainBytesBuilder.builder().bytes(plaintext))
                .add(algorithmBuilder).build();

        try (InputStream in = enc.getStream()) {
            return readAll(in);
        }
    }

    private static byte[] runDecrypt(DataContentBuilder<DataContent> algorithmBuilder, byte[] ciphertext)
            throws Exception {
        DataContent dec = DataContentChainBuilder.decrypt().add(PlainBytesBuilder.builder().bytes(ciphertext))
                .add(algorithmBuilder).build();

        try (InputStream in = dec.getStream()) {
            return readAll(in);
        }
    }

    private static String runHmacHex(HmacDataContentBuilder macBuilder, byte[] msg) throws Exception {
        DataContent dc = DataContentChainBuilder.encrypt().add(PlainBytesBuilder.builder().bytes(msg)).add(macBuilder)
                .build();

        byte[] out;
        try (InputStream in = dc.getStream()) {
            out = readAll(in);
        }
        String tagHex = new String(out, StandardCharsets.UTF_8).trim();
        return tagHex;
    }

    private static String runHmacVerifyBool(HmacDataContentBuilder verifyBuilder, byte[] msg) throws Exception {
        DataContent dc = DataContentChainBuilder.decrypt().add(PlainBytesBuilder.builder().bytes(msg))
                .add(verifyBuilder).build();

        byte[] out;
        try (InputStream in = dc.getStream()) {
            out = readAll(in);
        }
        String s = new String(out, StandardCharsets.UTF_8).trim();
        return s;
    }

    private static byte[] fixedBytes(int len, byte v) {
        byte[] b = new byte[len];
        Arrays.fill(b, v);
        return b;
    }

    private static byte[] readAll(InputStream in) throws Exception {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            in.transferTo(out);
            out.flush();
            return out.toByteArray();
        }
    }

    private static String shortHex(byte[] data, int maxBytes) {
        if (data == null) {
            return "null";
        }
        int n = Math.min(data.length, Math.max(0, maxBytes));
        StringBuilder sb = new StringBuilder(n * 2 + 3);
        for (int i = 0; i < n; i++) {
            int v = data[i] & 0xFF;
            sb.append(Character.forDigit(v >>> 4, 16));
            sb.append(Character.forDigit(v & 0x0F, 16));
        }
        if (data.length > n) {
            sb.append("...");
        }
        return sb.toString();
    }

    private static String shortText(String s, int maxLen) {
        if (s == null) {
            return "null";
        }
        if (s.length() <= maxLen) {
            return s;
        }
        return s.substring(0, maxLen) + "...";
    }

    @SuppressWarnings("unused")
    private static byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        new SecureRandom().nextBytes(b);
        return b;
    }
}
