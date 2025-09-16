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
package zeroecho.sdk.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link Kdf#hkdfSha256(byte[], byte[], byte[], int)} using RFC
 * 5869 test vectors.
 *
 * <h2>What is covered</h2>
 * <ul>
 * <li>RFC 5869 Appendix A.1, A.2, A.3 known-answer tests for HKDF-SHA-256 (OKM
 * only).</li>
 * <li>Behavior with {@code salt == null} vs. {@code salt.length == 0} (both
 * treated equivalently).</li>
 * <li>Input immutability (arguments are not modified).</li>
 * <li>Argument validation (empty IKM, invalid output length).</li>
 * </ul>
 */
public class KdfTest {

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.replaceAll("\\s+", ""));
    }

    @Test
    @DisplayName("RFC5869 A.1 - Basic test case with SHA-256")
    void rfc5869_caseA1() throws Exception {
        byte[] ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"); // 22 times 0x0b
        byte[] salt = hex("000102030405060708090a0b0c");
        byte[] info = hex("f0f1f2f3f4f5f6f7f8f9");
        int L = 42;

        byte[] okm = Kdf.hkdfSha256(ikm, salt, info, L);

        byte[] expectedOkm = hex(
                "3cb25f25faacd57a90434f64d0362f2a" + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" + "34007208d5b887185865");
        assertArrayEquals(expectedOkm, okm, "OKM must match RFC5869 A.1");
    }

    @Test
    @DisplayName("RFC5869 A.2 - Test with longer inputs/outputs")
    void rfc5869_caseA2() throws Exception {
        byte[] ikm = hex("000102030405060708090a0b0c0d0e0f" + "101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f" + "303132333435363738393a3b3c3d3e3f"
                + "404142434445464748494a4b4c4d4e4f"); // 0x00..0x4f (80 bytes)
        byte[] salt = hex("606162636465666768696a6b6c6d6e6f" + "707172737475767778797a7b7c7d7e7f"
                + "808182838485868788898a8b8c8d8e8f" + "909192939495969798999a9b9c9d9e9f"
                + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"); // 0x60..0xaf (80 bytes)
        byte[] info = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"); // 0xb0..0xff (80 bytes)
        int L = 82;

        byte[] okm = Kdf.hkdfSha256(ikm, salt, info, L);

        byte[] expectedOkm = hex("b11e398dc80327a1c8e7f78c596a4934" + "4f012eda2d4efad8a050cc4c19afa97c"
                + "59045a99cac7827271cb41c65e590e09" + "da3275600c2f09b8367793a9aca3db71"
                + "cc30c58179ec3e87c14c01d5c1f3434f" + "1d87");
        assertArrayEquals(expectedOkm, okm, "OKM must match RFC5869 A.2");
    }

    @Test
    @DisplayName("RFC5869 A.3 - Test with zero salt and empty info")
    void rfc5869_caseA3() throws Exception {
        byte[] ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"); // 22 times 0x0b
        byte[] salt = new byte[0]; // empty salt
        byte[] info = new byte[0]; // empty info
        int L = 42;

        byte[] okm = Kdf.hkdfSha256(ikm, salt, info, L);

        byte[] expectedOkm = hex(
                "8da4e775a563c18f715f802a063c5a31" + "b8a11f5c5ee1879ec3454e5f3c738d2d" + "9d201395faa4b61a96c8");
        assertArrayEquals(expectedOkm, okm, "OKM must match RFC5869 A.3");
    }

    @Test
    @DisplayName("salt == null behaves like empty salt")
    void nullSaltEqualsEmptySalt() throws Exception {
        byte[] ikm = "ikm".getBytes(StandardCharsets.US_ASCII);
        byte[] info = "info".getBytes(StandardCharsets.US_ASCII);

        byte[] a = Kdf.hkdfSha256(ikm, null, info, 32);
        byte[] b = Kdf.hkdfSha256(ikm, new byte[0], info, 32);
        assertArrayEquals(a, b, "null salt and empty salt must be equivalent");
    }

    @Test
    @DisplayName("Inputs are not mutated")
    void inputsAreNotMutated() throws Exception {
        byte[] ikm = hex("00112233aa55");
        byte[] salt = hex("a0a1a2a3");
        byte[] info = hex("b0b1");

        byte[] ikmCopy = ikm.clone();
        byte[] saltCopy = salt.clone();
        byte[] infoCopy = info.clone();

        Kdf.hkdfSha256(ikm, salt, info, 16);

        assertArrayEquals(ikmCopy, ikm, "IKM must not be modified");
        assertArrayEquals(saltCopy, salt, "salt must not be modified");
        assertArrayEquals(infoCopy, info, "info must not be modified");
    }

    @Test
    @DisplayName("Validation: empty IKM not allowed")
    void emptyIkmDisallowed() {
        assertThrows(IllegalArgumentException.class, () -> Kdf.hkdfSha256(new byte[0], null, null, 16));
    }

    @Test
    @DisplayName("Validation: output length must be within 1..(255*HashLen)")
    void invalidLengthsDisallowed() {
        byte[] ikm = hex("01");
        assertThrows(IllegalArgumentException.class, () -> Kdf.hkdfSha256(ikm, null, null, 0));
        assertThrows(IllegalArgumentException.class, () -> Kdf.hkdfSha256(ikm, null, null, 255 * 32 + 1));
    }

    @Test
    @DisplayName("Small sanity: different info yields different outputs")
    void differentInfoProducesDifferentOkm() throws Exception {
        byte[] ikm = "ikm".getBytes(StandardCharsets.US_ASCII);
        byte[] salt = "salt".getBytes(StandardCharsets.US_ASCII);
        byte[] info1 = "ctx1".getBytes(StandardCharsets.US_ASCII);
        byte[] info2 = "ctx2".getBytes(StandardCharsets.US_ASCII);

        byte[] okm1 = Kdf.hkdfSha256(ikm, salt, info1, 32);
        byte[] okm2 = Kdf.hkdfSha256(ikm, salt, info2, 32);

        assertNotEquals(HexFormat.of().formatHex(okm1), HexFormat.of().formatHex(okm2),
                "Distinct info should produce distinct OKM");
    }

    @Test
    @DisplayName("Idempotence for same inputs")
    void repeatability() throws Exception {
        byte[] ikm = "same-ikm".getBytes(StandardCharsets.US_ASCII);
        byte[] salt = "same-salt".getBytes(StandardCharsets.US_ASCII);
        byte[] info = "same-info".getBytes(StandardCharsets.US_ASCII);

        byte[] a = Kdf.hkdfSha256(ikm, salt, info, 48);
        byte[] b = Kdf.hkdfSha256(ikm, salt, info, 48);
        assertArrayEquals(a, b, "Same inputs must yield identical OKM");
    }

    @Test
    @DisplayName("Produces exact requested length")
    void exactLengthProduced() throws Exception {
        byte[] ikm = "ikm".getBytes(StandardCharsets.US_ASCII);
        for (int len : new int[] { 1, 16, 32, 33, 64, 100 }) {
            byte[] okm = Kdf.hkdfSha256(ikm, null, null, len);
            assertEquals(len, okm.length, "OKM length must equal requested length");
        }
    }

    @Test
    @DisplayName("Declared throws: GeneralSecurityException path is reachable")
    void macAlgorithmAvailable() throws Exception {
        // This test will fail only if HmacSHA256 is unavailable, which would throw
        // GeneralSecurityException.
        assertDoesNotThrow(() -> Kdf.hkdfSha256(new byte[] { 1, 2, 3 }, null, null, 32));
    }
}
