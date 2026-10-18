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
package zeroecho.core.alg.xwing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Properties;
import java.io.InputStream;

import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.KemContext;
import zeroecho.core.marshal.PairSeq;
import zeroecho.sdk.ZeroEchoSession;

class XWingBoundaryTest {
    @Test
    void internalKeyExportsCannotMutateRetainedMaterial() {
        byte[] seed = new byte[XWingPrivateKeySpec.SEED_LENGTH];
        byte[] encoded = new byte[XWingPublicKeySpec.RAW_LENGTH];
        XWingPrivateKey privateKey = new XWingPrivateKey(seed);
        XWingPublicKey publicKey = new XWingPublicKey(encoded);
        Arrays.fill(privateKey.rawSeed(), (byte) 1);
        Arrays.fill(publicKey.rawEncoded(), (byte) 1);
        assertArrayEquals(seed, privateKey.getEncoded());
        assertArrayEquals(encoded, publicKey.getEncoded());
        privateKey.destroy();
        assertThrows(IllegalStateException.class, privateKey::rawSeed);
    }

    @Test
    void decapsulatesIndependentDraftKnownAnswer() throws Exception {
        Properties vector = new Properties();
        try (InputStream input = XWingBoundaryTest.class.getResourceAsStream("draft-vector.properties")) {
            vector.load(java.util.Objects.requireNonNull(input));
        }
        HexFormat hex = HexFormat.of();
        ZeroEchoSession session = new ZeroEchoSession();
        PrivateKey key = session.keyBuilders().asymmetric().importPrivate("X-Wing",
                new XWingPrivateKeySpec(hex.parseHex(vector.getProperty("seed"))));
        PublicKey publicKey = session.keyBuilders().asymmetric().importPublic("X-Wing",
                new XWingPublicKeySpec(hex.parseHex(vector.getProperty("public"))));
        assertArrayEquals(hex.parseHex(vector.getProperty("public")), publicKey.getEncoded());
        try (KemContext context = session.createContext("X-Wing", KeyUsage.DECAPSULATE, key)) {
            assertArrayEquals(hex.parseHex(vector.getProperty("secret")),
                    context.decapsulate(hex.parseHex(vector.getProperty("ciphertext"))));
        }
        key.destroy();
    }

    @Test
    void rejectsInvalidEncodingLengthsIncludingPersistedInputs() {
        assertThrows(NullPointerException.class, () -> new XWingPublicKeySpec(null));
        assertThrows(NullPointerException.class, () -> new XWingPrivateKeySpec(null));
        for (int length : new int[] { 0, 1, 1215, 1217, 2432 }) {
            byte[] bytes = new byte[length];
            assertThrows(IllegalArgumentException.class, () -> new XWingPublicKeySpec(bytes));
            assertThrows(IllegalArgumentException.class, () -> XWingPublicKeySpec.unmarshal(
                    PairSeq.of("raw.b64", Base64.getEncoder().encodeToString(bytes))));
        }
        for (int length : new int[] { 0, 1, 31, 33, 64 }) {
            byte[] bytes = new byte[length];
            assertThrows(IllegalArgumentException.class, () -> new XWingPrivateKeySpec(bytes));
            assertThrows(IllegalArgumentException.class, () -> XWingPrivateKeySpec.unmarshal(
                    PairSeq.of("seed.b64", Base64.getEncoder().encodeToString(bytes))));
        }
        byte[] raw = new byte[1216];
        XWingPublicKeySpec publicSpec = new XWingPublicKeySpec(raw);
        raw[0] = 1;
        assertArrayEquals(new byte[1216], publicSpec.raw());
        publicSpec.raw()[0] = 2;
        assertArrayEquals(new byte[1216], publicSpec.raw());
        assertThrows(IllegalArgumentException.class, () -> XWingPublicKeySpec.unmarshal(
                PairSeq.of("raw.b64", "A".repeat(100_000))));
        assertThrows(IllegalArgumentException.class, () -> XWingPrivateKeySpec.unmarshal(
                PairSeq.of("seed.b64", "A".repeat(100_000))));
    }

    @Test
    void rejectsForeignKeysBeforeCreatingContext() {
        XWingAlgorithm algorithm = new XWingAlgorithm();
        PublicKey foreignPublic = new PublicKey() {
            public String getAlgorithm() { return "X-Wing"; }
            public String getFormat() { return "RAW"; }
            public byte[] getEncoded() { return new byte[1216]; }
        };
        PrivateKey foreignPrivate = new PrivateKey() {
            public String getAlgorithm() { return "X-Wing"; }
            public String getFormat() { return "RAW"; }
            public byte[] getEncoded() { return new byte[32]; }
        };
        assertThrows(IllegalArgumentException.class, () -> new XWingKemContext(algorithm, foreignPublic));
        assertThrows(IllegalArgumentException.class, () -> new XWingKemContext(algorithm, foreignPrivate));
        assertThrows(NullPointerException.class, () -> new XWingKemContext(algorithm, (PublicKey) null));
        assertThrows(NullPointerException.class, () -> new XWingKemContext(algorithm, (PrivateKey) null));
        assertThrows(NullPointerException.class, () -> new XWingKemContext(null, foreignPublic));
    }

    @Test
    void rejectsTruncatedAndExtendedCiphertexts() throws Exception {
        ZeroEchoSession session = new ZeroEchoSession();
        KeyPair pair = session.keyBuilders().asymmetric().generateKeyPair("X-Wing", XWingKeyGenSpec.DEFAULT);
        try (KemContext encrypt = session.createContext("X-Wing", KeyUsage.ENCAPSULATE, pair.getPublic());
                KemContext decrypt = session.createContext("X-Wing", KeyUsage.DECAPSULATE, pair.getPrivate())) {
            KemContext.KemResult result = encrypt.encapsulate();
            for (int length : new int[] { 0, 1, 1088, 1119, 1121, 2240 }) {
                byte[] changed = Arrays.copyOf(result.ciphertext(), length);
                assertThrows(IllegalArgumentException.class, () -> decrypt.decapsulate(changed));
            }
            assertThrows(IllegalArgumentException.class, () -> decrypt.decapsulate(null));
            assertArrayEquals(result.sharedSecret(), decrypt.decapsulate(result.ciphertext()));
            byte[] tampered = result.ciphertext().clone();
            tampered[0] ^= 1;
            org.junit.jupiter.api.Assertions.assertFalse(Arrays.equals(result.sharedSecret(), decrypt.decapsulate(tampered)));
            assertThrows(IllegalStateException.class, decrypt::encapsulate);
            assertThrows(IllegalStateException.class, () -> encrypt.decapsulate(result.ciphertext()));
        }
        pair.getPrivate().destroy();
        assertThrows(IllegalStateException.class,
                () -> new XWingKemContext(CryptoAlgorithms.require("X-Wing"), pair.getPrivate()));
    }
}
