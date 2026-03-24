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
package zeroecho.core.alg.mldsa;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.io.TailStrippingInputStream;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * Large-data streaming test for ML-DSA integration.
 *
 * <p>
 * Follows project rule "10) JUnit testy": prints test name, prints intermediate
 * results with the {@code "..."} prefix, and prints {@code "...ok"} on success.
 * </p>
 *
 * @since 1.0
 */
public final class MldsaLargeDataTest {

    private static final String INDENT = "...";
    private static final int MAX_HEX_BYTES = 32;

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

    /**
     * Executes the complete ML-DSA parameter set suite in streaming mode.
     *
     * @throws Exception on test failure
     */
    @Test
    void mldsa_complete_suite_streaming_sign_verify_large_data() throws Exception {
        System.out.println("mldsa_complete_suite_streaming_sign_verify_large_data");

        if (!CryptoAlgorithms.available().contains("ML-DSA")) {
            System.out.println(INDENT + " *** SKIP *** ML-DSA not registered");
            System.out.println(INDENT + "ok");
            return;
        }

        byte[] msg = randomBytes(48 * 1024 + 123);
        System.out.println(INDENT + " msg.len=" + msg.length);
        System.out.println(INDENT + " msg.hex=" + hexTruncated(msg, MAX_HEX_BYTES));

        runCase(msg, MldsaKeyGenSpec.ParameterSet.ML_DSA_44, MldsaKeyGenSpec.PreHash.NONE);
        runCase(msg, MldsaKeyGenSpec.ParameterSet.ML_DSA_65, MldsaKeyGenSpec.PreHash.NONE);
        runCase(msg, MldsaKeyGenSpec.ParameterSet.ML_DSA_87, MldsaKeyGenSpec.PreHash.NONE);

        runCase(msg, MldsaKeyGenSpec.ParameterSet.ML_DSA_44, MldsaKeyGenSpec.PreHash.SHA512);
        runCase(msg, MldsaKeyGenSpec.ParameterSet.ML_DSA_65, MldsaKeyGenSpec.PreHash.SHA512);
        runCase(msg, MldsaKeyGenSpec.ParameterSet.ML_DSA_87, MldsaKeyGenSpec.PreHash.SHA512);

        System.out.println(INDENT + "ok");
    }

    private static void runCase(byte[] msg, MldsaKeyGenSpec.ParameterSet ps, MldsaKeyGenSpec.PreHash preHash)
            throws Exception {

        MldsaKeyGenSpec spec = MldsaKeyGenSpec.of("BC", ps, preHash);

        String caseId = "ML-DSA " + ps.name() + " preHash=" + preHash.name();
        System.out.println(INDENT + " case=" + safeText(caseId));

        KeyPair kp = CryptoAlgorithms.keyPair("ML-DSA", spec);

        SignatureContext mldsaVerifier = CryptoAlgorithms.create("ML-DSA", KeyUsage.VERIFY, kp.getPublic());
        int expectedSigLen = mldsaVerifier.tagLength();
        System.out.println(INDENT + " expectedSigLen=" + expectedSigLen);

        SignatureContext signer = CryptoAlgorithms.create("ML-DSA", KeyUsage.SIGN, kp.getPrivate());

        final byte[][] sigHolder = new byte[1][];
        byte[] passthrough;
        try (InputStream in = new TailStrippingInputStream(signer.wrap(new ByteArrayInputStream(msg)), expectedSigLen,
                8192) {
            @Override
            protected void processTail(byte[] tail) throws IOException {
                sigHolder[0] = (tail == null) ? null : Arrays.copyOf(tail, tail.length);
            }
        }) {
            passthrough = readAll(in);
        } finally {
            try {
                signer.close();
            } catch (Exception ignore) {
            }
        }

        assertArrayEquals(msg, passthrough, "SIGN passthrough mismatch");

        byte[] signature = sigHolder[0];
        assertNotNull(signature, "signature trailer missing");

        System.out.println(INDENT + " signature.len=" + signature.length);
        System.out.println(INDENT + " signature.hex=" + hexTruncated(signature, MAX_HEX_BYTES));

        if (signature.length != expectedSigLen) {
            try {
                mldsaVerifier.close();
            } catch (Exception ignore) {
            }
            throw new AssertionError(
                    "Signature length mismatch: got=" + signature.length + " expected=" + expectedSigLen);
        }

        mldsaVerifier.setExpectedTag(Arrays.copyOf(signature, signature.length));

        byte[] verifyOut;
        try (InputStream verIn = mldsaVerifier.wrap(new ByteArrayInputStream(msg))) {
            verifyOut = readAll(verIn);
        } finally {
            try {
                mldsaVerifier.close();
            } catch (Exception ignore) {
            }
        }

        assertArrayEquals(msg, verifyOut, "VERIFY passthrough mismatch");
        System.out.println(INDENT + " verify=accepted");

        // Negative case: bit flip.
        byte[] badSig = Arrays.copyOf(signature, signature.length);
        badSig[0] = (byte) (badSig[0] ^ 0x01);

        SignatureContext badVerifier = CryptoAlgorithms.create("ML-DSA", KeyUsage.VERIFY, kp.getPublic());

        try {
            badVerifier.setExpectedTag(badSig);
            badVerifier.setVerificationApproach(badVerifier.getVerificationCore().getThrowOnMismatch());
            try (InputStream verBad = badVerifier.wrap(new ByteArrayInputStream(msg))) {
                readAll(verBad);
            }
            throw new AssertionError("Expected verification failure for mismatched signature");
        } catch (Exception expected) {
            System.out.println(INDENT + " verify=reject (mismatch)");
        } finally {
            try {
                badVerifier.close();
            } catch (Exception ignore) {
            }
        }
    }

    private static byte[] randomBytes(int len) {
        byte[] data = new byte[len];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(data);
        return data;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        try (InputStream src = in; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = src.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    private static String safeText(String s) {
        if (s == null) {
            return "null";
        }
        if (s.length() <= 30) {
            return s;
        }
        return s.substring(0, 30) + "...";
    }

    private static String hexTruncated(byte[] data, int maxBytes) {
        if (data == null) {
            return "null";
        }
        int n = Math.min(data.length, maxBytes);
        StringBuilder sb = new StringBuilder(n * 2 + 3);
        for (int i = 0; i < n; i++) {
            int v = data[i] & 0xFF;
            sb.append(HEX[(v >>> 4) & 0x0F]);
            sb.append(HEX[v & 0x0F]);
        }
        if (data.length > maxBytes) {
            sb.append("...");
        }
        return sb.toString();
    }

    private static final char[] HEX = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
            'e', 'f' };
}
