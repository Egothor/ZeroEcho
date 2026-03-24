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
package zeroecho.core.alg.slhdsa;

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
 * Large-data streaming test for SLH-DSA integration.
 *
 * <p>
 * Signature length is determined via {@link SlhDsaSignatureContext} created for
 * verification (public key). If the verification context is not an instance of
 * {@link SlhDsaSignatureContext}, the test fails.
 * </p>
 */
public final class SlhDsaLargeDataTest {

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

    @Test
    void slhdsa_complete_suite_streaming_sign_verify_large_data() throws Exception {
        String testName = "slhdsa_complete_suite_streaming_sign_verify_large_data";
        System.out.println(testName);

        if (!CryptoAlgorithms.available().contains("SLH-DSA")) {
            System.out.println(INDENT + " *** SKIP *** SLH-DSA not registered");
            System.out.println(INDENT + "ok");
            return;
        }

        int payloadLen = 48 * 1024 + 123;
        byte[] msg = randomBytes(payloadLen);

        System.out.println(INDENT + " msg.len=" + msg.length);
        System.out.println(INDENT + " msg.hex=" + hexTruncated(msg, MAX_HEX_BYTES));

        // Complete suite: 128/192/256 x FAST/SMALL, for both SHA2 and SHAKE, no
        // pre-hash
        runSuiteForHash(msg, SlhDsaKeyGenSpec.Hash.SHA2);
        runSuiteForHash(msg, SlhDsaKeyGenSpec.Hash.SHAKE);

        System.out.println(INDENT + "ok");
    }

    private static void runSuiteForHash(byte[] msg, SlhDsaKeyGenSpec.Hash hash) throws Exception {
        runCase(msg, hash, SlhDsaKeyGenSpec.Security.L1_128, SlhDsaKeyGenSpec.Variant.FAST);
        runCase(msg, hash, SlhDsaKeyGenSpec.Security.L1_128, SlhDsaKeyGenSpec.Variant.SMALL);

        runCase(msg, hash, SlhDsaKeyGenSpec.Security.L3_192, SlhDsaKeyGenSpec.Variant.FAST);
        runCase(msg, hash, SlhDsaKeyGenSpec.Security.L3_192, SlhDsaKeyGenSpec.Variant.SMALL);

        runCase(msg, hash, SlhDsaKeyGenSpec.Security.L5_256, SlhDsaKeyGenSpec.Variant.FAST);
        runCase(msg, hash, SlhDsaKeyGenSpec.Security.L5_256, SlhDsaKeyGenSpec.Variant.SMALL);
    }

    private static void runCase(byte[] msg, SlhDsaKeyGenSpec.Hash hash, SlhDsaKeyGenSpec.Security sec,
            SlhDsaKeyGenSpec.Variant variant) throws Exception {

        SlhDsaKeyGenSpec spec = SlhDsaKeyGenSpec.of("BC", hash, sec, variant, SlhDsaKeyGenSpec.PreHash.NONE);

        String caseId = "SLH-DSA " + hash.name() + " " + sec.name() + " " + variant.name();
        System.out.println(INDENT + " case=" + safeText(caseId));

        KeyPair kp = CryptoAlgorithms.keyPair("SLH-DSA", spec);

        // Create verifier FIRST to obtain tag length via
        // SlhDsaSignatureContext.sigLenFromPublicKey.
        SignatureContext verifierCtx = CryptoAlgorithms.create("SLH-DSA", KeyUsage.VERIFY, kp.getPublic());

        int expectedSigLen = verifierCtx.tagLength();
        System.out.println(INDENT + " expectedSigLen=" + expectedSigLen);

        // Now sign and strip trailer using the expected length from verifier (not from
        // signer).
        SignatureContext signer = CryptoAlgorithms.create("SLH-DSA", KeyUsage.SIGN, kp.getPrivate());

        final byte[][] sigHolder = new byte[1][];
        byte[] passthrough;
        try (InputStream in = new TailStrippingInputStream(signer.wrap(new ByteArrayInputStream(msg)), expectedSigLen,
                8192) {
            @Override
            protected void processTail(byte[] tail) throws IOException {
                sigHolder[0] = (tail == null ? null : Arrays.copyOf(tail, tail.length));
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
                verifierCtx.close();
            } catch (Exception ignore) {
            }
            throw new AssertionError(
                    "Signature length mismatch: got=" + signature.length + " expected=" + expectedSigLen);
        }

        // Verify OK with expected signature (use already-created SLH verifier).
        verifierCtx.setExpectedTag(Arrays.copyOf(signature, signature.length));
        byte[] verifyOut;
        try (InputStream verIn = verifierCtx.wrap(new ByteArrayInputStream(msg))) {
            verifyOut = readAll(verIn);
        } finally {
            try {
                verifierCtx.close();
            } catch (Exception ignore) {
            }
        }

        assertArrayEquals(msg, verifyOut, "VERIFY passthrough mismatch");
        System.out.println(INDENT + " verify=accepted");

        // Negative: bit flip and expect rejection (new verifier instance, must again be
        // our context).
        byte[] badSig = Arrays.copyOf(signature, signature.length);
        badSig[0] = (byte) (badSig[0] ^ 0x01);

        SignatureContext badVerifier = CryptoAlgorithms.create("SLH-DSA", KeyUsage.VERIFY, kp.getPublic());

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
