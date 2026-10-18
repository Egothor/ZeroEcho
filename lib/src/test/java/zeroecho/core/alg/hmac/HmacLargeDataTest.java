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
package zeroecho.core.alg.hmac;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.MacContext;
import zeroecho.core.io.TailStrippingInputStream;

public class HmacLargeDataTest {

    @BeforeAll
    static void setup() {
        // register providers if needed
    }

    private static void logBegin(Object... params) {
        String thisClass = HmacLargeDataTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = HmacLargeDataTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logEnd"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "...ok");
    }

    private static byte[] randomBytes(int len) {
        byte[] data = new byte[len];
        new SecureRandom().nextBytes(data);
        return data;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static byte[] jcaMac(String alg, SecretKey key, byte[] msg) throws Exception {
        Mac mac = Mac.getInstance(alg);
        mac.init(key);
        int off = 0;
        while (off < msg.length) {
            int len = Math.min(8192, msg.length - off);
            mac.update(msg, off, len);
            off += len;
        }
        return mac.doFinal();
    }

    @Test
    void hmac_sha256_streaming_mac_and_verify_with_jca_crosscheck() throws Exception {
        final int SIZE = 64 * 1024 + 321;
        final String ALG_ID = "HMAC";
        final String JCA_MAC = "HmacSHA256";
        logBegin(Integer.valueOf(SIZE), JCA_MAC);

        if (!CryptoAlgorithms.available().contains(ALG_ID)) {
            System.out.println("...*** SKIP *** " + ALG_ID + " not registered");
            return;
        }

        byte[] msg = randomBytes(SIZE);
        System.out.println("...input size: " + msg.length);

        CryptoAlgorithm algo = CryptoAlgorithms.require(ALG_ID);

        // Generate a key (macName must match)
        SecretKey key = algo.symmetricKeyGenerator(HmacKeyGenSpec.class)
                .generateSecret(new HmacKeyGenSpec(JCA_MAC, 256));

        // --- MAC (produce): engine emits [body][tag]; capture trailer ---
        HmacSpec spec = HmacSpec.sha256();
        MacContext mac = new zeroecho.sdk.ZeroEchoSession().createContext(ALG_ID, KeyUsage.MAC, key, spec);
        final byte[][] tagHolder = new byte[1][];
        final int tagLen = mac.tagLength();

        byte[] pass1;
        try (InputStream in = new TailStrippingInputStream(mac.wrap(new ByteArrayInputStream(msg)), tagLen, 8192) {
            @Override
            protected void processTail(byte[] tail) throws IOException {
                tagHolder[0] = (tail == null ? null : tail.clone());
            }
        }) {
            pass1 = readAll(in); // body only (trailer stripped)
        } finally {
            try {
                mac.close();
            } catch (Exception ignore) {
            }
        }

        assertArrayEquals(msg, pass1, "MAC passthrough mismatch");
        byte[] tag = tagHolder[0];
        assertNotNull(tag, "streaming HMAC tag null");
        assertTrue(tag.length > 0, "streaming HMAC tag empty");
        System.out.println("...tag size: " + tag.length);

        // Cross-check vs JCA
        byte[] ref = jcaMac(JCA_MAC, key, msg);
        assertArrayEquals(ref, tag, "HMAC tag mismatch vs JCA reference");

        // --- VERIFY (consume): provide expected tag and drain (throws on mismatch) ---
        MacContext ver = new zeroecho.sdk.ZeroEchoSession().createContext(ALG_ID, KeyUsage.MAC, key, spec);
        ver.setExpectedTag(tag);
        byte[] pass2;
        try (InputStream in = ver.wrap(new ByteArrayInputStream(msg))) {
            pass2 = readAll(in);
        } finally {
            try {
                ver.close();
            } catch (Exception ignore) {
            }
        }
        assertArrayEquals(msg, pass2, "VERIFY passthrough mismatch");
        System.out.println("...verified: true");

        logEnd();
    }
}
