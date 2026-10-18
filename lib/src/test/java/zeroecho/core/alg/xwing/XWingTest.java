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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyPair;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.xwing.XWingKeyGenSpec;
import zeroecho.core.context.KemContext;
import zeroecho.core.context.KemContext.KemResult;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * Round-trip test for X-Wing hybrid KEM.
 *
 * @since 1.0
 */
public final class XWingTest {

    private static final String INDENT = "...";

    @BeforeAll
    static void setup() {
        BouncyCastleActivator.init();
    }

    @Test
    void xwing_kem_roundtrip() throws Exception {
        System.out.println("xwing_kem_roundtrip");

        assertNotNull(CryptoAlgorithms.require("X-Wing"));

        zeroecho.sdk.ZeroEchoSession session = new zeroecho.sdk.ZeroEchoSession();

        KeyPair kp = session.keyBuilders().asymmetric().generateKeyPair("X-Wing", XWingKeyGenSpec.DEFAULT);
        assertNotNull(kp.getPublic(), "public key must not be null");
        assertNotNull(kp.getPrivate(), "private key must not be null");

        System.out.println(INDENT + " pubKeyLen=" + kp.getPublic().getEncoded().length);
        System.out.println(INDENT + " privKeyLen=" + kp.getPrivate().getEncoded().length);

        KemContext encCtx = session.createContext("X-Wing", KeyUsage.ENCAPSULATE, kp.getPublic());
        KemResult result = encCtx.encapsulate();
        assertNotNull(result, "encapsulation result must not be null");
        byte[] ciphertext = result.ciphertext();
        byte[] sharedSecretA = result.sharedSecret();
        assertNotNull(ciphertext, "ciphertext must not be null");
        assertFalse(ciphertext.length == 0, "ciphertext must not be empty");

        System.out.println(INDENT + " ciphertextLen=" + ciphertext.length);
        System.out.println(INDENT + " sharedSecretA.len=" + sharedSecretA.length);

        KemContext decCtx = session.createContext("X-Wing", KeyUsage.DECAPSULATE, kp.getPrivate());
        byte[] sharedSecretB = decCtx.decapsulate(ciphertext);
        assertNotNull(sharedSecretB, "decapsulated secret must not be null");

        System.out.println(INDENT + " sharedSecretB.len=" + sharedSecretB.length);

        assertArrayEquals(sharedSecretA, sharedSecretB, "shared secrets must match");

        System.out.println(INDENT + " secrets match");
        System.out.println(INDENT + "ok");
    }
}
