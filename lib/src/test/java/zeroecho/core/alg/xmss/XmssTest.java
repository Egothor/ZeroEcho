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
package zeroecho.core.alg.xmss;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.KeyUsage;
import zeroecho.core.alg.common.sig.GenericJcaSignatureContext;
import zeroecho.core.alg.ed25519.Ed25519Algorithm;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.err.UnsupportedRoleException;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.hybrid.signature.HybridSignatureContexts;
import zeroecho.sdk.hybrid.signature.HybridSignatureProfile;
import zeroecho.sdk.util.BouncyCastleActivator;

/** Stateful signing containment, retained key import, and provider-independent verification. */
public final class XmssTest {
    @BeforeAll
    static void setup() {
        BouncyCastleActivator.init();
    }

    @Test
    void signingBoundariesRejectWithoutChangingPrivateStateOrInvokingCallbacks() throws Exception {
        ZeroEchoSession session = new ZeroEchoSession();
        KeyPair keys = session.keyBuilders().asymmetric().generateKeyPair("XMSS", XmssKeyGenSpec.DEFAULT);
        PrivateKey key = keys.getPrivate();
        byte[] before = key.getEncoded();
        XmssAlgorithm algorithm = new XmssAlgorithm();
        AtomicInteger callbacks = new AtomicInteger();
        GenericJcaSignatureContext.EngineFactory factory = (ignored, sign) -> {
            callbacks.incrementAndGet();
            throw new AssertionError("Engine factory must not run");
        };
        GenericJcaSignatureContext.SignLengthResolver resolver = ignored -> {
            callbacks.incrementAndGet();
            throw new AssertionError("Length resolver must not run");
        };
        assertThrows(UnsupportedRoleException.class, () -> session.createContext("XMSS", KeyUsage.SIGN, key));
        assertThrows(UnsupportedRoleException.class, () -> new XmssSignatureContext(algorithm, key));
        assertThrows(UnsupportedRoleException.class,
                () -> new GenericJcaSignatureContext(algorithm, key, factory, resolver));
        assertThrows(UnsupportedRoleException.class,
                () -> new GenericJcaSignatureContext(new Ed25519Algorithm(), key, factory, resolver));
        assertThrows(UnsupportedRoleException.class,
                () -> GenericJcaSignatureContext.SignLengthResolver.probeWith("Ed25519", "missing-provider").resolve(key));
        assertThrows(UnsupportedRoleException.class,
                () -> GenericJcaSignatureContext.SignLengthResolver.probeWith("XMSS", "missing-provider").resolve(key));
        assertThrows(UnsupportedRoleException.class,
                () -> GenericJcaSignatureContext.jcaFactory("Ed25519", "missing-provider").create(key, true));
        HybridSignatureProfile profile = new HybridSignatureProfile("Ed25519", "XMSS", null, null,
                HybridSignatureProfile.VerifyRule.AND);
        assertThrows(UnsupportedRoleException.class,
                () -> HybridSignatureContexts.sign(session, profile, key, key, 4096));
        assertEquals(0, callbacks.get());
        assertArrayEquals(before, key.getEncoded());
    }

    @Test
    void importedKeyAndVerificationRetainCompatibilityWithoutAdvancingState() throws Exception {
        ZeroEchoSession session = new ZeroEchoSession();
        KeyPair keys = session.keyBuilders().asymmetric().generateKeyPair("XMSS", XmssKeyGenSpec.DEFAULT);
        PrivateKey imported = session.keyBuilders().asymmetric().importPrivate("XMSS",
                new XmssPrivateKeySpec(keys.getPrivate().getEncoded()));
        assertArrayEquals(keys.getPrivate().getEncoded(), imported.getEncoded());
        byte[] message = "stateful verification remains available".getBytes(StandardCharsets.UTF_8);
        // Independent provider signing creates a test fixture, never a ZeroEcho signing context.
        Signature provider = Signature.getInstance("XMSS", "BCPQC");
        provider.initSign(imported);
        provider.update(message);
        byte[] signature = provider.sign();
        byte[] afterFixture = imported.getEncoded();
        try (SignatureContext verifier = session.createContext("XMSS", KeyUsage.VERIFY, keys.getPublic())) {
            assertEquals(signature.length, verifier.tagLength());
            verifier.setExpectedTag(signature);
            try (java.io.InputStream stream = verifier.wrap(new ByteArrayInputStream(message))) {
                assertArrayEquals(message, stream.readAllBytes());
            }
        }
        try (SignatureContext verifier = session.createContext("XMSS", KeyUsage.VERIFY, keys.getPublic())) {
            signature[signature.length - 1] ^= 1;
            verifier.setExpectedTag(signature);
            assertThrows(IOException.class, () -> {
                try (java.io.InputStream stream = verifier.wrap(new ByteArrayInputStream(message))) {
                    stream.readAllBytes();
                }
            });
        }
        assertArrayEquals(afterFixture, imported.getEncoded());
    }
}
