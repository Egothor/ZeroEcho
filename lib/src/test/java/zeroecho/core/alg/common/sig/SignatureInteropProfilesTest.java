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
package zeroecho.core.alg.common.sig;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.HexFormat;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.core.alg.ecdsa.EcdsaCurveSpec;
import zeroecho.core.alg.rsa.RsaSigSpec;

/**
 * Regression tests for {@link SignatureInteropProfiles}.
 */
public final class SignatureInteropProfilesTest {

    @Test
    public void resolveSha256WithRsa_returnsPkcs1v15Sha256() {
        System.out.println("resolveSha256WithRsa_returnsPkcs1v15Sha256");

        Optional<SignatureInteropProfile> profileOpt = SignatureInteropProfiles.resolve("SHA256withRSA");
        assertTrue(profileOpt.isPresent());

        SignatureInteropProfile profile = profileOpt.get();
        System.out.println("...keyAlgorithmId=" + profile.keyAlgorithmId());
        System.out.println("...contextAlgorithmId=" + profile.contextAlgorithmId());
        System.out.println("...contextSpec=" + profile.contextSpec().getClass().getSimpleName());

        assertEquals("RSA", profile.keyAlgorithmId());
        assertEquals("RSA", profile.contextAlgorithmId());
        assertEquals(RsaSigSpec.pkcs1v15(RsaSigSpec.Hash.SHA256).description(),
                ((RsaSigSpec) profile.contextSpec()).description());

        System.out.println("resolveSha256WithRsa_returnsPkcs1v15Sha256...ok");
    }

    @Test
    public void resolveSha256WithEcdsa_roundTripsDerAndP1363() throws Exception {
        System.out.println("resolveSha256WithEcdsa_roundTripsDerAndP1363");

        Optional<SignatureInteropProfile> profileOpt = SignatureInteropProfiles.resolve("SHA256withECDSA");
        assertTrue(profileOpt.isPresent());

        SignatureInteropProfile profile = profileOpt.get();
        assertEquals("ECDSA", profile.keyAlgorithmId());
        assertEquals("ECDSA", profile.contextAlgorithmId());
        assertEquals(EcdsaCurveSpec.P256, profile.contextSpec());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        byte[] payload = "ecdsa-interop".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(kp.getPrivate());
        signer.update(payload);
        byte[] derSignature = signer.sign();

        byte[] p1363Signature = profile.externalToInternalSignature(derSignature);
        byte[] roundTripDer = profile.internalToExternalSignature(p1363Signature);

        System.out.println("...derLen=" + derSignature.length);
        System.out.println("...p1363Len=" + p1363Signature.length);
        System.out.println("...derHexPrefix=" + hexPrefix(derSignature));
        System.out.println("...p1363HexPrefix=" + hexPrefix(p1363Signature));

        assertEquals(EcdsaCurveSpec.P256.signFixedLength(), p1363Signature.length);
        assertArrayEquals(derSignature, roundTripDer);

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(kp.getPublic());
        verifier.update(payload);
        boolean ok = verifier.verify(roundTripDer);
        System.out.println("...verified=" + ok);
        assertTrue(ok);

        System.out.println("resolveSha256WithEcdsa_roundTripsDerAndP1363...ok");
    }

    private static String hexPrefix(byte[] bytes) {
        int len = Math.min(bytes.length, 16);
        byte[] prefix = new byte[len];
        System.arraycopy(bytes, 0, prefix, 0, len);
        String text = HexFormat.of().formatHex(prefix);
        return bytes.length > len ? text + "..." : text;
    }
}
