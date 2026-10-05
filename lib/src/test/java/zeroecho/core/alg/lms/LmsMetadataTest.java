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
package zeroecho.core.alg.lms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Arrays;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.Test;

import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.util.BouncyCastleActivator;

class LmsMetadataTest {
    @Test void structureAndLevelAreValidatedWithoutSigning() throws Exception {
        BouncyCastleActivator.init();
        PublicKey original = new ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("LMS", LmsKeyGenSpec.DEFAULT).getPublic();
        assertEquals(1296, LmsSignatureContext.sigLenFromPublicKey(original));
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(original.getEncoded());
        byte[] raw = info.getPublicKeyData().getBytes();
        for (byte[] invalid : new byte[][] { Arrays.copyOf(raw, 11), Arrays.copyOf(raw, raw.length - 1),
                Arrays.copyOf(raw, raw.length + 1), raw.clone() }) {
            if (invalid.length == raw.length) {
                ByteBuffer.wrap(invalid).putInt(2);
            }
            byte[] encoded = new SubjectPublicKeyInfo(info.getAlgorithm(), invalid).getEncoded();
            PublicKey malformed = new PublicKey() {
                @Override public String getAlgorithm() { return "LMS"; }
                @Override public String getFormat() { return "X.509"; }
                @Override public byte[] getEncoded() { return encoded.clone(); }
            };
            assertThrows(GeneralSecurityException.class, () -> LmsSignatureContext.sigLenFromPublicKey(malformed));
        }
    }
}
