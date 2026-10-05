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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;

import org.bouncycastle.pqc.jcajce.interfaces.XMSSKey;
import org.junit.jupiter.api.Test;

class XmssMetadataTest {
    @Test void digestSizesAndInvalidParametersNeedNoSignatureProbe() throws Exception {
        assertEquals(2500, XmssSignatureContext.xmssSigLen(key(10, "SHA256")));
        assertEquals(2500, XmssSignatureContext.xmssSigLen(key(10, "SHAKE128")));
        assertEquals(9092, XmssSignatureContext.xmssSigLen(key(10, "SHA512")));
        assertEquals(9092, XmssSignatureContext.xmssSigLen(key(10, "SHAKE256")));
        assertEquals(1492, XmssSignatureContext.xmssSigLen(key(10, "SHA256/192")));
        assertEquals(1492, XmssSignatureContext.xmssSigLen(key(10, "SHAKE256/192")));
        assertEquals(2500, XmssSignatureContext.xmssSigLen(key(10, "SHAKE256/256")));
        for (String digest : new String[] { null, "unknown", "SHA-256" }) {
            assertThrows(GeneralSecurityException.class, () -> XmssSignatureContext.xmssSigLen(key(10, digest)));
        }
        assertEquals(3140, XmssSignatureContext.xmssSigLen(key(30, "SHA256")));
        for (int height : new int[] { -1, 0, 1, 31, Integer.MAX_VALUE }) {
            assertThrows(GeneralSecurityException.class, () -> XmssSignatureContext.xmssSigLen(key(height, "SHA256")));
        }
    }
    private static XMSSKey key(int height, String digest) {
        return new XMSSKey() {
            @Override public int getHeight() { return height; }
            @Override public String getTreeDigest() { return digest; }
        };
    }
}
