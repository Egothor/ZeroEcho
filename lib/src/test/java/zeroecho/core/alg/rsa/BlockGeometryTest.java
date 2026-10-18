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
package zeroecho.core.alg.rsa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyPair;

import org.junit.jupiter.api.Test;

import zeroecho.core.KeyUsage;
import zeroecho.core.context.EncryptionContext;

class BlockGeometryTest {
    @Test
    void geometryValidation() {
        System.out.println("geometryValidation");
        assertThrows(IllegalArgumentException.class, () -> new BlockGeometry(1, 1, 0));
        assertThrows(IllegalArgumentException.class, () -> new BlockGeometry(2, 0, 0));
        assertThrows(IllegalArgumentException.class, () -> new BlockGeometry(3, 2, 0));
        assertThrows(IllegalArgumentException.class, () -> new BlockGeometry(2, 2, -1));
        assertThrows(IllegalArgumentException.class, () -> new BlockGeometry(2, 2, 1));

        BlockGeometry maximum = new BlockGeometry(Integer.MAX_VALUE, Integer.MAX_VALUE, 0);
        assertEquals(Integer.MAX_VALUE, maximum.inChunkSize());
        assertEquals(Integer.MAX_VALUE, maximum.outChunkSize());
        System.out.println("...maximum=" + maximum.inChunkSize());
        System.out.println("geometryValidation...ok");
    }

    @Test
    void valueSemantics() {
        System.out.println("valueSemantics");
        BlockGeometry first = new BlockGeometry(2, 3, 0);
        BlockGeometry equal = new BlockGeometry(2, 3, 0);
        BlockGeometry different = new BlockGeometry(2, 4, 0);

        assertEquals(first, equal);
        assertEquals(first.hashCode(), equal.hashCode());
        assertNotEquals(first, different);
        assertEquals(2, first.inChunkSize());
        assertEquals(3, first.outChunkSize());
        assertEquals(0, first.finalizationOutputChunks());
        assertEquals("BlockGeometry[inChunkSize=2, outChunkSize=3, finalizationOutputChunks=0]", first.toString());
        System.out.println("...legacyFields=true");
        System.out.println("valueSemantics...ok");
    }

    @Test
    void actualRsaPath() throws Exception {
        System.out.println("actualRsaPath");
        KeyPair keyPair = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("RSA",
                RsaKeyGenSpec.rsa2048());
        RsaEncSpec spec = RsaEncSpec.oaep(RsaEncSpec.Hash.SHA256);
        BlockGeometry encryptGeometry = BlockGeometry.forRsa(spec, keyPair.getPublic(), true);
        BlockGeometry decryptGeometry = BlockGeometry.forRsa(spec, keyPair.getPrivate(), false);

        assertEquals(190, encryptGeometry.inChunkSize());
        assertEquals(256, encryptGeometry.outChunkSize());
        assertEquals(256, decryptGeometry.inChunkSize());
        assertEquals(256, decryptGeometry.outChunkSize());

        EncryptionContext context = new zeroecho.sdk.ZeroEchoSession().createContext("RSA", KeyUsage.ENCRYPT,
                keyPair.getPublic(), spec);
        try (InputStream stream = context.attach(new ByteArrayInputStream(new byte[] { 1, 2, 3 }))) {
            assertEquals(256, stream.readAllBytes().length);
        } finally {
            context.close();
        }
        System.out.println("...ciphertextBytes=256");
        System.out.println("actualRsaPath...ok");
    }
}
