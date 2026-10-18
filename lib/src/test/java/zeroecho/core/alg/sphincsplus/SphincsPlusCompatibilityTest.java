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
package zeroecho.core.alg.sphincsplus;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Base64;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import zeroecho.core.marshal.PairSeq;
import zeroecho.sdk.util.BouncyCastleActivator;

class SphincsPlusCompatibilityTest {
    @BeforeAll
    static void provider() {
        BouncyCastleActivator.init();
    }

    @Test
    void unsupportedModesCannotBeHiddenByAnOverride() {
        SphincsPlusKeyGenBuilder builder = new SphincsPlusKeyGenBuilder();
        for (SphincsPlusKeyGenSpec.Hash hash : SphincsPlusKeyGenSpec.Hash.values()) {
            SphincsPlusKeyGenSpec robust = spec(hash, SphincsPlusKeyGenSpec.Mode.ROBUST);
            assertThrows(IllegalArgumentException.class, () -> builder.generateKeyPair(robust));
            assertThrows(IllegalArgumentException.class,
                    () -> builder.generateKeyPair(robust.withExplicitParamConstant("slh_dsa_sha2_128f")));
        }
        assertThrows(IllegalArgumentException.class, () -> builder.generateKeyPair(
                spec(SphincsPlusKeyGenSpec.Hash.HARAKA, SphincsPlusKeyGenSpec.Mode.SIMPLE)));
        assertThrows(IllegalArgumentException.class, () -> builder.generateKeyPair(
                spec(SphincsPlusKeyGenSpec.Hash.HARAKA, SphincsPlusKeyGenSpec.Mode.SIMPLE)
                        .withExplicitParamConstant("slh_dsa_sha2_128f")));
        assertEquals(SphincsPlusKeyGenSpec.Mode.SIMPLE, SphincsPlusKeyGenSpec.defaultSpec().mode());
        assertThrows(IllegalArgumentException.class, () -> builder.generateKeyPair(
                spec(SphincsPlusKeyGenSpec.Hash.SHA2, SphincsPlusKeyGenSpec.Mode.SIMPLE)
                        .withExplicitParamConstant("missing")));
        assertThrows(IllegalArgumentException.class, () -> builder.generateKeyPair(
                spec(SphincsPlusKeyGenSpec.Hash.SHA2, SphincsPlusKeyGenSpec.Mode.SIMPLE)
                        .withExplicitParamConstant("slh_dsa_sha2_128f_with_sha256")));
        assertThrows(IllegalArgumentException.class, () -> builder.generateKeyPair(SphincsPlusKeyGenSpec.of(
                "BCPQC", SphincsPlusKeyGenSpec.Hash.SHA2, SphincsPlusKeyGenSpec.Security.L1_128,
                SphincsPlusKeyGenSpec.Variant.FAST, SphincsPlusKeyGenSpec.Mode.SIMPLE)));
    }

    @Test
    void preservesExplicitPureParameterOverride() throws Exception {
        KeyPair pair = new SphincsPlusKeyGenBuilder().generateKeyPair(
                spec(SphincsPlusKeyGenSpec.Hash.SHA2, SphincsPlusKeyGenSpec.Mode.SIMPLE)
                        .withExplicitParamConstant("slh_dsa_shake_128f"));
        org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey key =
                (org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey) pair.getPublic();
        assertEquals("SLH-DSA-SHAKE-128F", key.getParameterSpec().getName().toUpperCase(java.util.Locale.ROOT));
    }

    @Test
    void newAndMissingProviderPayloadsImportButLegacyProviderIsRejected() throws Exception {
        KeyPair pair = new SphincsPlusKeyGenBuilder().generateKeyPair(
                spec(SphincsPlusKeyGenSpec.Hash.SHA2, SphincsPlusKeyGenSpec.Mode.SIMPLE));
        byte[] publicBytes = pair.getPublic().getEncoded();
        byte[] privateBytes = pair.getPrivate().getEncoded();
        SphincsPlusPublicKeySpec currentPublic = SphincsPlusPublicKeySpec.unmarshal(
                SphincsPlusPublicKeySpec.marshal(new SphincsPlusPublicKeySpec(publicBytes)));
        SphincsPlusPrivateKeySpec currentPrivate = SphincsPlusPrivateKeySpec.unmarshal(
                SphincsPlusPrivateKeySpec.marshal(new SphincsPlusPrivateKeySpec(privateBytes)));
        assertEquals("BC", currentPublic.providerName());
        assertEquals("BC", currentPrivate.providerName());
        assertArrayEquals(publicBytes, new SphincsPlusPublicKeyBuilder().importPublic(currentPublic).getEncoded());
        assertArrayEquals(privateBytes, new SphincsPlusPrivateKeyBuilder().importPrivate(currentPrivate).getEncoded());
        String pub = Base64.getEncoder().encodeToString(publicBytes);
        String priv = Base64.getEncoder().encodeToString(privateBytes);
        SphincsPlusPublicKeySpec missingPublic = SphincsPlusPublicKeySpec.unmarshal(PairSeq.of("x509.b64", pub));
        SphincsPlusPrivateKeySpec missingPrivate = SphincsPlusPrivateKeySpec.unmarshal(PairSeq.of("pkcs8.b64", priv));
        assertEquals("BC", missingPublic.providerName());
        assertEquals("BC", missingPrivate.providerName());
        assertArrayEquals(publicBytes, new SphincsPlusPublicKeyBuilder().importPublic(missingPublic).getEncoded());
        assertArrayEquals(privateBytes, new SphincsPlusPrivateKeyBuilder().importPrivate(missingPrivate).getEncoded());
        assertThrows(IllegalArgumentException.class, () -> SphincsPlusPublicKeySpec.unmarshal(
                PairSeq.of("x509.b64", pub, "provider", "BCPQC")));
        assertThrows(IllegalArgumentException.class, () -> SphincsPlusPrivateKeySpec.unmarshal(
                PairSeq.of("pkcs8.b64", priv, "provider", "BCPQC")));
        assertEquals("BC", new SphincsPlusPublicKeySpec(publicBytes, null).providerName());
        assertEquals("BC", new SphincsPlusPrivateKeySpec(privateBytes, null).providerName());
        SubjectPublicKeyInfo publicInfo = SubjectPublicKeyInfo.getInstance(publicBytes);
        PrivateKeyInfo privateInfo = PrivateKeyInfo.getInstance(privateBytes);
        AlgorithmIdentifier legacyAlgorithm = new AlgorithmIdentifier(BCObjectIdentifiers.sphincsPlus);
        byte[] legacyPublic = new SubjectPublicKeyInfo(legacyAlgorithm, publicInfo.getPublicKeyData().getBytes()).getEncoded();
        byte[] legacyPrivate = new PrivateKeyInfo(legacyAlgorithm,
                new org.bouncycastle.asn1.DEROctetString(privateInfo.getPrivateKey().getOctets())).getEncoded();
        assertThrows(GeneralSecurityException.class, () -> new SphincsPlusPublicKeyBuilder()
                .importPublic(new SphincsPlusPublicKeySpec(legacyPublic)));
        assertThrows(GeneralSecurityException.class, () -> new SphincsPlusPrivateKeyBuilder()
                .importPrivate(new SphincsPlusPrivateKeySpec(legacyPrivate)));
        assertThrows(GeneralSecurityException.class, () -> new SphincsPlusPublicKeyBuilder()
                .importPublic(new SphincsPlusPublicKeySpec(new byte[] { 1, 2, 3 })));
        assertThrows(GeneralSecurityException.class, () -> new SphincsPlusPrivateKeyBuilder()
                .importPrivate(new SphincsPlusPrivateKeySpec(new byte[] { 1, 2, 3 })));
    }

    private static SphincsPlusKeyGenSpec spec(SphincsPlusKeyGenSpec.Hash hash, SphincsPlusKeyGenSpec.Mode mode) {
        return SphincsPlusKeyGenSpec.of("BC", hash, SphincsPlusKeyGenSpec.Security.L1_128,
                SphincsPlusKeyGenSpec.Variant.FAST, mode);
    }
}
