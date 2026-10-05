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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.PrivateKey;
import java.security.Provider;
import java.util.List;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.Test;

import zeroecho.core.err.UnsupportedRoleException;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.Pkix;
import zeroecho.sdk.util.BouncyCastleActivator;

class LmsXmssGuardTest {
    @Test
    void recognizesEveryInstalledStatefulSignatureServiceAndAlias() {
        Provider provider = new BouncyCastlePQCProvider();
        for (Provider.Service service : provider.getServices()) {
            if (service.getType().equals("Signature") && statefulService(service)) {
                assertTrue(StatefulSigningGuard.isStateful(service.getAlgorithm()), service.getAlgorithm());
            }
        }
        String prefix = "Alg.Alias.Signature.";
        provider.forEach((key, value) -> {
            if (key.toString().startsWith(prefix)) {
                String alias = key.toString().substring(prefix.length());
                Provider.Service service = provider.getService("Signature", alias);
                if (service != null && statefulService(service)) {
                    assertTrue(StatefulSigningGuard.isStateful(alias), alias);
                }
            }
        });
    }

    @Test
    void handlesOidAndCustomCodecIdentityWithoutParsingParameters() {
        for (String oid : List.of("1.2.840.113549.1.9.16.3.17", "0.4.0.127.0.15.1.1.13.0",
                "0.4.0.127.0.15.1.1.14.0", "1.3.6.1.5.5.7.6.34", "1.3.6.1.5.5.7.6.35")) {
            assertTrue(StatefulSigningGuard.isStateful(oid));
            assertTrue(StatefulSigningGuard.isStateful("OID." + oid));
        }
        assertTrue(StatefulSigningGuard.isStateful("zealg:2:9:signature6:vendor3:lms12:custom-codec4:AAAA"));
        assertTrue(StatefulSigningGuard.isStateful("zealg:2:9:signature6:vendor4:xmss12:custom-codec4:AAAA"));
        assertFalse(StatefulSigningGuard.isStateful("zealg:2:9:signature4:xmss3:rsa12:custom-codec4:bG1z"));
        assertFalse(StatefulSigningGuard.isStateful("rsa" + "x".repeat(300)));
        assertFalse(StatefulSigningGuard.isStateful("1.3.101.110"));
        assertFalse(StatefulSigningGuard.isStateful("SLH-DSA-SHA2-128s"));
    }

    @Test
    void pkixRejectsBeforeParsingCsrOrEncodingPrivateKeys() {
        BouncyCastleActivator.init();
        for (String name : List.of("LMS", "XMSS")) {
            PrivateKey key = new PrivateKey() {
                public String getAlgorithm() { return name; }
                public String getFormat() { return "PKCS#8"; }
                public byte[] getEncoded() { throw new AssertionError("Key must not be encoded"); }
            };
            assertThrows(UnsupportedRoleException.class,
                    () -> Pkix.signer(key, AlgorithmIdentifier.absent("1.2.840.113549.1.1.11")));
            assertThrows(UnsupportedRoleException.class,
                    () -> Pkix.buildServerKeygenCsr(new byte[] { 0 },
                            org.mockito.Mockito.mock(java.security.PublicKey.class), key));
        }
    }

    private static boolean statefulService(Provider.Service service) {
        return service.getClassName().contains(".xmss.") || service.getClassName().contains(".lms.");
    }
}
