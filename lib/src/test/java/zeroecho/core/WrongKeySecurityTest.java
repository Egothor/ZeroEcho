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
package zeroecho.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import zeroecho.core.audit.AuditListener;
import zeroecho.core.audit.AuditMode;
import zeroecho.core.err.UnsupportedSpecException;
import zeroecho.sdk.ZeroEchoSession;

class WrongKeySecurityTest {

    @Test
    void wrongKeyMatrix() {
        System.out.println("wrongKeyMatrix");
        AtomicInteger auditEvents = new AtomicInteger();
        ZeroEchoSession session = new ZeroEchoSession().withAuditMode(AuditMode.WRAP)
                .withAuditListener(new AuditListener() {
                    @Override
                    public void onContextCreatedMeta(String contextId, String algorithmId, String provider,
                            KeyUsage role, String keyFingerprint, java.util.Map<String, Object> specMeta) {
                        auditEvents.incrementAndGet();
                    }
                });

        assertWrongKey(session, "AES", KeyUsage.ENCRYPT);
        assertWrongKey(session, "ECDSA", KeyUsage.SIGN);
        assertWrongKey(session, "Xdh", KeyUsage.AGREEMENT);
        assertWrongKey(session, "ML-KEM", KeyUsage.ENCAPSULATE);
        assertEquals(0, auditEvents.get(), "rejected keys must not create or process contexts");

        System.out.println("...families=4");
        System.out.println("wrongKeyMatrix...ok");
    }

    private static void assertWrongKey(ZeroEchoSession session, String algorithm, KeyUsage role) {
        UnsupportedSpecException failure = assertThrows(UnsupportedSpecException.class,
                () -> session.createContext(algorithm, role, NullKey.INSTANCE));
        assertTrue(failure.getMessage().contains(algorithm));
        assertTrue(failure.getMessage().contains(role.name()));
        assertNull(failure.getCause());
    }
}
