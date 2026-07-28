/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Key;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import zeroecho.core.audit.AuditMode;
import zeroecho.core.audit.AuditListener;
import zeroecho.core.err.UnsupportedSpecException;
import zeroecho.core.spec.ContextSpec;
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
