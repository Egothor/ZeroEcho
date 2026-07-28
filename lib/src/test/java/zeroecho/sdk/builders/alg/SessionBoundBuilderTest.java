/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.sdk.builders.alg;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.InputStream;
import java.security.Key;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import zeroecho.core.KeyUsage;
import zeroecho.core.audit.AuditListener;
import zeroecho.core.audit.AuditMode;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.builtin.PlainBytes;

class SessionBoundBuilderTest {

    @Test
    void generatedKeyUsesBuilderSessionAuditSink() {
        System.out.println("generatedKeyUsesBuilderSessionAuditSink");
        RecordingListener listener = new RecordingListener();
        ZeroEchoSession session = new ZeroEchoSession().withAuditListener(listener);

        AesDataContentBuilder.builder(session).generateKey(128).modeGcm(128).build(true);

        assertEquals(1, listener.keyBuilt);
        System.out.println("...keyBuiltEvents=" + listener.keyBuilt);
        System.out.println("generatedKeyUsesBuilderSessionAuditSink...ok");
    }

    @Test
    void policyDenialOccursBeforeContextCreation() {
        System.out.println("policyDenialOccursBeforeContextCreation");
        RecordingListener listener = new RecordingListener();
        ZeroEchoSession session = new ZeroEchoSession()
                .withAuditListener(listener)
                .withPolicy((id, role, key, spec) -> {
                    throw new IllegalArgumentException("controlled policy denial");
                });
        DataContent encryption = AesDataContentBuilder.builder(session)
                .withKey(new SecretKeySpec(new byte[16], "AES"))
                .modeGcm(128)
                .build(true);
        encryption.setInput(new PlainBytes(new byte[] { 1 }));

        assertThrows(IllegalArgumentException.class, encryption::getStream);
        assertEquals(0, listener.contextCreated);
        System.out.println("...contextCreatedEvents=0");
        System.out.println("policyDenialOccursBeforeContextCreation...ok");
    }

    @Test
    void wrappedContextUsesBuilderSessionAuditConfiguration() throws Exception {
        System.out.println("wrappedContextUsesBuilderSessionAuditConfiguration");
        RecordingListener listener = new RecordingListener();
        ZeroEchoSession session = new ZeroEchoSession()
                .withAuditListener(listener)
                .withAuditMode(AuditMode.WRAP);
        DataContent encryption = AesDataContentBuilder.builder(session)
                .withKey(new SecretKeySpec(new byte[16], "AES"))
                .modeGcm(128)
                .build(true);
        encryption.setInput(new PlainBytes(new byte[] { 1, 2, 3 }));

        try (InputStream input = encryption.getStream()) {
            input.readAllBytes();
        }

        assertEquals(1, listener.contextCreated);
        assertEquals(1, listener.contextClosed);
        System.out.println("...created=1...closed=1");
        System.out.println("wrappedContextUsesBuilderSessionAuditConfiguration...ok");
    }

    private static final class RecordingListener implements AuditListener {
        private int keyBuilt;
        private int contextCreated;
        private int contextClosed;

        @Override
        public void onKeyBuilt(String id, String provider, AlgorithmKeySpec spec, Key key) {
            keyBuilt++;
        }

        @Override
        public void onContextCreatedMeta(String contextId, String algorithmId, String provider, KeyUsage role,
                String keyFingerprint, Map<String, Object> specMeta) {
            contextCreated++;
        }

        @Override
        public void onContextClosed(String contextId, long bodyBytes, long trailerBytes, long durationMillis) {
            contextClosed++;
        }
    }
}
