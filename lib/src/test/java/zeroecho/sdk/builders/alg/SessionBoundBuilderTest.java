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
        ZeroEchoSession session = new ZeroEchoSession().withAuditListener(listener)
                .withPolicy((id, role, key, spec) -> {
                    throw new IllegalArgumentException("controlled policy denial");
                });
        DataContent encryption = AesDataContentBuilder.builder(session).withKey(new SecretKeySpec(new byte[16], "AES"))
                .modeGcm(128).build(true);
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
        ZeroEchoSession session = new ZeroEchoSession().withAuditListener(listener).withAuditMode(AuditMode.WRAP);
        DataContent encryption = AesDataContentBuilder.builder(session).withKey(new SecretKeySpec(new byte[16], "AES"))
                .modeGcm(128).build(true);
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
