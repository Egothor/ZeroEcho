/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.audit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import zeroecho.core.KeyUsage;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.DigestContext;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.context.MessageAgreementContext;

class AuditedContextsRegressionTest {

    @Test
    void unrelatedProxyGetsWrapped() throws Exception {
        System.out.println("unrelatedProxyGetsWrapped");
        DigestContext target = mock(DigestContext.class);
        when(target.tagLength()).thenReturn(2);
        when(target.wrap(any(InputStream.class))).thenAnswer(invocation -> invocation.getArgument(0));
        DigestContext unrelated = (DigestContext) Proxy.newProxyInstance(DigestContext.class.getClassLoader(),
                new Class<?>[] { DigestContext.class }, (proxy, method, arguments) -> {
                    try {
                        return method.invoke(target, arguments);
                    } catch (InvocationTargetException exception) {
                        throw exception.getCause();
                    }
                });

        DigestContext wrapped = (DigestContext) AuditedContexts.wrap(unrelated, AuditListener.noop(), KeyUsage.DIGEST);

        assertNotSame(unrelated, wrapped);
        assertTrue(Proxy.isProxyClass(wrapped.getClass()));
        assertArrayEquals(new byte[] { 1, 2 },
                wrapped.wrap(new ByteArrayInputStream(new byte[] { 1, 2 })).readAllBytes());
        assertSame(wrapped, AuditedContexts.wrap(wrapped, AuditListener.noop(), KeyUsage.DIGEST));
        System.out.println("...nestedProxy=true");
        System.out.println("unrelatedProxyGetsWrapped...ok");
    }

    @Test
    void verifyEofKeepsBodyAccounting() throws Exception {
        System.out.println("verifyEofKeepsBodyAccounting");
        RecordingListener listener = new RecordingListener();
        DigestContext target = mock(DigestContext.class);
        when(target.tagLength()).thenReturn(8);
        when(target.wrap(any(InputStream.class))).thenAnswer(invocation -> invocation.getArgument(0));
        DigestContext wrapped = (DigestContext) AuditedContexts.wrap(target, listener, KeyUsage.DIGEST);
        wrapped.setExpectedTag(new byte[8]);

        assertArrayEquals(new byte[] { 1, 2, 3 },
                wrapped.wrap(new ByteArrayInputStream(new byte[] { 1, 2, 3 })).readAllBytes());

        assertEquals(List.of(Boolean.TRUE), listener.verificationResults);
        assertEquals(3, listener.bodyBytes);
        assertEquals(0, listener.trailerBytes);
        assertEquals(0, listener.tagEvents);
        System.out.println("...body=3...trailer=0");
        System.out.println("verifyEofKeepsBodyAccounting...ok");
    }

    @Test
    void verifyFailureSingleEvent() throws Exception {
        System.out.println("verifyFailureSingleEvent");
        RecordingListener listener = new RecordingListener();
        IOException expected = new IOException("controlled verification failure");
        DigestContext target = mock(DigestContext.class);
        when(target.tagLength()).thenReturn(4);
        when(target.wrap(any(InputStream.class))).thenReturn(new InputStream() {
            @Override
            public int read() throws IOException {
                throw expected;
            }
        });
        DigestContext wrapped = (DigestContext) AuditedContexts.wrap(target, listener, KeyUsage.DIGEST);
        wrapped.setExpectedTag(new byte[4]);

        IOException actual = assertThrows(IOException.class, () -> {
            try (InputStream input = wrapped.wrap(new ByteArrayInputStream(new byte[0]))) {
                input.readAllBytes();
            }
        });

        assertSame(expected, actual);
        assertEquals(List.of(expected), listener.failures);
        assertEquals(List.of(Boolean.FALSE), listener.verificationResults);
        System.out.println("...failures=1...verifyFalse=1");
        System.out.println("verifyFailureSingleEvent...ok");
    }

    @Test
    void fingerprintsAvoidSecretBytes() {
        System.out.println("fingerprintsAvoidSecretBytes");
        RecordingListener listener = new RecordingListener();
        SecretKey secretKey = mock(SecretKey.class);
        when(secretKey.getAlgorithm()).thenReturn("CONTROLLED-SECRET");
        PrivateKey privateKey = mock(PrivateKey.class);
        when(privateKey.getAlgorithm()).thenReturn("CONTROLLED-PRIVATE");

        EncryptionContext secretContext = mock(EncryptionContext.class);
        when(secretContext.key()).thenReturn(secretKey);
        EncryptionContext privateContext = mock(EncryptionContext.class);
        when(privateContext.key()).thenReturn(privateKey);
        AuditedContexts.wrap(secretContext, listener, KeyUsage.ENCRYPT);
        AuditedContexts.wrap(privateContext, listener, KeyUsage.DECRYPT);

        verify(secretKey, never()).getEncoded();
        verify(privateKey, never()).getEncoded();
        assertEquals(2, listener.fingerprints.size());
        assertTrue(listener.fingerprints.get(0).startsWith("CONTROLLED-SECRET:"));
        assertTrue(listener.fingerprints.get(1).startsWith("CONTROLLED-PRIVATE:"));
        assertFalse(listener.fingerprints.toString().contains("sensitive-key-bytes"));

        byte[] publicEncoding = { 1, 2, 3, 4 };
        PublicKey publicKey = mock(PublicKey.class);
        when(publicKey.getAlgorithm()).thenReturn("CONTROLLED-PUBLIC");
        when(publicKey.getEncoded()).thenReturn(publicEncoding);
        EncryptionContext publicContext = mock(EncryptionContext.class);
        when(publicContext.key()).thenReturn(publicKey);
        AuditedContexts.wrap(publicContext, listener, KeyUsage.ENCRYPT);
        assertArrayEquals(new byte[4], publicEncoding);
        assertFalse(listener.fingerprints.get(2).contains(Arrays.toString(new byte[] { 1, 2, 3, 4 })));

        System.out.println("...privateEncodedCalls=0...secretEncodedCalls=0...publicEncodingCleared=true");
        System.out.println("fingerprintsAvoidSecretBytes...ok");
    }

    @Test
    void proxyStringRepresentationDoesNotDelegate() {
        System.out.println("proxyStringRepresentationDoesNotDelegate");
        SensitiveStringDigest target = new SensitiveStringDigest();

        DigestContext wrapped = (DigestContext) AuditedContexts.wrap(target, AuditListener.noop(), KeyUsage.DIGEST);
        String description = wrapped.toString();

        assertTrue(description.startsWith("AuditedCryptoContext["));
        assertFalse(description.contains("SENSITIVE-TARGET-STATE"));
        assertEquals(0, target.toStringCalls);
        System.out.println("...description=" + description.substring(0, Math.min(30, description.length())) + "...");
        System.out.println("proxyStringRepresentationDoesNotDelegate...ok");
    }

    @Test
    void agreementFailuresSingleEvent() {
        System.out.println("agreementFailuresSingleEvent");
        RecordingListener listener = new RecordingListener();
        IllegalArgumentException peerFailure = new IllegalArgumentException("peer failure");
        IllegalStateException deriveFailure = new IllegalStateException("derive failure");
        AgreementContext agreement = mock(AgreementContext.class);
        doThrow(peerFailure).when(agreement).setPeerPublic(any(PublicKey.class));
        when(agreement.deriveSecret()).thenThrow(deriveFailure);
        AgreementContext wrappedAgreement = (AgreementContext) AuditedContexts.wrap(agreement, listener,
                KeyUsage.AGREEMENT);

        assertSame(peerFailure, assertThrows(IllegalArgumentException.class,
                () -> wrappedAgreement.setPeerPublic(mock(PublicKey.class))));
        assertSame(deriveFailure, assertThrows(IllegalStateException.class, wrappedAgreement::deriveSecret));

        IllegalArgumentException setMessageFailure = new IllegalArgumentException("set message failure");
        IllegalStateException getMessageFailure = new IllegalStateException("get message failure");
        IllegalStateException messageDeriveFailure = new IllegalStateException("message derive failure");
        MessageAgreementContext messageAgreement = mock(MessageAgreementContext.class);
        doThrow(setMessageFailure).when(messageAgreement).setPeerMessage(any(byte[].class));
        when(messageAgreement.getPeerMessage()).thenThrow(getMessageFailure);
        when(messageAgreement.deriveSecret()).thenThrow(messageDeriveFailure);
        MessageAgreementContext wrappedMessage = (MessageAgreementContext) AuditedContexts.wrap(messageAgreement,
                listener, KeyUsage.AGREEMENT);

        assertSame(setMessageFailure,
                assertThrows(IllegalArgumentException.class, () -> wrappedMessage.setPeerMessage(new byte[] { 1 })));
        assertSame(getMessageFailure, assertThrows(IllegalStateException.class, wrappedMessage::getPeerMessage));
        assertSame(messageDeriveFailure, assertThrows(IllegalStateException.class, wrappedMessage::deriveSecret));
        assertEquals(List.of(peerFailure, deriveFailure, setMessageFailure, getMessageFailure, messageDeriveFailure),
                listener.failures);

        System.out.println("...operations=5...failures=5");
        System.out.println("agreementFailuresSingleEvent...ok");
    }

    private static final class RecordingListener implements AuditListener {
        private final List<String> fingerprints = new ArrayList<>();
        private final List<Throwable> failures = new ArrayList<>();
        private final List<Boolean> verificationResults = new ArrayList<>();
        private long bodyBytes;
        private long trailerBytes;
        private int tagEvents;

        @Override
        public void onContextCreatedMeta(String contextId, String algorithmId, String provider, KeyUsage role,
                String keyFingerprint, Map<String, Object> specMeta) {
            fingerprints.add(keyFingerprint);
        }

        @Override
        public void onProgress(String contextId, long bodyByteCount, long trailerByteCount) {
            bodyBytes = bodyByteCount;
            trailerBytes = trailerByteCount;
        }

        @Override
        public void onTagProduced(String contextId, int tagLength, String policy) {
            tagEvents++;
        }

        @Override
        public void onVerifyResult(String contextId, boolean success, String policy, String expectedSource,
                int tagLength) {
            verificationResults.add(Boolean.valueOf(success));
        }

        @Override
        public void onFailure(String contextId, String stage, String operation, Throwable cause) {
            failures.add(cause);
        }

    }

    private static final class SensitiveStringDigest extends AuditedContextsAccessorTest.BaseDigest {
        private int toStringCalls;

        @Override
        public String toString() {
            toStringCalls++;
            return "SENSITIVE-TARGET-STATE";
        }
    }
}
