/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Proxy;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import zeroecho.core.audit.AuditListener;
import zeroecho.core.audit.AuditedContexts;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.CryptoContext;
import zeroecho.core.context.DigestContext;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.context.KemContext;
import zeroecho.core.context.KemContext.KemResult;
import zeroecho.core.context.MacContext;
import zeroecho.core.context.MessageAgreementContext;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.tag.TagEngine;

/**
 * Verifies audited proxy wrapping for representative {@link CryptoContext}
 * contract types.
 *
 * <p>
 * These tests focus on the internal audit wrapping path used by
 * {@link AuditedContexts#wrap(CryptoContext, AuditListener, KeyUsage)}.
 * They verify that representative context types are wrapped as audited JDK
 * proxies and that the resulting wrapper preserves the expected basic
 * delegation behavior.
 * </p>
 */
class CryptoAlgorithmsAuditWrapTest {

    @Test
    void wrapForAuditDigestContextReturnsProxy() {
        System.out.println("wrapForAuditDigestContextReturnsProxy");

        DigestContext context = mock(DigestContext.class);
        DigestContext wrapped = (DigestContext) AuditedContexts.wrap(context, AuditListener.noop(), KeyUsage.DIGEST);

        System.out.println("...ctxClass=" + wrapped.getClass().getName());
        assertTrue(Proxy.isProxyClass(wrapped.getClass()), "Digest context should be wrapped as JDK proxy");

        System.out.println("wrapForAuditDigestContextReturnsProxy...ok");
    }

    @Test
    void wrapForAuditAgreementContextReturnsProxy() {
        System.out.println("wrapForAuditAgreementContextReturnsProxy");

        AgreementContext context = mock(AgreementContext.class);
        AgreementContext wrapped = (AgreementContext) AuditedContexts.wrap(context, AuditListener.noop(),
                KeyUsage.AGREEMENT);

        System.out.println("...ctxClass=" + wrapped.getClass().getName());
        assertTrue(Proxy.isProxyClass(wrapped.getClass()), "Agreement context should be wrapped as JDK proxy");

        System.out.println("wrapForAuditAgreementContextReturnsProxy...ok");
    }

    @Test
    void wrapForAuditDigestContextCloseDelegatesToWrappedContext() throws Exception {
        System.out.println("wrapForAuditDigestContextCloseDelegatesToWrappedContext");

        DigestContext context = mock(DigestContext.class);
        DigestContext wrapped = (DigestContext) AuditedContexts.wrap(context, AuditListener.noop(), KeyUsage.DIGEST);

        wrapped.close();

        verify(context).close();
        System.out.println("...wrappedCloseDelegated=true");
        System.out.println("wrapForAuditDigestContextCloseDelegatesToWrappedContext...ok");
    }

    @Test
    void wrapAllFamilies() throws Exception {
        System.out.println("wrapAllFamilies");
        byte[] body = { 1, 2, 3 };

        RecordingListener encryptionEvents = new RecordingListener();
        EncryptionContext encryption = mock(EncryptionContext.class);
        when(encryption.attach(any(InputStream.class))).thenAnswer(invocation -> invocation.getArgument(0));
        EncryptionContext auditedEncryption = wrap(encryption, encryptionEvents, KeyUsage.ENCRYPT);
        assertArrayEquals(body, auditedEncryption.attach(new ByteArrayInputStream(body)).readAllBytes());
        encryptionEvents.assertCreationBefore("progress");

        assertTagFamily(mockTag(SignatureContext.class), KeyUsage.SIGN, body);
        assertTagFamily(mockTag(MacContext.class), KeyUsage.MAC, body);
        assertTagFamily(mockTag(DigestContext.class), KeyUsage.DIGEST, body);

        RecordingListener agreementEvents = new RecordingListener();
        AgreementContext agreement = mock(AgreementContext.class);
        PublicKey peer = mock(PublicKey.class);
        when(agreement.deriveSecret()).thenReturn(new byte[] { 4, 5 });
        AgreementContext auditedAgreement = wrap(agreement, agreementEvents, KeyUsage.AGREEMENT);
        auditedAgreement.setPeerPublic(peer);
        assertArrayEquals(new byte[] { 4, 5 }, auditedAgreement.deriveSecret());
        agreementEvents.assertCreationBefore("peer");
        agreementEvents.assertBefore("peer", "derived");

        RecordingListener messageEvents = new RecordingListener();
        MessageAgreementContext messageAgreement = mock(MessageAgreementContext.class);
        when(messageAgreement.getPeerMessage()).thenReturn(new byte[] { 6, 7, 8 });
        when(messageAgreement.deriveSecret()).thenReturn(new byte[] { 9 });
        MessageAgreementContext auditedMessage = wrap(messageAgreement, messageEvents, KeyUsage.AGREEMENT);
        auditedMessage.setPeerMessage(new byte[] { 6 });
        assertArrayEquals(new byte[] { 6, 7, 8 }, auditedMessage.getPeerMessage());
        assertArrayEquals(new byte[] { 9 }, auditedMessage.deriveSecret());
        messageEvents.assertCreationBefore("message-set");
        messageEvents.assertBefore("message-set", "message-get");
        messageEvents.assertBefore("message-get", "derived");

        RecordingListener kemEvents = new RecordingListener();
        KemContext kem = mock(KemContext.class);
        KemResult result = new KemResult(new byte[] { 10, 11 }, new byte[] { 12 });
        when(kem.encapsulate()).thenReturn(result);
        when(kem.decapsulate(any(byte[].class))).thenReturn(new byte[] { 12 });
        KemContext auditedKem = wrap(kem, kemEvents, KeyUsage.ENCAPSULATE);
        assertSame(result, auditedKem.encapsulate());
        assertArrayEquals(new byte[] { 12 }, auditedKem.decapsulate(new byte[] { 10, 11 }));
        kemEvents.assertCreationBefore("encapsulated");
        kemEvents.assertBefore("encapsulated", "decapsulated");

        System.out.println("...families=7");
        System.out.println("wrapAllFamilies...ok");
    }

    @Test
    void wrapFailureAndIdempotency() throws Exception {
        System.out.println("wrapFailureAndIdempotency");
        RecordingListener listener = new RecordingListener();
        IOException expected = new IOException("controlled read failure");
        EncryptionContext target = mock(EncryptionContext.class);
        when(target.attach(any(InputStream.class))).thenReturn(new InputStream() {
            @Override
            public int read() throws IOException {
                throw expected;
            }
        });

        EncryptionContext wrapped = wrap(target, listener, KeyUsage.DECRYPT);
        int eventsAfterCreation = listener.events.size();
        assertSame(wrapped, AuditedContexts.wrap(wrapped, listener, KeyUsage.DECRYPT));
        assertEquals(eventsAfterCreation, listener.events.size());

        IOException actual = assertThrows(IOException.class,
                () -> wrapped.attach(new ByteArrayInputStream(new byte[0])).readAllBytes());
        assertSame(expected, actual);
        assertEquals(1, listener.count("failure"));
        listener.assertCreationBefore("failure");

        System.out.println("...failureEvents=" + listener.count("failure"));
        System.out.println("wrapFailureAndIdempotency...ok");
    }

    private static <T extends CryptoContext> T wrap(T context, RecordingListener listener, KeyUsage usage) {
        @SuppressWarnings("unchecked")
        T wrapped = (T) AuditedContexts.wrap(context, listener, usage);
        assertTrue(Proxy.isProxyClass(wrapped.getClass()));
        return wrapped;
    }

    private static <T extends CryptoContext & TagEngine<?>> T mockTag(Class<T> type) throws IOException {
        T context = mock(type);
        when(context.tagLength()).thenReturn(2);
        when(context.wrap(any(InputStream.class))).thenAnswer(invocation -> {
            InputStream upstream = invocation.getArgument(0);
            return new java.io.SequenceInputStream(upstream, new ByteArrayInputStream(new byte[] { 0, 0 }));
        });
        return context;
    }

    private static void assertTagFamily(CryptoContext context, KeyUsage usage, byte[] body) throws IOException {
        RecordingListener listener = new RecordingListener();
        CryptoContext wrapped = wrap(context, listener, usage);
        TagEngine<?> engine = (TagEngine<?>) wrapped;
        byte[] output = engine.wrap(new ByteArrayInputStream(body)).readAllBytes();

        assertArrayEquals(new byte[] { 1, 2, 3, 0, 0 }, output);
        assertEquals(1, listener.count("tag"));
        listener.assertCreationBefore("tag");
    }

    private static final class RecordingListener implements AuditListener {
        private final List<String> events = new ArrayList<>();

        @Override
        public void onContextCreatedMeta(String contextId, String algorithmId, String provider, KeyUsage role,
                String keyFingerprint, Map<String, Object> specMeta) {
            events.add("meta");
        }

        @Override
        public void onProgress(String contextId, long bodyBytes, long trailerBytes) {
            events.add("progress");
        }

        @Override
        public void onTagProduced(String contextId, int tagLength, String policy) {
            events.add("tag");
        }

        @Override
        public void onAgreementPeerSet(String contextId, String peerFingerprint) {
            events.add("peer");
        }

        @Override
        public void onAgreementDerived(String contextId, int secretLength) {
            events.add("derived");
        }

        @Override
        public void onAgreementPeerMessageSet(String contextId, int messageLength) {
            events.add("message-set");
        }

        @Override
        public void onAgreementPeerMessageGet(String contextId, int messageLength) {
            events.add("message-get");
        }

        @Override
        public void onKemEncapsulated(int ciphertextLength, int sharedSecretLength) {
            events.add("encapsulated");
        }

        @Override
        public void onKemDecapsulated(int sharedSecretLength) {
            events.add("decapsulated");
        }

        @Override
        public void onFailure(String contextId, String stage, String operation, Throwable cause) {
            events.add("failure");
        }

        private int count(String event) {
            return (int) events.stream().filter(event::equals).count();
        }

        private void assertCreationBefore(String event) {
            assertEquals("meta", events.get(0));
            assertEquals(1, count("meta"));
            assertTrue(events.indexOf(event) > 0);
        }

        private void assertBefore(String first, String second) {
            assertTrue(events.indexOf(first) < events.indexOf(second));
        }
    }
}
