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
package zeroecho.core.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.Signature;
import java.util.Arrays;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.policy.CryptoPolicy;
import zeroecho.core.spec.ContextSpec;
import zeroecho.sdk.ZeroEchoSession;

final class KeyringSignatureExecutorTest {
    private static final char[] PASSWORD = { 'e', 'x', 'e', 'c', 'u', 't', 'o', 'r' };
    private static final String PRIVATE_ALIAS = "signing.prv";

    @TempDir
    Path temporaryDirectory;

    private KeyringStore keyring;
    private KeyPair keyPair;

    @BeforeEach
    void createKeyring() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        try (KeyringPassword password = password()) {
            keyring = KeyringStore.create(temporaryDirectory.resolve("executor.zek"), password);
        }
        keyring.putPrivate(PRIVATE_ALIAS, "RSA", keyPair.getPrivate());
    }

    @AfterEach
    void closeKeyring() {
        keyring.close();
    }

    @Test
    void rejectsStatefulStoredMetadataAndActualKeysBeforeSessionOrContent() throws Exception {
        for (String algorithm : java.util.List.of("LMS", "XMSS")) {
            KeyringStore mockedStore = mock(KeyringStore.class);
            ZeroEchoSession session = mock(ZeroEchoSession.class);
            PrivateKey key = mock(PrivateKey.class);
            when(key.getAlgorithm()).thenReturn(algorithm);
            when(mockedStore.getPrivateWithId(PRIVATE_ALIAS))
                    .thenReturn(new KeyringStore.PrivateWithId("RSA", key));
            TestContent content = new TestContent(() -> { throw new AssertionError("No content read"); });
            KeyringSignatureExecutor.Failure failure = assertThrows(KeyringSignatureExecutor.Failure.class,
                    () -> new KeyringSignatureExecutor(mockedStore, session).sign(PRIVATE_ALIAS,
                            BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, content, CancellationSignal.NONE));
            assertEquals(KeyringSignatureExecutor.FailureCode.ALGORITHM_MISMATCH, failure.code());
            org.mockito.Mockito.verifyNoInteractions(session);
            assertEquals(0, content.openCount.get());
        }
    }

    @Test
    void signsMultipleBuffersAndReturnedSignatureVerifies() throws Exception {
        System.out.println("signsMultipleBuffersAndReturnedSignatureVerifies");
        byte[] payload = new byte[96 * 1024 + 37];
        for (int index = 0; index < payload.length; index++) {
            payload[index] = (byte) index;
        }
        AtomicInteger delegateCloseCount = new AtomicInteger();
        TestContent content = new TestContent(() -> new ByteArrayInputStream(payload) {
            @Override
            public void close() throws IOException {
                if (delegateCloseCount.incrementAndGet() > 1) {
                    throw new IOException("delegate closed more than once");
                }
                super.close();
            }
        });

        byte[] signature = executor(new ZeroEchoSession()).sign(PRIVATE_ALIAS,
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, content, CancellationSignal.NONE);

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(payload);
        assertTrue(verifier.verify(signature));
        assertEquals(1, content.openCount.get());
        assertEquals(1, content.streamCloseCount.get());
        assertEquals(1, delegateCloseCount.get());
        assertFalse(content.closed.get());
        System.out.println("...payload=" + payload.length + " bytes");
        System.out.println("signsMultipleBuffersAndReturnedSignatureVerifies...ok");
    }

    @Test
    void rejectsUnavailableKeysInvalidIdentitiesAndIncompatibleAlgorithms() throws Exception {
        System.out.println("rejectsUnavailableKeysInvalidIdentitiesAndIncompatibleAlgorithms");
        KeyringSignatureExecutor executor = executor(new ZeroEchoSession());
        TestContent content = TestContent.bytes(new byte[] { 1, 2, 3 });

        KeyringSignatureExecutor.Failure missing = assertThrows(KeyringSignatureExecutor.Failure.class,
                () -> executor.sign("missing.prv", BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, content,
                        CancellationSignal.NONE));
        assertEquals(KeyringSignatureExecutor.FailureCode.KEY_UNAVAILABLE, missing.code());
        assertEquals("KEY_UNAVAILABLE", missing.getMessage());
        assertRedacted(missing, "missing.prv");

        assertThrows(IllegalArgumentException.class,
                () -> executor.sign(PRIVATE_ALIAS, BootstrapAlgorithmIdentities.SHA256, content,
                        CancellationSignal.NONE));
        assertThrows(IllegalArgumentException.class,
                () -> executor.sign(" ", BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, content,
                        CancellationSignal.NONE));

        KeyringSignatureExecutor.Failure incompatible = assertThrows(KeyringSignatureExecutor.Failure.class,
                () -> executor.sign(PRIVATE_ALIAS, BootstrapAlgorithmIdentities.ECDSA_SHA256, content,
                        CancellationSignal.NONE));
        assertEquals(KeyringSignatureExecutor.FailureCode.ALGORITHM_MISMATCH, incompatible.code());
        assertEquals(0, content.openCount.get());
        System.out.println("rejectsUnavailableKeysInvalidIdentitiesAndIncompatibleAlgorithms...ok");
    }

    @Test
    void closedKeyringPreservesIoFailureAndPolicyDenialIsRedacted() throws Exception {
        System.out.println("closedKeyringPreservesIoFailureAndPolicyDenialIsRedacted");
        TestContent content = TestContent.bytes(new byte[] { 4, 5, 6 });
        ZeroEchoSession deniedSession = new ZeroEchoSession().withPolicy(
                (CryptoPolicy<ContextSpec, java.security.Key>) (id, role, key, spec) -> {
                    throw new IllegalArgumentException("PROVIDER_SENTINEL");
                });
        KeyringSignatureExecutor.Failure denied = assertThrows(KeyringSignatureExecutor.Failure.class,
                () -> executor(deniedSession).sign(PRIVATE_ALIAS, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                        content, CancellationSignal.NONE));
        assertEquals(KeyringSignatureExecutor.FailureCode.PROVIDER_FAILURE, denied.code());
        assertEquals("PROVIDER_FAILURE", denied.getMessage());
        assertRedacted(denied, "PROVIDER_SENTINEL");

        KeyringStore unsafeKeyring = mock(KeyringStore.class);
        ProviderException importFailure = new ProviderException("KEY_IMPORT_SENTINEL",
                new IllegalStateException("KEY_IMPORT_NESTED_SENTINEL"));
        importFailure.addSuppressed(new IOException("KEY_IMPORT_SUPPRESSED_SENTINEL"));
        when(unsafeKeyring.getPrivateWithId(PRIVATE_ALIAS)).thenThrow(importFailure);
        KeyringSignatureExecutor.Failure keyImport = assertThrows(KeyringSignatureExecutor.Failure.class,
                () -> new KeyringSignatureExecutor(unsafeKeyring, new ZeroEchoSession()).sign(PRIVATE_ALIAS,
                        BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, content, CancellationSignal.NONE));
        assertEquals(KeyringSignatureExecutor.FailureCode.PROVIDER_FAILURE, keyImport.code());
        assertRedacted(keyImport, "KEY_IMPORT_SENTINEL");
        assertRedacted(keyImport, "KEY_IMPORT_NESTED_SENTINEL");
        assertRedacted(keyImport, "KEY_IMPORT_SUPPRESSED_SENTINEL");

        keyring.close();
        assertThrows(IOException.class,
                () -> executor(new ZeroEchoSession()).sign(PRIVATE_ALIAS,
                        BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, content, CancellationSignal.NONE));
        assertEquals(0, content.openCount.get());
        System.out.println("closedKeyringPreservesIoFailureAndPolicyDenialIsRedacted...ok");
    }

    @Test
    void cancellationWinsBeforeResolutionAndStopsDuringStreaming() throws Exception {
        System.out.println("cancellationWinsBeforeResolutionAndStopsDuringStreaming");
        TestContent unopened = TestContent.bytes(new byte[] { 7 });
        AtomicInteger cancellationChecks = new AtomicInteger();
        CancellationSignal oneShotCancellation = () -> {
            if (cancellationChecks.incrementAndGet() > 1) {
                throw new IllegalStateException("CANCELLATION_RECHECK_SENTINEL");
            }
            return true;
        };
        assertThrows(InterruptedIOException.class,
                () -> executor(new ZeroEchoSession()).sign("missing.prv",
                        BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, unopened, oneShotCancellation));
        assertEquals(1, cancellationChecks.get());
        assertEquals(0, unopened.openCount.get());

        AtomicBoolean cancelled = new AtomicBoolean();
        AtomicInteger streamingCancellationChecks = new AtomicInteger();
        AtomicInteger streamingReadCalls = new AtomicInteger();
        TestContent streaming = new TestContent(() -> new InputStream() {
            private boolean first = true;

            @Override
            public int read() {
                return -1;
            }

            @Override
            public int read(byte[] bytes, int offset, int length) {
                if (streamingReadCalls.incrementAndGet() > 1) {
                    throw new IllegalStateException("POST_CANCELLATION_DRAIN_SENTINEL");
                }
                if (!first) {
                    return -1;
                }
                first = false;
                int count = Math.min(length, 4096);
                Arrays.fill(bytes, offset, offset + count, (byte) 0x5a);
                cancelled.set(true);
                return count;
            }
        });
        assertThrows(InterruptedIOException.class,
                () -> executor(new ZeroEchoSession()).sign(PRIVATE_ALIAS,
                        BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, streaming, () -> {
                            if (streamingCancellationChecks.incrementAndGet() > 5) {
                                throw new IllegalStateException("POST_CANCELLATION_CHECK_SENTINEL");
                            }
                            return cancelled.get();
                        }));
        assertEquals(5, streamingCancellationChecks.get());
        assertEquals(1, streamingReadCalls.get());
        assertEquals(1, streaming.streamCloseCount.get());
        assertFalse(streaming.closed.get());
        System.out.println("cancellationWinsBeforeResolutionAndStopsDuringStreaming...ok");
    }

    @Test
    void zeroProgressAndFailingContentAreCheckedAndClosed() throws Exception {
        System.out.println("zeroProgressAndFailingContentAreCheckedAndClosed");
        TestContent zeroProgress = new TestContent(() -> new InputStream() {
            @Override
            public int read() {
                return 0;
            }

            @Override
            public int read(byte[] bytes, int offset, int length) {
                return 0;
            }
        });
        assertThrows(IOException.class,
                () -> executor(new ZeroEchoSession()).sign(PRIVATE_ALIAS,
                        BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, zeroProgress, CancellationSignal.NONE));
        assertEquals(1, zeroProgress.streamCloseCount.get());

        IOException controlledFailure = new IOException("controlled read failure");
        AtomicInteger failingReadCalls = new AtomicInteger();
        TestContent failing = new TestContent(() -> new InputStream() {
            @Override
            public int read() throws IOException {
                throw controlledFailure;
            }

            @Override
            public int read(byte[] bytes, int offset, int length) throws IOException {
                if (failingReadCalls.incrementAndGet() > 1) {
                    throw new IllegalStateException("POST_CONTENT_FAILURE_DRAIN_SENTINEL");
                }
                throw controlledFailure;
            }
        });
        AtomicInteger contentCancellationChecks = new AtomicInteger();
        IOException observedFailure = assertThrows(IOException.class,
                () -> executor(new ZeroEchoSession()).sign(PRIVATE_ALIAS,
                        BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, failing, () -> {
                            if (contentCancellationChecks.incrementAndGet() > 4) {
                                throw new IllegalStateException("CONTENT_CANCELLATION_RECHECK_SENTINEL");
                            }
                            return false;
                        }));
        assertSame(controlledFailure, observedFailure);
        assertEquals(4, contentCancellationChecks.get());
        assertEquals(1, failingReadCalls.get());
        assertEquals(1, failing.streamCloseCount.get());
        assertFalse(failing.closed.get());
        System.out.println("zeroProgressAndFailingContentAreCheckedAndClosed...ok");
    }

    @Test
    void providerIoAndMalformedResultsAreRedactedProviderFailures() throws Exception {
        System.out.println("providerIoAndMalformedResultsAreRedactedProviderFailures");
        TestContent content = TestContent.bytes(new byte[] { 1, 2, 3 });

        SignatureContext tagLengthFailure = mock(SignatureContext.class);
        when(tagLengthFailure.tagLength()).thenThrow(new ProviderException("PROVIDER_TAG_LENGTH_SENTINEL"));
        KeyringSignatureExecutor.Failure tagLength = assertThrows(KeyringSignatureExecutor.Failure.class,
                () -> executor(mockSession(tagLengthFailure)).sign(PRIVATE_ALIAS,
                        BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, content, CancellationSignal.NONE));
        assertEquals(KeyringSignatureExecutor.FailureCode.PROVIDER_FAILURE, tagLength.code());
        assertRedacted(tagLength, "PROVIDER_TAG_LENGTH_SENTINEL");

        SignatureContext wrapFailure = mockContext(256);
        when(wrapFailure.wrap(any(InputStream.class))).thenThrow(new IOException("PROVIDER_WRAP_SENTINEL"));
        AtomicInteger providerCancellationChecks = new AtomicInteger();
        KeyringSignatureExecutor.Failure wrap = assertThrows(KeyringSignatureExecutor.Failure.class,
                () -> executor(mockSession(wrapFailure)).sign(PRIVATE_ALIAS,
                        BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, content, () -> {
                            if (providerCancellationChecks.incrementAndGet() > 2) {
                                throw new IllegalStateException("PROVIDER_CANCELLATION_RECHECK_SENTINEL");
                            }
                            return false;
                        }));
        assertEquals(KeyringSignatureExecutor.FailureCode.PROVIDER_FAILURE, wrap.code());
        assertRedacted(wrap, "PROVIDER_WRAP_SENTINEL");
        assertEquals(2, providerCancellationChecks.get());

        SignatureContext readFailure = mockContext(256);
        when(readFailure.wrap(any(InputStream.class))).thenReturn(new InputStream() {
            @Override
            public int read() throws IOException {
                throw new IOException("PROVIDER_READ_SENTINEL");
            }
        });
        KeyringSignatureExecutor.Failure read = assertThrows(KeyringSignatureExecutor.Failure.class,
                () -> executor(mockSession(readFailure)).sign(PRIVATE_ALIAS,
                        BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, content, CancellationSignal.NONE));
        assertEquals(KeyringSignatureExecutor.FailureCode.PROVIDER_FAILURE, read.code());
        assertRedacted(read, "PROVIDER_READ_SENTINEL");

        SignatureContext closeFailure = mockContext(256);
        when(closeFailure.wrap(any(InputStream.class))).thenReturn(new ByteArrayInputStream(new byte[256]));
        doThrow(new IOException("PROVIDER_CLOSE_SENTINEL")).when(closeFailure).close();
        KeyringSignatureExecutor.Failure close = assertThrows(KeyringSignatureExecutor.Failure.class,
                () -> executor(mockSession(closeFailure)).sign(PRIVATE_ALIAS,
                        BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, content, CancellationSignal.NONE));
        assertEquals(KeyringSignatureExecutor.FailureCode.PROVIDER_FAILURE, close.code());
        assertRedacted(close, "PROVIDER_CLOSE_SENTINEL");

        SignatureContext runtimeCloseFailure = mockContext(256);
        when(runtimeCloseFailure.wrap(any(InputStream.class))).thenReturn(new ByteArrayInputStream(new byte[256]));
        doThrow(new ProviderException("PROVIDER_RUNTIME_CLOSE_SENTINEL")).when(runtimeCloseFailure).close();
        KeyringSignatureExecutor.Failure runtimeClose = assertThrows(KeyringSignatureExecutor.Failure.class,
                () -> executor(mockSession(runtimeCloseFailure)).sign(PRIVATE_ALIAS,
                        BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, content, CancellationSignal.NONE));
        assertEquals(KeyringSignatureExecutor.FailureCode.PROVIDER_FAILURE, runtimeClose.code());
        assertRedacted(runtimeClose, "PROVIDER_RUNTIME_CLOSE_SENTINEL");

        SignatureContext malformedContext = mockContext(256);
        when(malformedContext.wrap(any(InputStream.class))).thenReturn(new ByteArrayInputStream(new byte[8]));
        KeyringSignatureExecutor.Failure malformed = assertThrows(KeyringSignatureExecutor.Failure.class,
                () -> executor(mockSession(malformedContext)).sign(PRIVATE_ALIAS,
                        BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, content, CancellationSignal.NONE));
        assertEquals(KeyringSignatureExecutor.FailureCode.PROVIDER_FAILURE, malformed.code());
        assertRedacted(malformed, "MALFORMED_RESULT_SENTINEL");
        System.out.println("providerIoAndMalformedResultsAreRedactedProviderFailures...ok");
    }

    @Test
    void publicSurfaceAndFieldsExposeNoPrivateKeyTypes() {
        System.out.println("publicSurfaceAndFieldsExposeNoPrivateKeyTypes");
        for (Field field : KeyringSignatureExecutor.class.getDeclaredFields()) {
            assertFalse(PrivateKey.class.isAssignableFrom(field.getType()));
        }
        for (Method method : KeyringSignatureExecutor.class.getDeclaredMethods()) {
            if (!Modifier.isPublic(method.getModifiers())) {
                continue;
            }
            if ("sign".equals(method.getName())) {
                assertEquals(1, Arrays.stream(method.getParameterTypes()).filter(String.class::equals).count());
            }
            assertFalse(PrivateKey.class.isAssignableFrom(method.getReturnType()));
            assertFalse(KeyringStore.PrivateWithId.class.isAssignableFrom(method.getReturnType()));
            for (Class<?> parameterType : method.getParameterTypes()) {
                assertFalse(PrivateKey.class.isAssignableFrom(parameterType));
                assertFalse(KeyringStore.PrivateWithId.class.isAssignableFrom(parameterType));
                assertFalse(KeyPair.class.isAssignableFrom(parameterType));
            }
        }
        System.out.println("publicSurfaceAndFieldsExposeNoPrivateKeyTypes...ok");
    }

    private KeyringSignatureExecutor executor(ZeroEchoSession session) {
        return new KeyringSignatureExecutor(keyring, session);
    }

    private static ZeroEchoSession mockSession(SignatureContext context) {
        ZeroEchoSession session = mock(ZeroEchoSession.class);
        doReturn(context).when(session).createContext(anyString(), eq(KeyUsage.SIGN), any(PrivateKey.class),
                any(ContextSpec.class));
        return session;
    }

    private static SignatureContext mockContext(int signatureLength) {
        SignatureContext context = mock(SignatureContext.class);
        when(context.tagLength()).thenReturn(signatureLength);
        return context;
    }

    private static void assertRedacted(KeyringSignatureExecutor.Failure failure, String sentinel) {
        assertEquals(null, failure.getCause());
        assertEquals(0, failure.getSuppressed().length);
        assertFalse(failure.toString().contains(sentinel));
    }

    private static KeyringPassword password() {
        return new KeyringPassword(PASSWORD);
    }

    @FunctionalInterface
    private interface InputFactory {
        InputStream open() throws IOException;
    }

    private static final class TestContent implements RepeatableContent {
        private final InputFactory factory;
        private final AtomicInteger openCount = new AtomicInteger();
        private final AtomicInteger streamCloseCount = new AtomicInteger();
        private final AtomicBoolean closed = new AtomicBoolean();

        private TestContent(InputFactory factory) {
            this.factory = factory;
        }

        private static TestContent bytes(byte[] bytes) {
            return new TestContent(() -> new ByteArrayInputStream(bytes));
        }

        @Override
        public InputStream openStream() throws IOException {
            openCount.incrementAndGet();
            InputStream delegate = factory.open();
            return new java.io.FilterInputStream(delegate) {
                private boolean streamClosed;

                @Override
                public void close() throws IOException {
                    if (streamClosed) {
                        return;
                    }
                    streamClosed = true;
                    streamCloseCount.incrementAndGet();
                    super.close();
                }
            };
        }

        @Override
        public OptionalLong length() {
            return OptionalLong.empty();
        }

        @Override
        public String contentId() {
            return "executor-test-content";
        }

        @Override
        public void close() {
            closed.set(true);
        }
    }
}
