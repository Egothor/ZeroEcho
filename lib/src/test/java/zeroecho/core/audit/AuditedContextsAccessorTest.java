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
package zeroecho.core.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.KeyUsage;
import zeroecho.core.NullKey;
import zeroecho.core.alg.aes.AesAlgorithm;
import zeroecho.core.context.DigestContext;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.spec.ContextSpec;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;

public class AuditedContextsAccessorTest {
    @Test
    void specAccessorBinding() {
        System.out.println("specAccessorBinding");
        MetadataListener firstListener = new MetadataListener();
        MetadataListener secondListener = new MetadataListener();
        MetadataListener missingListener = new MetadataListener();
        MetadataListener incompatibleListener = new MetadataListener();

        AuditedContexts.wrap(new FirstSpecDigest(), firstListener, KeyUsage.DIGEST);
        AuditedContexts.wrap(new SecondSpecDigest(), secondListener, KeyUsage.DIGEST);
        AuditedContexts.wrap(new BaseDigest(), missingListener, KeyUsage.DIGEST);
        AuditedContexts.wrap(new IncompatibleAccessorsContext(), incompatibleListener, KeyUsage.ENCRYPT);

        assertNotNull(firstListener.specMeta);
        assertNotNull(secondListener.specMeta);
        assertNull(missingListener.specMeta);
        assertNull(incompatibleListener.specMeta);
        assertEquals("default", firstListener.provider);
        assertEquals("default", secondListener.provider);
        System.out.println("...runtimeClasses=4");
        System.out.println("specAccessorBinding...ok");
    }

    @Test
    void tagLengthAccessorBinding() throws Exception {
        System.out.println("tagLengthAccessorBinding");
        BaseDigest explicitTarget = new BaseDigest();
        DigestContext explicit = (DigestContext) AuditedContexts.wrap(explicitTarget, AuditListener.noop(),
                KeyUsage.DIGEST);
        assertEquals(4, explicit.tagLength());
        assertEquals(4, explicit.tagLength());
        explicit.wrap(new ByteArrayInputStream(new byte[] { 1 })).readAllBytes();
        assertEquals(2, explicitTarget.tagCalls.get());

        BaseDigest lazyTarget = new BaseDigest();
        DigestContext lazy = (DigestContext) AuditedContexts.wrap(lazyTarget, AuditListener.noop(), KeyUsage.DIGEST);
        lazy.wrap(new ByteArrayInputStream(new byte[] { 1 })).readAllBytes();
        lazy.wrap(new ByteArrayInputStream(new byte[] { 2 })).readAllBytes();
        assertEquals(1, lazyTarget.tagCalls.get());

        BaseDigest concurrentTarget = new BaseDigest();
        DigestContext concurrent = (DigestContext) AuditedContexts.wrap(concurrentTarget, AuditListener.noop(),
                KeyUsage.DIGEST);
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<java.util.concurrent.Callable<Integer>> calls = new ArrayList<>();
            for (int index = 0; index < 64; index++) {
                calls.add(concurrent::tagLength);
            }
            for (java.util.concurrent.Future<Integer> result : executor.invokeAll(calls)) {
                assertEquals(4, result.get());
            }
        } finally {
            executor.close();
        }
        assertEquals(64, concurrentTarget.tagCalls.get());
        System.out.println("...concurrentCalls=" + concurrentTarget.tagCalls.get());
        System.out.println("tagLengthAccessorBinding...ok");
    }

    @Test
    void accessorFailureOrder() throws Exception {
        System.out.println("accessorFailureOrder");
        RecordingListener listener = new RecordingListener();
        IllegalStateException expected = new IllegalStateException("controlled tag failure");
        DigestContext failing = (DigestContext) AuditedContexts.wrap(new FailingDigest(expected), listener,
                KeyUsage.DIGEST);

        IllegalStateException actual = assertThrows(IllegalStateException.class, failing::tagLength);
        assertSame(expected, actual);
        assertSame(expected, listener.failure);
        assertEquals(List.of("meta", "failure"), listener.events);

        RecordingListener successListener = new RecordingListener();
        DigestContext successful = (DigestContext) AuditedContexts.wrap(new BaseDigest(), successListener,
                KeyUsage.DIGEST);
        successful.wrap(new ByteArrayInputStream(new byte[] { 1, 2, 3 })).readAllBytes();
        assertEquals("meta", successListener.events.get(0));
        assertEquals("tag", successListener.events.get(successListener.events.size() - 1));
        System.out.println("...failureEvents=" + listener.events.size());
        System.out.println("accessorFailureOrder...ok");
    }

    public interface SpecAccessor {
        ContextSpec spec();
    }

    public interface IncompatibleAccessors {
        InputStream wrap(InputStream input);

        String spec();

        String tagLength();
    }

    public record TestSpec(String name) implements ContextSpec {
    }

    public static class BaseDigest implements DigestContext {
        private final AtomicInteger tagCalls = new AtomicInteger();

        @Override
        public InputStream wrap(InputStream upstream) {
            return new java.io.SequenceInputStream(upstream, new ByteArrayInputStream(new byte[4]));
        }

        @Override
        public int tagLength() {
            tagCalls.incrementAndGet();
            return 4;
        }

        @Override
        public void setVerificationApproach(VerificationBiPredicate<byte[]> strategy) {
            // Not needed by this test context.
        }

        @Override
        public VerificationBiPredicate<byte[]> getVerificationCore() {
            return null;
        }

        @Override
        public CryptoAlgorithm algorithm() {
            return new AesAlgorithm();
        }

        @Override
        public Key key() {
            return NullKey.INSTANCE;
        }

        @Override
        public void close() {
            // No resources.
        }
    }

    public static final class FirstSpecDigest extends BaseDigest implements SpecAccessor {
        @Override
        public ContextSpec spec() {
            return new TestSpec("first");
        }
    }

    public static final class SecondSpecDigest extends BaseDigest implements SpecAccessor {
        @Override
        public ContextSpec spec() {
            return new TestSpec("second");
        }
    }

    public static final class FailingDigest extends BaseDigest {
        private final IllegalStateException failure;

        private FailingDigest(IllegalStateException failure) {
            this.failure = failure;
        }

        @Override
        public int tagLength() {
            throw failure;
        }
    }

    public static final class IncompatibleAccessorsContext implements EncryptionContext, IncompatibleAccessors {
        @Override
        public InputStream attach(InputStream upstream) {
            return upstream;
        }

        @Override
        public InputStream wrap(InputStream input) {
            return input;
        }

        @Override
        public String spec() {
            return "not a context spec";
        }

        @Override
        public String tagLength() {
            return "not an integer";
        }

        @Override
        public CryptoAlgorithm algorithm() {
            return new AesAlgorithm();
        }

        @Override
        public Key key() {
            return NullKey.INSTANCE;
        }

        @Override
        public void close() {
            // No resources.
        }
    }

    private static class MetadataListener implements AuditListener {
        private String provider;
        private Map<String, Object> specMeta;

        @Override
        public void onContextCreatedMeta(String ctxId, String algoId, String providerName, KeyUsage role,
                String keyFingerprint, Map<String, Object> metadata) {
            provider = providerName;
            specMeta = metadata;
        }
    }

    private static final class RecordingListener extends MetadataListener {
        private final List<String> events = new ArrayList<>();
        private Throwable failure;

        @Override
        public void onContextCreatedMeta(String ctxId, String algoId, String providerName, KeyUsage role,
                String keyFingerprint, Map<String, Object> metadata) {
            super.onContextCreatedMeta(ctxId, algoId, providerName, role, keyFingerprint, metadata);
            events.add("meta");
        }

        @Override
        public void onFailure(String ctxId, String stage, String operation, Throwable cause) {
            failure = cause;
            events.add("failure");
        }

        @Override
        public void onTagProduced(String ctxId, int tagLength, String policy) {
            events.add("tag");
        }
    }
}
