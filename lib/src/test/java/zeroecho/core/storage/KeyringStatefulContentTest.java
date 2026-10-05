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
package zeroecho.core.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.OptionalLong;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.sdk.util.BouncyCastleActivator;

class KeyringStatefulContentTest {
    @TempDir Path root;
    @BeforeAll static void provider() { BouncyCastleActivator.init(); }

    @Test void contentLimitsCancellationAndFailuresBurnOnlyAdmittedLeaves() throws Exception {
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.create(root.resolve("keys/store"), password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.create(root.resolve("authority"))) {
            store.generateStatefulKey("key", "XMSS", authority);
            StatefulSigner signer = store.statefulSigner("key", authority);
            assertThrows(IOException.class, () -> signer.sign(new ImmutableByteContent(new byte[4]), () -> true, 4));
            assertThrows(IOException.class, () -> signer.sign(new ImmutableByteContent(new byte[5]), CancellationSignal.NONE, 4));
            assertThrows(IllegalArgumentException.class, () -> signer.sign(new ImmutableByteContent(new byte[0]), CancellationSignal.NONE, -1));
            assertEquals(0, KeyringStatefulSigningTest.leaf("XMSS", KeyringStatefulSigningTest.sign(signer)));
            for (OptionalLong declared : new OptionalLong[] { OptionalLong.empty(), OptionalLong.of(0) }) {
                AtomicBoolean closed = new AtomicBoolean();
                RepeatableContent content = content(new ByteArrayInputStream(new byte[5]) {
                    @Override public void close() { closed.set(true); }
                }, declared);
                assertThrows(IOException.class, () -> signer.sign(content, CancellationSignal.NONE, 4));
                assertTrue(closed.get());
            }
            AtomicBoolean cancelled = new AtomicBoolean();
            AtomicBoolean closed = new AtomicBoolean();
            RepeatableContent content = content(new ByteArrayInputStream(new byte[1]) {
                @Override public synchronized int read(byte[] bytes, int offset, int length) {
                    cancelled.set(true);
                    return super.read(bytes, offset, length);
                }
                @Override public void close() { closed.set(true); }
            }, OptionalLong.empty());
            assertThrows(IOException.class, () -> signer.sign(content, cancelled::get, 4));
            assertTrue(closed.get());
            RepeatableContent stalled = content(new InputStream() {
                @Override public int read() { return 0; }
                @Override public int read(byte[] bytes, int offset, int length) { return 0; }
            }, OptionalLong.empty());
            assertThrows(IOException.class, () -> signer.sign(stalled, CancellationSignal.NONE, 4));
            byte[] empty = signer.sign(new ImmutableByteContent(new byte[0]), CancellationSignal.NONE, 0);
            assertEquals(5, KeyringStatefulSigningTest.leaf("XMSS", empty));
            java.security.Signature verifier = java.security.Signature.getInstance("XMSS", "BCPQC");
            verifier.initVerify(store.getPublic("key"));
            assertTrue(verifier.verify(empty));
        }
    }

    @Test void closeWaitsForAdmittedSignatureAndBorrowedHandleThenFails() throws Exception {
        CountDownLatch reading = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch closing = new CountDownLatch(1);
        try (KeyringPassword password = KeyringStatefulSigningTest.password();
                KeyringStore store = KeyringStore.create(root.resolve("keys/store"), password);
                LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.create(root.resolve("authority"));
                java.util.concurrent.ExecutorService workers = Executors.newFixedThreadPool(2)) {
            store.generateStatefulKey("key", "LMS", authority);
            StatefulSigner signer = store.statefulSigner("key", authority);
            RepeatableContent content = content(new ByteArrayInputStream(new byte[0]) {
                @Override public synchronized int read(byte[] bytes, int offset, int length) {
                    reading.countDown();
                    try { assertTrue(release.await(30, TimeUnit.SECONDS)); }
                    catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new AssertionError(failure); }
                    return -1;
                }
            }, OptionalLong.empty());
            java.util.concurrent.Future<byte[]> signing = workers.submit(() -> signer.sign(content, CancellationSignal.NONE, 0));
            try {
                assertTrue(reading.await(30, TimeUnit.SECONDS));
                java.util.concurrent.Future<?> close = workers.submit(() -> { closing.countDown(); authority.close(); return null; });
                assertTrue(closing.await(30, TimeUnit.SECONDS));
                release.countDown();
                assertEquals(0, KeyringStatefulSigningTest.leaf("LMS", signing.get(30, TimeUnit.SECONDS)));
                close.get(30, TimeUnit.SECONDS);
                assertThrows(IOException.class, signer::signatureLength);
            } finally { release.countDown(); }
        }
    }

    private static RepeatableContent content(InputStream input, OptionalLong length) {
        return new RepeatableContent() {
            @Override public InputStream openStream() { return input; }
            @Override public OptionalLong length() { return length; }
            @Override public String contentId() { return "fault-fixture"; }
            @Override public void close() { }
        };
    }
}
