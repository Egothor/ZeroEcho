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
package zeroecho.pki.server.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import zeroecho.pki.server.PkiServerConfiguration;

/** Deterministic bounded-admission, queue, cancellation and worker-close tests. */
class ServerRuntimeTest {
    @Test
    void enforcesFixedWorkersBoundedQueueAndPermitRelease() throws Exception {
        System.out.println("enforcesFixedWorkersBoundedQueueAndPermitRelease");
        ServerRuntime runtime = new ServerRuntime(configuration());
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try {
            assertTrue(runtime.tryAdmit());
            assertEquals(false, runtime.tryAdmit());
            runtime.releaseAdmission();
            ServerRuntime.Submitted<String> first = runtime.submit(cancellation -> {
                started.countDown();
                release.await();
                return Thread.currentThread().getName();
            });
            assertTrue(started.await(2, TimeUnit.SECONDS));
            ServerRuntime.Submitted<String> waiting = runtime.submit(cancellation -> "queued");
            assertEquals(1, runtime.activeOperations());
            assertEquals(1, runtime.operationQueueSize());
            assertThrows(RejectedExecutionException.class, () -> runtime.submit(cancellation -> "rejected"));
            release.countDown();
            assertTrue(first.future().get(2, TimeUnit.SECONDS).startsWith(ServerRuntime.OPERATION_PREFIX));
            assertEquals("queued", waiting.future().get(2, TimeUnit.SECONDS));
            first.finish();
            waiting.finish();
            System.out.println("...maximum-concurrent=1");
        } finally {
            release.countDown();
            runtime.close();
        }
        System.out.println("...ok");
    }

    @Test
    void closesFromOperationWorkerWithoutWaitingForItself() throws Exception {
        System.out.println("closesFromOperationWorkerWithoutWaitingForItself");
        ServerRuntime runtime = new ServerRuntime(configuration());
        ServerRuntime.Submitted<Boolean> submitted = runtime.submit(cancellation -> {
            runtime.close();
            return Thread.currentThread().isInterrupted();
        });
        submitted.future().get(2, TimeUnit.SECONDS);
        submitted.finish();
        assertEquals(false, runtime.accepting());
        System.out.println("...self-wait=false");
        System.out.println("...ok");
    }

    private static PkiServerConfiguration.Execution configuration() {
        return new PkiServerConfiguration.Execution(1, 1, 1, 1, 1,
                Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofMillis(100),
                Duration.ofMillis(100));
    }
}
