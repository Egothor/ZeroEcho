/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
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
package zeroecho.pki.util.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.impl.async.PkiCodecs;
import zeroecho.pki.util.async.codec.ResultCodec;
import zeroecho.pki.util.async.impl.AppendOnlyLineStore;
import zeroecho.pki.util.async.impl.DurableAsyncBus;

public class DurableAsyncBusTest {

    @TempDir
    Path tempDir;

    @Test
    public void submitUpdateConsume_removesResultAndOperation() {
        System.out.println("submitUpdateConsume_removesResultAndOperation");

        Path log = tempDir.resolve("async.log");
        System.out.println("...log=" + log.getFileName());

        AppendOnlyLineStore store = new AppendOnlyLineStore(log);

        DurableAsyncBus<PkiId, Principal, String, String> bus = new DurableAsyncBus<PkiId, Principal, String, String>(
                PkiCodecs.PKI_ID, PkiCodecs.PRINCIPAL, PkiCodecs.STRING, new ResultCodec<String>() {
                    @Override
                    public String encode(String result) {
                        return result;
                    }

                    @Override
                    public String decode(String token) {
                        return token;
                    }
                }, store);

        PkiId opId = new PkiId("op-1");
        Principal owner = new Principal("USER", "alice");
        bus.registerEndpoint("endpoint-1", new AsyncEndpoint<PkiId, String>() {
            @Override
            public Optional<AsyncStatus> status(PkiId id) {
                return Optional.empty();
            }

            @Override
            public Optional<String> result(PkiId id) {
                return Optional.empty();
            }
        });

        bus.submit(opId, "ISSUE_CERT", owner, "endpoint-1", Instant.parse("2025-01-01T00:00:00Z"), Duration.ofHours(1));

        AsyncStatus ok = new AsyncStatus(AsyncState.SUCCEEDED, Instant.parse("2025-01-01T00:00:10Z"), Optional.of("OK"),
                java.util.Map.of("note", "done"));

        bus.update(opId, ok, Optional.of("RESULT-ABC"));

        Optional<String> consumed = bus.consumeResult(opId);
        System.out.println("...consumed=" + (consumed.isPresent() ? consumed.get() : "<empty>"));
        assertTrue(consumed.isPresent());
        assertEquals("RESULT-ABC", consumed.get());

        assertTrue(bus.snapshot(opId).isEmpty());
        assertTrue(bus.status(opId).isEmpty());

        System.out.println("...ok");
    }

    @Test
    public void replay_restoresSnapshotAndStatus() {
        System.out.println("replay_restoresSnapshotAndStatus");

        Path log = tempDir.resolve("async.log");
        System.out.println("...log=" + log.getFileName());

        AppendOnlyLineStore store1 = new AppendOnlyLineStore(log);

        DurableAsyncBus<PkiId, Principal, String, String> bus1 = new DurableAsyncBus<PkiId, Principal, String, String>(
                PkiCodecs.PKI_ID, PkiCodecs.PRINCIPAL, PkiCodecs.STRING, ResultCodec.none(), store1);

        PkiId opId = new PkiId("op-2");
        Principal owner = new Principal("SERVICE", "issuer");
        bus1.submit(opId, "CRL", owner, "endpoint-1", Instant.parse("2025-01-01T00:00:00Z"), Duration.ofHours(2));

        AsyncStatus running = new AsyncStatus(AsyncState.RUNNING, Instant.parse("2025-01-01T00:00:05Z"),
                Optional.of("RUNNING"), java.util.Map.of());
        bus1.update(opId, running, Optional.empty());

        AppendOnlyLineStore store2 = new AppendOnlyLineStore(log);

        DurableAsyncBus<PkiId, Principal, String, String> bus2 = new DurableAsyncBus<PkiId, Principal, String, String>(
                PkiCodecs.PKI_ID, PkiCodecs.PRINCIPAL, PkiCodecs.STRING, ResultCodec.none(), store2);

        Optional<AsyncOperationSnapshot<PkiId, Principal, String>> snap = bus2.snapshot(opId);
        Optional<AsyncStatus> st = bus2.status(opId);

        System.out.println("...snapshotPresent=" + snap.isPresent());
        System.out.println("...statusPresent=" + st.isPresent());

        assertTrue(snap.isPresent());
        assertTrue(st.isPresent());
        assertEquals(AsyncState.RUNNING, st.get().state());
        assertEquals("CRL", snap.get().type());

        System.out.println("...ok");
    }
}
