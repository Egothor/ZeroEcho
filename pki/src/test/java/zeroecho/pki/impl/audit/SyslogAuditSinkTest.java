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
package zeroecho.pki.impl.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Constructor;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.spi.ProviderConfig;

public final class SyslogAuditSinkTest {

    @Test
    @Timeout(10)
    void closeAbortsInFlightTcpRecordWithoutReconnect() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        CountDownLatch writing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch closing = new CountDownLatch(1);
        CountDownLatch closed = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        try (ServerSocket server = new ServerSocket(0, 1, loopback);
                SyslogAuditSink sink = new SyslogAuditSink(loopback, server.getLocalPort(),
                        SyslogAuditSink.Protocol.TCP, "lifecycle-test");
                Socket accepted = server.accept()) {
            Field connectionField = SyslogAuditSink.class.getDeclaredField("tcpConnection");
            connectionField.setAccessible(true);
            @SuppressWarnings("unchecked")
            AtomicReference<Object> connection = (AtomicReference<Object>) connectionField.get(sink);
            Object original = connection.get();
            Field socketField = original.getClass().getDeclaredField("socket");
            socketField.setAccessible(true);
            Constructor<?> constructor = original.getClass().getDeclaredConstructor(Socket.class, OutputStream.class);
            constructor.setAccessible(true);
            connection.set(constructor.newInstance(socketField.get(original), new OutputStream() {
                @Override
                public void write(int ignored) throws IOException {
                    writing.countDown();
                    try {
                        if (!release.await(5, TimeUnit.SECONDS)) throw new IOException("Fixture timeout");
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        throw new IOException(interrupted);
                    }
                    throw new IOException("Simulated aborted write");
                }
            }));
            Thread sender = Thread.ofPlatform().start(() -> {
                try { sink.record(testEvent()); } catch (Throwable error) { failure.set(error); }
            });
            Thread closer = null;
            try {
                assertTrue(writing.await(5, TimeUnit.SECONDS));
                closer = Thread.ofPlatform().start(() -> {
                    closing.countDown();
                    try { sink.close(); } catch (Throwable error) { failure.set(error); }
                    finally { closed.countDown(); }
                });
                assertTrue(closing.await(5, TimeUnit.SECONDS));
                assertTrue(closed.await(5, TimeUnit.SECONDS), "close must abort a blocked write");
                assertTrue(((Socket) socketField.get(original)).isClosed());
            } finally {
                release.countDown();
                sender.join(5000);
                if (closer != null) closer.join(5000);
            }
            assertFalse(sender.isAlive());
            assertEquals(null, failure.get());
            server.setSoTimeout(100);
            assertThrows(SocketTimeoutException.class, server::accept, "closed sink must not reconnect");
            assertThrows(IllegalStateException.class, () -> sink.record(testEvent()));
        }
    }

    private static AuditEvent testEvent() {
        return new AuditEvent(Instant.parse("2026-01-01T12:00:00Z"), "ISSUANCE", "ISSUE_END_ENTITY",
                new Principal("ADMIN", "alice"), new Purpose("credential.issue"),
                Optional.empty(), Optional.empty(), Map.of("serial", "should-not-appear-in-syslog"));
    }

    // ── UDP send ──────────────────────────────────────────────────────────────

    @Test
    @Timeout(5)
    void udpSend_receivedDatagram_containsRfc5424Fields() throws Exception {
        System.out.println("udpSend_receivedDatagram_containsRfc5424Fields");

        try (DatagramSocket server = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            server.setSoTimeout(3000);
            int port = server.getLocalPort();

            try (SyslogAuditSink sink = new SyslogAuditSink(
                    InetAddress.getLoopbackAddress(), port, SyslogAuditSink.Protocol.UDP, "ze-test")) {
                sink.record(testEvent());
            }

            byte[] buf = new byte[2048];
            DatagramPacket pkt = new DatagramPacket(buf, buf.length);
            server.receive(pkt);
            String msg = new String(buf, 0, pkt.getLength(), StandardCharsets.UTF_8);

            System.out.println("  received: " + msg);

            assertTrue(msg.startsWith("<109>1 "), "must start with RFC 5424 priority+version");
            assertTrue(msg.contains("ze-test"), "app-name must appear");
            assertTrue(msg.contains("category=ISSUANCE"), "category field");
            assertTrue(msg.contains("action=ISSUE_END_ENTITY"), "action field");
            assertTrue(msg.contains("principalName=alice"), "principal name field");
            assertFalse(msg.contains("should-not-appear-in-syslog"), "details must be omitted");
        }

        System.out.println("  ok");
    }

    @Test
    @Timeout(5)
    void udpSend_concurrentRecords_allReceived() throws Exception {
        System.out.println("udpSend_concurrentRecords_allReceived");

        int count = 8;
        CountDownLatch latch = new CountDownLatch(count);

        try (DatagramSocket server = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            server.setSoTimeout(2000);
            int port = server.getLocalPort();

            Thread receiver = Thread.ofVirtual().start(() -> {
                byte[] buf = new byte[2048];
                for (int i = 0; i < count; i++) {
                    try {
                        DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                        server.receive(pkt);
                        latch.countDown();
                    } catch (IOException e) {
                        break;
                    }
                }
            });

            try (SyslogAuditSink sink = new SyslogAuditSink(
                    InetAddress.getLoopbackAddress(), port, SyslogAuditSink.Protocol.UDP, "ze-test")) {
                Thread[] senders = new Thread[count];
                for (int i = 0; i < count; i++) {
                    senders[i] = Thread.ofVirtual().start(() -> sink.record(testEvent()));
                }
                for (Thread t : senders) t.join(2000);
            }

            assertTrue(latch.await(3, TimeUnit.SECONDS), "all " + count + " datagrams must be received");
            receiver.join(500);
        }

        System.out.println("  ok");
    }

    // ── Provider config ───────────────────────────────────────────────────────

    @Test
    void provider_id_isSyslog() {
        assertEquals("syslog", new SyslogAuditSinkProvider().id());
    }

    @Test
    void provider_missingHost_throwsIllegalArgument() {
        SyslogAuditSinkProvider provider = new SyslogAuditSinkProvider();
        ProviderConfig config = new ProviderConfig("syslog", Map.of());
        assertThrows(IllegalArgumentException.class, () -> provider.validateConfig(config));
    }

    @Test
    void provider_invalidPort_throwsIllegalArgument() {
        SyslogAuditSinkProvider provider = new SyslogAuditSinkProvider();
        ProviderConfig config = new ProviderConfig("syslog", Map.of("host", "127.0.0.1", "port", "99999"));
        assertThrows(IllegalArgumentException.class, () -> provider.validateConfig(config));
    }

    @Test
    void provider_invalidProtocol_throwsIllegalArgument() {
        SyslogAuditSinkProvider provider = new SyslogAuditSinkProvider();
        ProviderConfig config = new ProviderConfig("syslog", Map.of("host", "127.0.0.1", "protocol", "ftp"));
        assertThrows(IllegalArgumentException.class, () -> provider.validateConfig(config));
    }

    @Test
    @Timeout(5)
    void provider_allocate_createsUdpSink() throws Exception {
        System.out.println("provider_allocate_createsUdpSink");

        try (DatagramSocket server = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            server.setSoTimeout(2000);
            int port = server.getLocalPort();

            SyslogAuditSinkProvider provider = new SyslogAuditSinkProvider();
            ProviderConfig config = new ProviderConfig("syslog",
                    Map.of("host", "127.0.0.1", "port", Integer.toString(port)));

            try (SyslogAuditSink sink = (SyslogAuditSink) provider.allocate(config)) {
                sink.record(testEvent());
            }

            byte[] buf = new byte[2048];
            DatagramPacket pkt = new DatagramPacket(buf, buf.length);
            server.receive(pkt);
            String msg = new String(buf, 0, pkt.getLength(), StandardCharsets.UTF_8);
            assertTrue(msg.startsWith("<109>1 "));
        }

        System.out.println("  ok");
    }

    // ── Close guard ───────────────────────────────────────────────────────────

    @Test
    @Timeout(5)
    void record_afterClose_throwsIllegalState() throws Exception {
        System.out.println("record_afterClose_throwsIllegalState");

        try (DatagramSocket server = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            int port = server.getLocalPort();
            SyslogAuditSink sink = new SyslogAuditSink(
                    InetAddress.getLoopbackAddress(), port, SyslogAuditSink.Protocol.UDP, "ze-test");
            sink.close();
            assertThrows(IllegalStateException.class, () -> sink.record(testEvent()));
        }

        System.out.println("  ok");
    }
}
