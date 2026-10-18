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

import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.spi.audit.AuditSink;

/**
 * {@link AuditSink} that forwards audit events to a remote syslog server using
 * RFC 5424 framing.
 *
 * <h2>Format</h2>
 * <p>
 * Each record is emitted as a single RFC 5424 syslog message using facility
 * {@code LOG_SECURITY} (13) and severity {@code NOTICE} (5) for informational
 * audit events:
 * </p>
 * <pre>
 * &lt;109&gt;1 2026-09-30T12:34:56.789Z hostname zeroecho-pki - - - category=ISSUANCE action=ISSUE_END_ENTITY ...
 * </pre>
 *
 * <h2>Transport</h2>
 * <ul>
 * <li>UDP — one datagram per event; no connection state; messages exceeding
 *     1 KiB are silently truncated to avoid IP fragmentation.</li>
 * <li>TCP — octet-count framed (RFC 6587 §3.4.1); a single persistent
 *     connection is held open; the sink reconnects once on send failure.</li>
 * </ul>
 *
 * <h2>Thread safety</h2>
 * <p>
 * Thread-safe. UDP socket sends are atomic per datagram. TCP writes are
 * serialized by a frame lock. Closing concurrently aborts a blocked TCP write
 * and prevents reconnection.
 * </p>
 *
 * <h2>Security</h2>
 * <p>
 * {@link AuditEvent#details()} is intentionally omitted from the syslog
 * payload to reduce the risk of sensitive metadata exposure to syslog
 * collectors that may not apply the same access-control as the PKI store.
 * Only category, action, principal type/name, and purpose are transmitted.
 * </p>
 *
 * @since 1.0
 */
public final class SyslogAuditSink implements AuditSink {
    private static final String CLOSED_MESSAGE = "SyslogAuditSink is closed";

    /** RFC 5424: LOG_SECURITY facility (13) × 8 + NOTICE severity (5) = 109. */
    private static final int PRIORITY = 13 * 8 + 5;

    private static final DateTimeFormatter TS = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC);
    private static final Logger LOG = Logger.getLogger(SyslogAuditSink.class.getName());

    /** Syslog protocol selection. */
    public enum Protocol {
        /** Sends one datagram per record without delivery acknowledgement. */
        UDP,
        /** Sends octet-counted records over a TCP connection. */
        TCP
    }

    private final InetAddress address;
    private final int port;
    private final Protocol protocol;
    private final String appName;
    private final String hostname;

    // UDP path — socket is shared; DatagramSocket.send() is safe to call concurrently.
    private final DatagramSocket udpSocket;

    // Serialize frames, but allow close to detach and abort a blocked TCP write.
    private final ReentrantLock tcpLock = new ReentrantLock();
    private final AtomicReference<TcpConnection> tcpConnection = new AtomicReference<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);

    /**
     * Opens a syslog sink.
     *
     * @param address  resolved server address
     * @param port     server port (1–65535)
     * @param protocol transport protocol
     * @param appName  RFC 5424 APP-NAME field (printable US-ASCII, ≤ 48 chars)
     * @throws IOException if socket creation fails
     */
    public SyslogAuditSink(InetAddress address, int port, Protocol protocol, String appName) throws IOException {
        this.address = Objects.requireNonNull(address, "address");
        if (port < 1 || port > 65_535) { throw new IllegalArgumentException("Invalid syslog port: " + port); }
        this.port = port;
        this.protocol = Objects.requireNonNull(protocol, "protocol");
        this.appName = sanitizeHeader(Objects.requireNonNull(appName, "appName"), 48);
        this.hostname = sanitizeHeader(resolveHostname(), 255);

        if (protocol == Protocol.UDP) {
            udpSocket = new DatagramSocket();
        } else {
            udpSocket = null;
            reconnectTcp();
        }
        LOG.info(() -> "SyslogAuditSink opened: " + protocol + " " + address.getHostAddress() + ":" + port);
    }

    @Override
    public void record(AuditEvent event) {
        Objects.requireNonNull(event, "event");
        if (closed.get()) { throw new IllegalStateException(CLOSED_MESSAGE); }

        String msg = buildMessage(event);
        byte[] bytes = msg.getBytes(StandardCharsets.UTF_8);

        if (protocol == Protocol.UDP) {
            sendUdp(bytes);
        } else {
            sendTcp(bytes);
        }
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) { return; }
        if (udpSocket != null) { udpSocket.close(); }
        closeTcpQuietly();
    }

    private String buildMessage(AuditEvent event) {
        String timestamp = TS.format(event.time());
        StringBuilder sb = new StringBuilder(256);
        // RFC 5424 header: PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD
        sb.append('<').append(PRIORITY).append(">1 ")
          .append(timestamp).append(' ')
          .append(hostname).append(' ')
          .append(appName).append(" - - - category=") // PROCID, MSGID and STRUCTURED-DATA are nil
          .append(safe(event.category()))
          .append(" action=").append(safe(event.action()))
          .append(" principalType=").append(safe(event.principal().type()))
          .append(" principalName=").append(safe(event.principal().name()))
          .append(" purpose=").append(safe(event.purpose().value()));
        event.objectId().ifPresent(id -> sb.append(" objectId=").append(safe(id.toString())));
        return sb.toString();
    }

    private void sendUdp(byte[] bytes) {
        // Truncate to 1024 bytes to stay within a single IP datagram without fragmentation.
        int length = Math.min(bytes.length, 1024);
        try {
            udpSocket.send(new DatagramPacket(bytes, length, address, port));
        } catch (IOException e) {
            LOG.warning(() -> "SyslogAuditSink UDP send failed: " + e.getMessage());
        }
    }

    private void sendTcp(byte[] bytes) {
        tcpLock.lock();
        try {
            if (closed.get()) {
                throw new IllegalStateException(CLOSED_MESSAGE);
            }
            sendTcpLocked(bytes);
        } finally {
            tcpLock.unlock();
        }
    }

    private void sendTcpLocked(byte[] bytes) {
        String framed = bytes.length + " ";
        byte[] prefix = framed.getBytes(StandardCharsets.US_ASCII);
        try {
            writeTcp(prefix, bytes);
        } catch (IOException first) {
            if (closed.get()) {
                return;
            }
            // Single reconnect attempt.
            try {
                closeTcpQuietly();
                reconnectTcp();
                writeTcp(prefix, bytes);
            } catch (IOException second) {
                LOG.warning(() -> "SyslogAuditSink TCP send failed after reconnect: " + second.getMessage());
            }
        }
    }

    private void writeTcp(byte[] prefix, byte[] payload) throws IOException {
        TcpConnection connection = tcpConnection.get();
        if (connection == null) {
            throw new IOException(CLOSED_MESSAGE);
        }
        connection.output().write(prefix);
        connection.output().write(payload);
        connection.output().flush();
    }

    private void reconnectTcp() throws IOException {
        if (closed.get()) {
            throw new IOException(CLOSED_MESSAGE);
        }
        Socket socket = new Socket(address, port); // NOPMD CloseResource - Ownership is transferred to the enclosing lifecycle and its explicit close/stream completion; not a local resource.
        boolean published = false;
        try { // NOPMD UseTryWithResources - Socket ownership transfers to the atomic connection; unpublished sockets close in finally.
            socket.setKeepAlive(true);
            TcpConnection connection = new TcpConnection(socket, socket.getOutputStream());
            if (closed.get()) {
                throw new IOException(CLOSED_MESSAGE);
            }
            tcpConnection.set(connection);
            published = true;
            if (closed.get()) {
                closeTcpQuietly();
                throw new IOException(CLOSED_MESSAGE);
            }
        } finally {
            if (!published) {
                socket.close();
            }
        }
    }

    private void closeTcpQuietly() {
        TcpConnection connection = tcpConnection.getAndSet(null);
        if (connection != null) {
            try { connection.socket().close(); } catch (IOException ignored) { /* best effort */ }
        }
    }

    private record TcpConnection(Socket socket, OutputStream output) { }

    private static String resolveHostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (IOException e) {
            return "unknown";
        }
    }

    private static String sanitizeHeader(String value, int maxLen) {
        // RFC 5424: printable US-ASCII (0x21–0x7E), no spaces, max length.
        StringBuilder sb = new StringBuilder(Math.min(value.length(), maxLen));
        for (int i = 0; i < value.length() && sb.length() < maxLen; i++) {
            char c = value.charAt(i);
            if (c >= 0x21 && c <= 0x7E) { sb.append(c); }
        }
        return sb.isEmpty() ? "-" : sb.toString();
    }

    private static String safe(String value) {
        if (value == null) { return "-"; }
        return value.replace(' ', '_').replace('\n', '_').replace('\r', '_');
    }
}
