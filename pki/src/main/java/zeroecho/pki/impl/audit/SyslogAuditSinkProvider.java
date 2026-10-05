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
package zeroecho.pki.impl.audit;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Objects;
import java.util.Set;

import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.audit.AuditSinkProvider;

/**
 * {@link AuditSinkProvider} that creates a {@link SyslogAuditSink}.
 *
 * <h2>Configuration keys</h2>
 * <table border="1">
 * <caption>Syslog audit sink configuration</caption>
 * <tr><th>Key</th><th>Required</th><th>Default</th><th>Description</th></tr>
 * <tr><td>{@code host}</td><td>yes</td><td>—</td>
 *     <td>Syslog server hostname or IP address.</td></tr>
 * <tr><td>{@code port}</td><td>no</td><td>{@code 514}</td>
 *     <td>Syslog server UDP/TCP port.</td></tr>
 * <tr><td>{@code protocol}</td><td>no</td><td>{@code udp}</td>
 *     <td>Transport protocol: {@code udp} or {@code tcp}.</td></tr>
 * <tr><td>{@code app-name}</td><td>no</td><td>{@code zeroecho-pki}</td>
 *     <td>RFC 5424 APP-NAME field (printable US-ASCII, ≤ 48 chars).</td></tr>
 * </table>
 *
 * @since 1.0
 */
public final class SyslogAuditSinkProvider implements AuditSinkProvider {

    private static final Set<String> KEYS = Set.of("host", "port", "protocol", "app-name");

    /** Creates a syslog audit-sink provider descriptor. */
    public SyslogAuditSinkProvider() {
        // Stateless provider descriptor.
    }

    @Override
    public String id() {
        return "syslog";
    }

    @Override
    public Set<String> supportedKeys() {
        return KEYS;
    }

    @Override
    public void validateConfig(ProviderConfig config) {
        AuditSinkProvider.super.validateConfig(config);
        config.require("host");
        String port = config.properties().get("port");
        if (port != null) {
            try {
                int p = Integer.parseInt(port);
                if (p < 1 || p > 65_535) { throw new IllegalArgumentException("Invalid port: " + port); }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("port must be an integer: " + port, e);
            }
        }
        String protocol = config.properties().get("protocol");
        if (protocol != null && !"udp".equalsIgnoreCase(protocol) && !"tcp".equalsIgnoreCase(protocol)) {
            throw new IllegalArgumentException("protocol must be 'udp' or 'tcp', got: " + protocol);
        }
    }

    @Override
    public AuditSink allocate(ProviderConfig config) {
        Objects.requireNonNull(config, "config");
        validateConfig(config);

        String host = config.require("host");
        int port = Integer.parseInt(config.properties().getOrDefault("port", "514"));
        String protocolStr = config.properties().getOrDefault("protocol", "udp");
        SyslogAuditSink.Protocol protocol = "tcp".equalsIgnoreCase(protocolStr)
                ? SyslogAuditSink.Protocol.TCP : SyslogAuditSink.Protocol.UDP;
        String appName = config.properties().getOrDefault("app-name", "zeroecho-pki");

        try {
            InetAddress address = InetAddress.getByName(host);
            return new SyslogAuditSink(address, port, protocol, appName);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to open syslog sink to " + host + ":" + port, e);
        }
    }
}
