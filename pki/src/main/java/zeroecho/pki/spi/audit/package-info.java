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
/**
 * Service Provider Interfaces (SPI) for PKI audit event persistence.
 *
 * <p>
 * This package defines the SPI contracts that allow the PKI subsystem to
 * delegate audit event persistence to pluggable, backend-specific
 * implementations discovered via {@link java.util.ServiceLoader}.
 * </p>
 *
 * <h2>Purpose and scope</h2>
 * <p>
 * Audit functionality in the PKI layer is intentionally decoupled from any
 * concrete storage mechanism. Implementations may persist audit events to
 * filesystems, databases, remote services, or in-memory buffers, depending on
 * deployment requirements.
 * </p>
 *
 * <p>
 * The SPI is split into two roles:
 * </p>
 * <ul>
 * <li>{@link zeroecho.pki.spi.audit.AuditSink} – a runtime component that
 * receives {@link zeroecho.pki.api.audit.AuditEvent audit events} and persists
 * them.</li>
 * <li>{@link zeroecho.pki.spi.audit.AuditSinkProvider} – a
 * {@link java.util.ServiceLoader}-discoverable factory responsible for creating
 * and configuring {@code AuditSink} instances.</li>
 * </ul>
 *
 * <h2>Instantiation model</h2>
 * <p>
 * {@link java.util.ServiceLoader} is used only to discover
 * {@code AuditSinkProvider} implementations. Direct discovery of
 * {@code AuditSink} instances is intentionally avoided because most audit
 * backends require configuration parameters (such as paths, connection strings,
 * credentials, or limits).
 * </p>
 *
 * <p>
 * Providers must expose a public no-argument constructor and create
 * {@code AuditSink} instances exclusively through the
 * {@link zeroecho.pki.spi.audit.AuditSinkProvider#allocate allocate} method,
 * using a {@link zeroecho.pki.spi.ProviderConfig} supplied by the bootstrap or
 * runtime environment.
 * </p>
 *
 * <h2>Security and compliance requirements</h2>
 * <p>
 * Implementations of this SPI are security-critical. The following rules are
 * mandatory:
 * </p>
 * <ul>
 * <li>Audit sinks must never persist secrets, private keys, shared secrets,
 * passwords, tokens, or other sensitive cryptographic material.</li>
 * <li>Providers and sinks must apply appropriate redaction and minimization
 * policies to all persisted data.</li>
 * <li>Configuration values supplied via {@code ProviderConfig} must never be
 * written to logs or audit outputs, as they may contain sensitive information.
 * </li>
 * </ul>
 *
 * <h2>Thread-safety and lifecycle</h2>
 * <p>
 * Unless explicitly documented otherwise by a concrete implementation,
 * {@code AuditSink} instances are expected to be thread-safe and usable by
 * multiple concurrent PKI operations.
 * </p>
 *
 * <p>
 * Lifecycle management (creation, activation, shutdown) is controlled by the
 * PKI bootstrap and runtime layers; this SPI does not define explicit close or
 * shutdown semantics unless required by a specific implementation.
 * </p>
 *
 * <h2>Intended usage</h2>
 * <p>
 * This package is intended for infrastructure-level integration and must not be
 * used directly by application code. Consumers should interact with audit
 * functionality exclusively through the public PKI API.
 * </p>
 */
package zeroecho.pki.spi.audit;
