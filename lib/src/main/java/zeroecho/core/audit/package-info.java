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
/**
 * Auditing utilities for cryptographic contexts, including event contracts and
 * a JUL-backed listener.
 *
 * <p>
 * This package provides a lightweight dynamic-proxy wrapper that observes
 * selected operations of crypto contexts and emits structured audit events
 * without changing behavior. It also defines the listener API and a
 * production-ready {@link java.util.logging java.util.logging}-based
 * implementation.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Wrap existing contexts and transparently intercept lifecycle, progress,
 * verification, and failure signals while preserving functional results and
 * exceptions.</li>
 * <li>Offer a stable, structured callback surface suitable for logs, metrics,
 * and policy hooks.</li>
 * <li>Summarize non-secret specification attributes for diagnostics (mode, tag
 * length, IV length, and similar).</li>
 * </ul>
 *
 * <h2>Key elements</h2>
 * <ul>
 * <li>{@link AuditedContexts} - creates a dynamic proxy around a context and
 * emits creation metadata, streaming progress, verification outcomes,
 * KEM/Agreement signals, closure totals, and failure notifications. The wrapper
 * delegates all calls to the target and does not alter return values or
 * exceptions.</li>
 * <li>{@link AuditListener} - event sink interface; default methods are no-ops
 * so implementors override only what they need. Callbacks cover creation,
 * progress, headers, random material, KDF usage, verify results, failures, and
 * closure.</li>
 * <li>{@link JulAuditListenerStd} - concrete listener that emits parameterized
 * {@code java.util.logging} records in a stable {@code key=value} format; a
 * fluent builder configures logger, levels, and stack-trace inclusion.</li>
 * <li>{@link SpecIntrospector} - internal helper that summarizes non-secret
 * {@code ContextSpec} attributes for diagnostics.</li>
 * </ul>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // Configure a JUL-backed listener.
 * AuditListener audit = JulAuditListenerStd.builder()
 *     .progressLevel(java.util.logging.Level.FINE)
 *     .includeStackTraces(false)
 *     .build();
 *
 * // Create a context and wrap it for auditing.
 * zeroecho.core.context.CryptoContext raw = ...; // created by an algorithm descriptor
 * zeroecho.core.KeyUsage role = zeroecho.core.KeyUsage.ENCRYPT;
 * zeroecho.core.context.CryptoContext ctx = AuditedContexts.wrap(raw, audit, role);
 *
 * // Use as usual; the proxy emits structured events.
 * try (java.io.InputStream in =
 *         ((zeroecho.core.context.EncryptionContext) ctx).attach(upstream)) {
 *     in.transferTo(out);
 * }
 * }</pre>
 *
 * <h2>Privacy and safety</h2>
 * <ul>
 * <li>No secret material is logged; keys are summarized by short,
 * non-reversible fingerprints.</li>
 * <li>Counting uses passthrough streams; the wrapper introduces no buffering
 * beyond normal streaming.</li>
 * <li>Thread-safety follows the wrapped context; no additional synchronization
 * is added.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.audit;
