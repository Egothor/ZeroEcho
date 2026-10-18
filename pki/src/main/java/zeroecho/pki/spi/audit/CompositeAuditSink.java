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
package zeroecho.pki.spi.audit;

import java.util.List;
import java.util.Objects;

import zeroecho.pki.api.audit.AuditEvent;

/**
 * Fan-out {@link AuditSink} that delivers each event to an ordered list of
 * delegate sinks.
 *
 * <p>Each delegate receives every event independently. A failure thrown by one
 * delegate is caught, logged at {@code WARNING}, and does not prevent delivery
 * to subsequent delegates. This ensures that a broken or slow sink cannot
 * suppress audit delivery to other active sinks.
 *
 * <p>Typical use is to combine the built-in file sink with one or more
 * additional transport sinks (syslog, OpenTelemetry, in-process test listener)
 * without coupling the PKI core to any specific additional transport:
 *
 * <pre>{@code
 * AuditSink composite = new CompositeAuditSink(List.of(fileSink, syslogSink));
 * }</pre>
 *
 * <h2>Thread safety</h2>
 * <p>This class is thread-safe. The delegate list is immutable after
 * construction. Thread-safety of delivery to each delegate depends on the
 * delegate's own contract; all built-in {@code AuditSink} implementations are
 * thread-safe.
 *
 * <h2>Lifecycle</h2>
 * <p>{@link #close()} closes each delegate in the order they were supplied.
 * Failures during individual delegate close are caught and logged; close
 * continues to the remaining delegates.
 *
 * @since 1.0
 */
public final class CompositeAuditSink implements AuditSink {

    private static final System.Logger LOG = System.getLogger(CompositeAuditSink.class.getName());

    private final List<AuditSink> delegates;

    /**
     * Creates a composite sink that fans out to the given delegates in order.
     *
     * @param delegates non-null, non-empty list of delegate sinks; defensively
     *                  copied; no element may be {@code null}
     * @throws NullPointerException     if {@code delegates} is {@code null} or
     *                                  contains a {@code null} element
     * @throws IllegalArgumentException if {@code delegates} is empty
     */
    public CompositeAuditSink(List<AuditSink> delegates) {
        Objects.requireNonNull(delegates, "delegates");
        if (delegates.isEmpty()) {
            throw new IllegalArgumentException("delegates must not be empty");
        }
        List<AuditSink> copy = List.copyOf(delegates);
        for (AuditSink sink : copy) { // NOPMD CloseResource - Ownership is transferred to the enclosing lifecycle and its explicit close/stream completion; not a local resource.
            Objects.requireNonNull(sink, "delegate sink must not be null");
        }
        this.delegates = copy;
    }

    /**
     * Delivers the event to each delegate in order, continuing past any failure.
     *
     * <p>A delegate that throws is logged at {@code WARNING} and the next
     * delegate still receives the event. The caller never observes a delegate
     * exception — this method always returns normally.
     *
     * @param event the event to deliver; never {@code null}
     * @throws NullPointerException if {@code event} is {@code null}
     */
    @Override
    @SuppressWarnings("PMD.AvoidCatchingGenericException") // deliberate: isolate each delegate failure
    public void record(AuditEvent event) {
        Objects.requireNonNull(event, "event");
        for (AuditSink delegate : delegates) { // NOPMD CloseResource - Instance owns delegates until its lifecycle closes them.
            try {
                delegate.record(event);
            } catch (RuntimeException failure) {
                LOG.log(System.Logger.Level.WARNING,
                        "Audit sink delegate failed; event may not have been delivered to "
                                + delegate.getClass().getName(),
                        failure);
            }
        }
    }

    /**
     * Closes each delegate in order, continuing past any individual close failure.
     *
     * <p>All delegates are closed even if an earlier close throws. Close failures
     * are logged at {@code WARNING} and do not propagate.
     */
    @Override
     // deliberate: close all delegates regardless of failure
    public void close() {
        for (AuditSink delegate : delegates) { // NOPMD CloseResource - This loop closes instance-owned delegates.
            try {
                delegate.close();
            } catch (Exception failure) {
                LOG.log(System.Logger.Level.WARNING,
                        "Audit sink delegate close failed for " + delegate.getClass().getName(),
                        failure);
            }
        }
    }
}
