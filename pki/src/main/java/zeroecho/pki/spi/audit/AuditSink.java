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

import zeroecho.pki.api.audit.AuditEvent;

/**
 * SPI for persisting audit events.
 *
 * <p>Implementations must apply appropriate redaction policies and must never
 * write secrets.
 *
 * <h2>Thread safety</h2>
 * <p>Implementations must be thread-safe; the PKI server calls
 * {@link #record(AuditEvent)} from multiple threads concurrently.
 *
 * @since 1.0
 */
@FunctionalInterface
public interface AuditSink extends AutoCloseable {

    /**
     * Persists an audit event.
     *
     * @param event audit event
     * @throws IllegalArgumentException if {@code event} is null
     * @throws RuntimeException         if persistence fails
     */
    void record(AuditEvent event);

    /**
     * Releases lifecycle-owned sink resources.
     *
     * <p>The default implementation owns no closeable resource. Stateful
     * providers may override this method; repeated close calls should be
     * harmless.</p>
     */
    @Override
    default void close() {
        // Most current sinks open resources only for the duration of record(...).
    }
}
