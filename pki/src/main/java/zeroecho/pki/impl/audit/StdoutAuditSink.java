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

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import java.util.logging.Logger;

import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.spi.audit.AuditSink;

/**
 * Reference {@link AuditSink} provider writing a deterministic summary line to
 * standard output.
 *
 * <h2>Security properties</h2>
 * <ul>
 * <li>Does not print {@link AuditEvent#details()} to reduce the risk of secret
 * disclosure.</li>
 * <li>Only prints high-level metadata (time, category, action, principal,
 * purpose).</li>
 * </ul>
 *
 * <h2>Determinism</h2>
 * <p>
 * Timestamp is rendered in ISO-8601 UTC, and the output line layout is stable.
 * </p>
 *
 * <p>
 * This sink is suitable for development and demonstrations. It is not intended
 * as a production persistence backend.
 * </p>
 */
public final class StdoutAuditSink implements AuditSink {

    private static final DateTimeFormatter TS = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC);
    private static final Logger LOG = Logger.getLogger(StdoutAuditSink.class.getName());

    /**
     * Public no-arg constructor required for {@link java.util.ServiceLoader}.
     */
    public StdoutAuditSink() {
        LOG.info("initialized");
    }

    @Override
    public void record(AuditEvent event) {
        Objects.requireNonNull(event, "event");

        String line = TS.format(event.time()) + " category=" + safe(event.category()) + " action="
                + safe(event.action()) + " principalType=" + safe(event.principal().type()) + " principalName="
                + safe(event.principal().name()) + " purpose=" + safe(event.purpose().value());

        System.out.println(line);
    }

    private static String safe(String s) {
        if (s == null) {
            return "";
        }
        return s.replace('\n', ' ').replace('\r', ' ');
    }
}
