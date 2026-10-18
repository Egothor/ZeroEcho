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
package zeroecho.pki.server.jfr;

import jdk.jfr.Category;
import jdk.jfr.Description;
import jdk.jfr.Event;
import jdk.jfr.Label;
import jdk.jfr.Name;
import jdk.jfr.StackTrace;

/**
 * JFR event emitted when an audit record is written to the durable audit sink.
 *
 * <p>
 * Measures the latency of the audit write path, distinguishes the audit
 * category, and records whether the write included an fsync. Useful for
 * identifying audit-path bottlenecks under load.
 * </p>
 *
 * @since 1.0
 */
@Name("zeroecho.pki.AuditWrite")
@Label("Audit Write")
@Category({"ZeroEcho PKI", "Audit"})
@Description("An audit record written to the durable server-control audit sink.")
@StackTrace(false)
public final class AuditWriteEvent extends Event {

    /** Audit category of the record, e.g. {@code SERVER_SECURITY}. */
    @Label("Category")
    @Description("Audit category of the written record, e.g. SERVER_SECURITY.")
    public String category;

    /** Number of records written in this batch (always 1 for the server-control sink). */
    @Label("Record Count")
    @Description("Number of audit records written in this write operation.")
    public int recordCount;

    /**
     * Whether the write included an explicit filesystem sync; {@code false} for
     * best-effort writes.
     */
    @Label("Fsync")
    @Description("True if the write included an explicit filesystem sync; false for best-effort writes.")
    public boolean fsync;
    /** Creates an uncommitted event with default field values; populate fields before committing. */
    public AuditWriteEvent() {
        super();
    }
}
