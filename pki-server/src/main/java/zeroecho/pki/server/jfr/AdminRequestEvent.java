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
 * JFR event emitted for every request handled by the administrative HTTPS handler.
 *
 * <p>
 * Captures the operation type, acting principal, HTTP status code, and whether
 * the request was authorized. The event duration spans the full handler
 * lifecycle from request receipt to response write — useful for measuring
 * end-to-end admin API latency per operation and principal.
 * </p>
 *
 * @since 1.0
 */
@Name("zeroecho.pki.AdminRequest")
@Label("Admin API Request")
@Category({"ZeroEcho PKI", "Admin API"})
@Description("A request handled by the ZeroEcho PKI administrative HTTPS endpoint.")
@StackTrace(false)
public final class AdminRequestEvent extends Event { // NOPMD DataClass - JFR event fields are its runtime schema.

    /**
     * Stable operation identifier resolved from the request path, e.g.
     * {@code credential.issue}; empty string for pre-routing failures.
     */
    @Label("Operation ID")
    @Description("Stable operation identifier resolved from the request path; empty for pre-routing failures.")
    public String operationId;

    /**
     * Server principal identifier of the authenticated end-client; empty string
     * when authentication failed or did not complete.
     */
    @Label("Principal ID")
    @Description("Server principal identifier of the authenticated end-client; empty when authentication failed.")
    public String principalId;

    /** HTTP status code of the response sent to the caller. */
    @Label("HTTP Status")
    @Description("HTTP status code of the response sent to the caller.")
    public int httpStatus;

    /** Whether the request was authorized and admitted for execution. */
    @Label("Authorized")
    @Description("True if the request passed authentication and authorization; false otherwise.")
    public boolean authorized;
    /** Creates an uncommitted event with default field values; populate fields before committing. */
    public AdminRequestEvent() {
        super();
    }
}
