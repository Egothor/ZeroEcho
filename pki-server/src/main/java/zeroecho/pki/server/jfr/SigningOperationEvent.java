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
 * JFR event emitted for every signing operation submitted to the gateway.
 *
 * <p>
 * Captures the operation type, target authority, and outcome so that JFR
 * recordings can be used to measure signing throughput and latency per
 * authority and operation type.
 * </p>
 *
 * @since 1.0
 */
@Name("zeroecho.pki.SigningOperation")
@Label("Signing Operation")
@Category({"ZeroEcho PKI", "Signing"})
@Description("A PKI signing operation submitted through the server gateway.")
@StackTrace(false)
public final class SigningOperationEvent extends Event { // NOPMD DataClass - JFR event fields are its runtime schema.

    /** Stable operation identifier, e.g. {@code credential.issue}. */
    @Label("Operation ID")
    @Description("Stable operation identifier, e.g. credential.issue or ca.create.")
    public String operationId;

    /** Identifier of the certificate authority targeted by this operation. */
    @Label("Authority ID")
    @Description("Identifier of the certificate authority targeted by this operation; empty when not applicable.")
    public String authorityId;

    /** Whether the operation completed without a server-side failure. */
    @Label("Succeeded")
    @Description("True if the operation was accepted or completed; false if the server returned a failure outcome.")
    public boolean succeeded;

    /**
     * Short failure reason code when the operation did not succeed; {@code null}
     * when {@link #succeeded} is {@code true}.
     */
    @Label("Failure Reason")
    @Description("Short failure-reason code from the outcome; null when the operation succeeded.")
    public String failureReason;
    /** Creates an uncommitted event with default field values; populate fields before committing. */
    public SigningOperationEvent() {
        super();
    }
}
