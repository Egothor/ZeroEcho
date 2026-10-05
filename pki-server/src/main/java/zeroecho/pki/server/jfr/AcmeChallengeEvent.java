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
package zeroecho.pki.server.jfr;

import jdk.jfr.Category;
import jdk.jfr.Description;
import jdk.jfr.Event;
import jdk.jfr.Label;
import jdk.jfr.Name;
import jdk.jfr.StackTrace;

/**
 * JFR event emitted when an ACME challenge validation attempt completes.
 *
 * <p>
 * Covers both {@code HTTP-01} and {@code DNS-01} challenge types. The event
 * duration spans the full network probe — useful for identifying slow DNS
 * resolvers or unresponsive HTTP servers.
 * </p>
 *
 * @since 1.0
 */
@Name("zeroecho.pki.AcmeChallenge")
@Label("ACME Challenge Validation")
@Category({"ZeroEcho PKI", "ACME"})
@Description("An ACME challenge validation probe issued by the server.")
@StackTrace(false)
public final class AcmeChallengeEvent extends Event { // NOPMD DataClass - JFR event fields are its runtime schema.

    /** Challenge type: {@code HTTP_01} or {@code DNS_01}. */
    @Label("Challenge Type")
    @Description("ACME challenge type: HTTP_01 or DNS_01.")
    public String challengeType;

    /** DNS name or IP address identifier being validated. */
    @Label("Identifier")
    @Description("The DNS name or IP address identifier being validated.")
    public String identifier;

    /** Whether the challenge validation succeeded. */
    @Label("Succeeded")
    @Description("True if the challenge token was found and matched; false if validation failed.")
    public boolean succeeded;

    /**
     * Short reason code when the challenge failed; {@code null} when
     * {@link #succeeded} is {@code true}.
     */
    @Label("Failure Reason")
    @Description("Short failure-reason code from the provider result; null when the challenge succeeded.")
    public String failureReason;
    /** Creates an uncommitted event with default field values; populate fields before committing. */
    public AcmeChallengeEvent() {
        super();
    }
}
