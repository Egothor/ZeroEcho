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
 * JFR event emitted when a CRL or OCSP status object is generated.
 *
 * <p>
 * Records the issuing authority, whether the object is a delta CRL, the
 * number of revoked entries included, and the outcome. Used to measure
 * revocation-publication latency and CRL size trends.
 * </p>
 *
 * @since 1.0
 */
@Name("zeroecho.pki.CrlGeneration")
@Label("CRL Generation")
@Category({"ZeroEcho PKI", "Revocation"})
@Description("A CRL or status object generation signing operation.")
@StackTrace(false)
public final class CrlGenerationEvent extends Event { // NOPMD DataClass - JFR event fields are its runtime schema.

    /** Identifier of the certificate authority issuing this CRL. */
    @Label("Authority ID")
    @Description("Identifier of the certificate authority issuing this CRL.")
    public String authorityId;

    /** Number of revoked certificate entries included in the status object. */
    @Label("Revoked Count")
    @Description("Number of revoked certificate entries included in the generated status object.")
    public int revokedCount;

    /** Whether this is a delta CRL rather than a full CRL. */
    @Label("Delta")
    @Description("True if this is a delta CRL; false if it is a full CRL.")
    public boolean delta;

    /** Whether the generation operation completed without failure. */
    @Label("Succeeded")
    @Description("True if the status object was generated and signed successfully.")
    public boolean succeeded;
    /** Creates an uncommitted event with default field values; populate fields before committing. */
    public CrlGenerationEvent() {
        super();
    }
}
