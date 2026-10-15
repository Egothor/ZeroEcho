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
package zeroecho.pki.server.enrollment;

import zeroecho.pki.server.cmp.CmpEndpoint;
import zeroecho.pki.server.est.EstEndpoint;
import zeroecho.pki.server.scep.ScepEndpoint;

/**
 * Closed immutable protocol binding with an explicit enrollment policy.
 * Certificate profiles define issued certificate content; enrollment profiles
 * govern admission and approval. Both identities are mandatory.
 */
public sealed interface EnrollmentEndpoint permits EstEndpoint, ScepEndpoint, CmpEndpoint {
    /**
     * Returns the protocol-local path identity.
     * @return canonical protocol-local URL label
     */
    String label();
    /**
     * Returns the issuing authority binding.
     * @return issuing authority identity
     */
    String authorityId();
    /**
     * Returns the certificate-content policy binding.
     * @return certificate profile identity
     */
    String profileId();
    /**
     * Returns the admission-policy binding.
     * @return mandatory enrollment profile identity
     */
    String enrollmentProfileId();

    /**
     * Validates an enrollment-profile reference without resolving its current policy.
     * @param id canonical, non-null identity
     * @throws IllegalArgumentException if the identity is absent or malformed
     */
    static void requireProfileId(String id) {
        if (id == null || !id.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}")) {
            throw new IllegalArgumentException("Enrollment profile reference is not canonical");
        }
    }
}
