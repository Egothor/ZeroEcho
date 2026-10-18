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
package zeroecho.pki.application;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Exact public audience of credential-confirmation proof transcripts.
 *
 * <p>The value is a lowercase ASCII RFC 4122 version-4 UUID URN and is compared
 * byte-for-byte without normalization. It is a public deployment or cluster
 * identifier, not a secret, credential, authorization grant, or request-derived
 * value. Operators must provision the same audience mapping into participating
 * clients and keep audience values unique across independently administered
 * deployments that may accept the same proof protocol.</p>
 *
 * @param value exact {@code urn:uuid:xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx}
 */
public record CredentialConfirmationProofAudience(String value) {
    private static final Pattern UUID_V4_URN = Pattern.compile(
            "urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}");

    /**
     * Validates the exact canonical audience without normalization.
     *
     * @throws NullPointerException if {@code value} is {@code null}
     * @throws IllegalArgumentException if the value is not a canonical lowercase UUID-v4 URN
     */
    public CredentialConfirmationProofAudience {
        Objects.requireNonNull(value, "value");
        if (!UUID_V4_URN.matcher(value).matches()) {
            throw new IllegalArgumentException(
                    "Credential confirmation proof audience is not a canonical UUID v4 URN");
        }
    }

    /** Returns the exact public audience value. */
    @Override
    public String toString() {
        return value;
    }
}
