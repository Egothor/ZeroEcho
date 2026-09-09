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
package zeroecho.pki.api.confirmation;

/** Closed credential-disclosure policies with stable persistence-independent codes. */
public enum ConfirmationDisclosurePolicy {
    /** Anonymous retrieval and public indexing may be permitted. */
    PUBLIC(1),
    /** Anonymous retrieval requires a separate capability and is not indexed. */
    PUBLIC_UNLISTED(2),
    /** Retrieval requires an authenticated principal in the configured scope. */
    AUTHENTICATED(3),
    /** Retrieval is limited to an owner or specifically authorized administrator. */
    OWNER_ONLY(4),
    /** Retrieval requires an explicit principal or role grant. */
    RESTRICTED(5),
    /** The credential is not exposed through a publication surface. */
    NOT_PUBLISHED(6);

    private final int code;

    ConfirmationDisclosurePolicy(int code) {
        this.code = code;
    }

    /**
     * Returns the stable canonical code.
     *
     * @return integer code in the range 1 through 6
     */
    public int code() {
        return code;
    }

    /**
     * Resolves a stable canonical code.
     *
     * @param code integer code to resolve
     * @return matching closed policy
     * @throws IllegalArgumentException if the code is unknown
     */
    public static ConfirmationDisclosurePolicy fromCode(int code) {
        for (ConfirmationDisclosurePolicy candidate : values()) {
            if (candidate.code == code) {
                return candidate;
            }
        }
        throw new IllegalArgumentException("Unknown confirmation disclosure-policy code");
    }
}
