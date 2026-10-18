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
package zeroecho.pki.impl.async;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;

/**
 * PKI-specific async bus type aliases.
 *
 * <p>
 * This class exists solely to centralize the chosen type parameters used to
 * instantiate the generic async bus core.
 * </p>
 */
public final class PkiAsyncTypes {

    private PkiAsyncTypes() {
        throw new AssertionError("No instances.");
    }

    /**
     * Operation identifier type for PKI asynchronous operations.
     */
    public static final class OpId { // NOPMD
        private OpId() {
        }
    }

    /**
     * Owner type for PKI asynchronous operations.
     */
    public static final class Owner {
        private Owner() {
        }
    }

    /**
     * Endpoint identifier type for PKI asynchronous operations.
     */
    public static final class EndpointId {
        private EndpointId() {
        }
    }

    /**
     * Result type for PKI asynchronous operations.
     *
     * <p>
     * The default bus does not persist results by default. Higher layers should
     * store results (e.g., issued certificates) in PKI storage and use the bus only
     * for status + references.
     * </p>
     */
    public static final class Result {
        private Result() {
        }
    }

    /**
     * Returns the operation id type.
     *
     * @return class token
     */
    public static Class<PkiId> opIdType() {
        return PkiId.class;
    }

    /**
     * Returns the owner type.
     *
     * @return class token
     */
    public static Class<Principal> ownerType() {
        return Principal.class;
    }
}
