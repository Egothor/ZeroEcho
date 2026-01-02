/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.util;

import java.util.Objects;
import java.util.UUID;

import zeroecho.pki.api.PkiId;

/**
 * Utility methods for generating and validating {@link PkiId} values.
 *
 * <p>
 * The PKI subsystem uses {@link PkiId} as a stable identifier for domain
 * records and long-running operations. This helper centralizes ID generation to
 * avoid ad-hoc implementations scattered across providers and orchestration
 * code.
 * </p>
 *
 * <h2>Security</h2>
 * <p>
 * Generated identifiers must not embed secrets. The default generator uses a
 * random UUID which is suitable for correlation and storage keys but does not
 * reveal secret material.
 * </p>
 */
public final class PkiIds {

    private PkiIds() {
        throw new AssertionError("No instances.");
    }

    /**
     * Generates a new random PKI identifier.
     *
     * <p>
     * The returned identifier is based on {@link UUID#randomUUID()}.
     * </p>
     *
     * @return new identifier (never {@code null})
     */
    public static PkiId newRandomId() {
        return new PkiId(UUID.randomUUID().toString());
    }

    /**
     * Validates that the provided identifier is non-null.
     *
     * @param id identifier to validate
     * @return the same identifier for fluent usage
     * @throws IllegalArgumentException if {@code id} is {@code null}
     */
    public static PkiId require(PkiId id) {
        return Objects.requireNonNull(id, "id");
    }
}
