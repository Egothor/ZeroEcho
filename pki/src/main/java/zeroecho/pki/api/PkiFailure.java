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
package zeroecho.pki.api;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

/**
 * Immutable, non-sensitive description of a PKI failure.
 *
 * <p>
 * This value is safe to carry across an internal trust boundary because it
 * contains only a stable classification and a validated machine-readable code.
 * It deliberately contains no diagnostic message, cause, payload, or arbitrary
 * data. Protocol adapters should map the classification and code explicitly and
 * must not infer behavior by parsing exception text.
 * </p>
 *
 * <p>
 * Construction, access, equality, and hashing require constant time and
 * auxiliary memory because both components are members of closed enums.
 * </p>
 *
 * @param classification protocol-independent failure classification
 * @param code stable machine-readable code whose declared classification must
 *             equal {@code classification}
 */
public record PkiFailure(PkiFailureClassification classification, PkiFailureCode code) implements Serializable {

    @Serial
    private static final long serialVersionUID = -4042740539326155478L;

    /**
     * Creates a validated failure description.
     *
     * @throws NullPointerException if {@code classification} or {@code code} is {@code null}
     * @throws IllegalArgumentException if the code is not assigned to
     *         {@code classification}
     */
    public PkiFailure {
        Objects.requireNonNull(classification, "classification");
        Objects.requireNonNull(code, "code");
        if (code.classification() != classification) {
            throw new IllegalArgumentException("code classification does not match classification");
        }
    }
}
