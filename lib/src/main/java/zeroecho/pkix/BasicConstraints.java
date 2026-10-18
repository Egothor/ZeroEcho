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
package zeroecho.pkix;

import java.util.OptionalInt;

/**
 * The X.509 {@code BasicConstraints} extension value (RFC 5280, 4.2.1.9).
 *
 * @param certificateAuthority whether the subject is a CA
 * @param pathLenConstraint maximum number of subordinate CAs, present only when
 *        {@code certificateAuthority} is {@code true}
 */
public record BasicConstraints(boolean certificateAuthority, OptionalInt pathLenConstraint) {

    /** Canonicalizing constructor. */
    public BasicConstraints {
        if (pathLenConstraint == null) {
            pathLenConstraint = OptionalInt.empty();
        }
        if (!certificateAuthority && pathLenConstraint.isPresent()) {
            throw new IllegalArgumentException("pathLenConstraint is only valid for a CA");
        }
        if (pathLenConstraint.isPresent() && pathLenConstraint.getAsInt() < 0) {
            throw new IllegalArgumentException("pathLenConstraint must not be negative");
        }
    }

    /**
     * An end-entity (non-CA) basic constraints value.
     *
     * @return end-entity basic constraints
     */
    public static BasicConstraints endEntity() {
        return new BasicConstraints(false, OptionalInt.empty());
    }

    /**
     * A CA basic constraints value with no path-length limit.
     *
     * @return unconstrained CA basic constraints
     */
    public static BasicConstraints ca() {
        return new BasicConstraints(true, OptionalInt.empty());
    }

    /**
     * A CA basic constraints value with the given path-length limit.
     *
     * @param pathLen maximum number of subordinate CAs (non-negative)
     * @return path-limited CA basic constraints
     */
    public static BasicConstraints ca(int pathLen) {
        return new BasicConstraints(true, OptionalInt.of(pathLen));
    }
}
