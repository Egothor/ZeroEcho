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
package zeroecho.pki.api.content;

/**
 * Explicit deployment-owned resource constraint.
 *
 * <p>
 * This type distinguishes absence of a deployment limit from a positive finite
 * limit without nullable numbers or sentinel values. It never changes PKI,
 * algorithm or X.509 binding semantics.
 * </p>
 */
public sealed interface ResourceLimit permits ResourceLimit.UnrestrictedByDeployment, ResourceLimit.LimitedTo {
    /** Smallest valid observed aggregate value. */
    long EMPTY = 0L;

    /**
     * Checks an incrementally observed non-negative value.
     *
     * @param observed observed aggregate count or byte length
     * @throws IllegalArgumentException if {@code observed} is negative
     * @throws ResourceLimitExceededException if the configured limit is exceeded
     */
    void requireAllows(long observed);

    /**
     * Explicit absence of a deployment-owned limit.
     */
    record UnrestrictedByDeployment() implements ResourceLimit {
        @Override
        public void requireAllows(long observed) {
            if (observed < EMPTY) {
                throw new IllegalArgumentException("Observed resource value must not be negative");
            }
        }
    }

    /**
     * Positive finite deployment-owned limit.
     *
     * @param maximum inclusive maximum
     */
    record LimitedTo(long maximum) implements ResourceLimit {
        /**
         * Creates a finite limit.
         *
         * @throws IllegalArgumentException if {@code maximum} is not positive
         */
        public LimitedTo {
            if (maximum <= EMPTY) {
                throw new IllegalArgumentException("Deployment resource limit must be positive");
            }
        }

        @Override
        public void requireAllows(long observed) {
            if (observed < EMPTY) {
                throw new IllegalArgumentException("Observed resource value must not be negative");
            }
            if (observed > maximum) {
                throw new ResourceLimitExceededException();
            }
        }
    }

    /**
     * Stable non-sensitive failure for deployment resource rejection.
     */
    final class ResourceLimitExceededException extends IllegalStateException {
        private static final long serialVersionUID = 5780535874172354935L;

        private ResourceLimitExceededException() {
            super("Deployment resource limit exceeded: code=DEPLOYMENT_RESOURCE_LIMIT_EXCEEDED");
        }
    }
}
