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
package zeroecho.sdk.hybrid.signature;

import java.util.Objects;

import zeroecho.core.spec.ContextSpec;

/**
 * Immutable definition of a hybrid signature composition.
 *
 * {@code HybridSignatureProfile} is a pure configuration object that defines:
 * <ul>
 * <li>which two signature algorithms participate in the hybrid
 * composition,</li>
 * <li>their fixed ordering within the produced signature trailer,</li>
 * <li>the verification aggregation rule applied to their results.</li>
 * </ul>
 *
 * <p>
 * The profile is the <em>single source of truth</em> for hybrid signature
 * processing. No algorithm identifiers or metadata are embedded in the
 * signature trailer itself; both signing and verification sides must use the
 * same profile.
 * </p>
 *
 * <p>
 * Instances of this record are immutable and thread-safe.
 * </p>
 *
 * @param classicSigId canonical identifier of the classical signature algorithm
 *                     (for example {@code "Ed25519"})
 * @param pqcSigId     canonical identifier of the post-quantum signature
 *                     algorithm (for example {@code "ML-DSA-65"})
 * @param classicSpec  optional {@link ContextSpec} for the classical signature
 *                     engine; may be {@code null}
 * @param pqcSpec      optional {@link ContextSpec} for the post-quantum
 *                     signature engine; may be {@code null}
 * @param verifyRule   aggregation rule applied during verification
 *
 * @since 1.0
 */
public record HybridSignatureProfile(String classicSigId, String pqcSigId, ContextSpec classicSpec, ContextSpec pqcSpec,
        VerifyRule verifyRule) {

    /**
     * Verification aggregation rule for hybrid signatures.
     *
     * @since 1.0
     */
    public enum VerifyRule {
        /**
         * Both component signatures must verify successfully.
         */
        AND,

        /**
         * At least one component signature must verify successfully.
         */
        OR
    }

    /**
     * Canonical constructor with invariant checks.
     *
     * <p>
     * Uses {@link Objects#requireNonNull(Object, String)} to enforce mandatory
     * components while keeping validation idiomatic and consistent with the rest of
     * the ZeroEcho codebase.
     * </p>
     *
     * @throws NullPointerException if {@code classicSigId}, {@code pqcSigId}, or
     *                              {@code verifyRule} is {@code null}
     */
    public HybridSignatureProfile {
        Objects.requireNonNull(classicSigId, "classicSigId");
        Objects.requireNonNull(pqcSigId, "pqcSigId");
        Objects.requireNonNull(verifyRule, "verifyRule");
    }
}
