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
package zeroecho.pki.api.credential;

import java.time.Instant;

import zeroecho.pki.api.PkiException;

/**
 * Resolves authoritative runtime credential status for trust decisions.
 *
 * <p>
 * One {@link Evaluation} captures one authoritative instant and must be reused
 * for every candidate considered by the same operation.
 * </p>
 */
@FunctionalInterface
public interface EffectiveCredentialStatusResolver {

    /**
     * Starts one status evaluation using one captured authoritative time.
     *
     * @return evaluation session
     * @throws PkiException if the authoritative time cannot be obtained safely
     */
    Evaluation beginEvaluation();

    /**
     * One immutable-time effective-status evaluation.
     */
    interface Evaluation {

        /**
         * Returns the authoritative instant captured for this evaluation.
         *
         * @return evaluation instant
         */
        Instant evaluationTime();

        /**
         * Resolves one credential using current revocation state and the captured
         * evaluation time.
         *
         * @param credential credential to resolve
         * @return effective runtime status
         * @throws NullPointerException if {@code credential} is {@code null}
         * @throws PkiException         if current status cannot be resolved safely
         */
        EffectiveCredentialStatus resolve(Credential credential);

        /**
         * Requires a credential to be usable for the supplied operation category.
         *
         * @param credential credential to check
         * @param use        trust-decision category
         * @return the supplied credential when usable
         * @throws NullPointerException if an argument is {@code null}
         * @throws PkiException         if status resolution fails or the credential is
         *                              not usable
         */
        Credential requireUsable(Credential credential, CredentialUse use);
    }
}
