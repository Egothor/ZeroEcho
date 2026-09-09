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
package zeroecho.pki.spi.confirmation;

/**
 * Trusted, request-stateless provider for one key-possession proof suite.
 *
 * <p>Providers are explicitly injected trusted-computing-base components, not
 * client-selected plugins. An implementation must be immutable and thread-safe,
 * or otherwise stateless and thread-safe. It receives no store or mutation
 * capability and must not retain a context, response, credential, public key,
 * challenge, or array obtained during a call.</p>
 *
 * <p>Every operation must fail closed for a suite or profile mismatch. Runtime
 * failures mean that verification could not be established; callers must never
 * reinterpret them as {@link KeyPossessionProofVerification#VERIFIED}.</p>
 */
public interface KeyPossessionProofProvider {

    /**
     * Returns the canonical suite identity served by this provider.
     *
     * @return exact canonical suite identity, equal to the suite identity in every returned descriptor
     */
    String suiteId();

    /**
     * Returns the exact immutable descriptor for one approved RSA modulus ceiling.
     *
     * @param rsaMaximumModulusBits inclusive configured ceiling from 2048 through 16384 bits
     * @return exact descriptor whose binding contains the supplied ceiling
     * @throws IllegalArgumentException if the ceiling or resulting profile is unsupported
     * @throws RuntimeException if the trusted provider cannot construct its descriptor
     */
    KeyPossessionProofDescriptor descriptor(int rsaMaximumModulusBits);

    /**
     * Validates the request-local authoritative public key against the exact
     * configured suite binding and key profile before any caller performs a mutation.
     * Certificate parsing is owned by PKI orchestration and is not delegated to
     * the provider.
     *
     * <p>This preflight is nonmutating and must not retain its input. A later
     * verification request independently repeats all binding and profile checks.</p>
     *
     * @param credential authoritative extracted public key, credential identity, and suite binding
     * @throws NullPointerException if {@code credential} is {@code null}
     * @throws IllegalArgumentException if the binding or key profile is unsupported
     * @throws RuntimeException if secure validation cannot be established
     */
    void validateCredential(KeyPossessionProofCredential credential);

    /**
     * Creates one bounded canonical public challenge presentation without retaining the context.
     *
     * <p>For identical context this operation is deterministic. It performs no
     * I/O, certificate or key parsing, and consults no mutable dependency.</p>
     *
     * @param context exact authoritative persisted challenge context
     * @return immutable canonical presentation for the client
     * @throws NullPointerException if {@code context} is {@code null}
     * @throws IllegalArgumentException if the context does not match this exact provider profile
     * @throws RuntimeException if challenge construction is unavailable
     */
    KeyPossessionProofPresentation createChallenge(KeyPossessionProofChallengeContext context);

    /**
     * Verifies one bounded response against the complete authoritative context.
     *
     * <p>Verification independently validates the exact binding and request-local
     * authoritative public-key profile because it may execute in a separate request from preflight.
     * The context credential identity and binding must exactly equal those in
     * {@code credential}. Provider exceptions never imply that the caller may
     * mutate state.</p>
     *
     * @param context exact authoritative persisted challenge context
     * @param credential authoritative extracted public key, credential identity, and suite binding
     * @param response bounded client response
     * @return closed cryptographic result
     * @throws NullPointerException if an argument is {@code null}
     * @throws IllegalArgumentException if the context, credential, or response does not match this exact profile
     * @throws RuntimeException if verification cannot be established
     */
    KeyPossessionProofVerification verify(KeyPossessionProofChallengeContext context,
            KeyPossessionProofCredential credential, KeyPossessionProofResponse response);
}
