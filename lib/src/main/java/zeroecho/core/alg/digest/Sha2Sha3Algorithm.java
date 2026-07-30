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
package zeroecho.core.alg.digest;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.KeyUsage;
import zeroecho.core.NullKey;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.context.DigestContext;
import zeroecho.core.err.ProviderFailureException;

/**
 * <h2>SHA-2, SHA-3, and SHAKE digest algorithms</h2>
 *
 * Implementation of the {@link CryptoAlgorithm} abstraction for unkeyed hash
 * functions from the SHA-2 and SHA-3 families, including extendable-output
 * functions (XOFs) such as SHAKE128 and SHAKE256.
 *
 * <p>
 * This algorithm is registered under the canonical identifier {@code "DIGEST"}
 * with the display name {@code "SHA-2/SHA-3/SHAKE"}.
 * </p>
 *
 * <h2>Capabilities</h2> The algorithm declares a single capability:
 * <ul>
 * <li>Family: {@link AlgorithmFamily#DIGEST}</li>
 * <li>Role: {@link KeyUsage#DIGEST}</li>
 * <li>Context type: {@link zeroecho.core.context.DigestContext}</li>
 * <li>Key type: {@link NullKey} (no cryptographic key required)</li>
 * <li>Spec type: {@link DigestSpec} (algorithm selection)</li>
 * <li>Default spec: {@link DigestSpec#sha256()}</li>
 * </ul>
 *
 * <h2>Provider model</h2> Internally, this class delegates to the JCA
 * {@link java.security.MessageDigest} implementation corresponding to the
 * chosen digest variant. The constructor performs lookup via
 * {@link MessageDigest#getInstance(String)}, and wraps the result in a
 * {@link JcaDigestContext}.
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Acquire algorithm via static registry
 * CryptoAlgorithm algo = CryptoAlgorithms.require("DIGEST");
 *
 * // Create a digest context for SHA3-512
 * DigestContext ctx = session.createContext(
 *         "DIGEST", KeyUsage.DIGEST, NullKey.INSTANCE, DigestSpec.sha3_512());
 *
 * // Stream data into the digest
 * ctx.update(inputStream);
 *
 * byte[] hash = ctx.doFinal();
 * }</pre>
 *
 * <p>
 * The {@link NullKey} sentinel must always be provided for the key argument
 * since digests are unkeyed functions. The {@link DigestSpec} determines the
 * exact digest variant (SHA-256, SHA-512, SHA3-256, SHAKE128, etc.).
 * </p>
 *
 * <h2>Thread-safety</h2> The {@code Sha2Sha3Algorithm} instance is immutable
 * and can be shared across threads. The created {@link DigestContext} objects
 * are not thread-safe and must not be used concurrently.
 *
 * @since 1.0
 */
public final class Sha2Sha3Algorithm extends AbstractCryptoAlgorithm {
    /**
     * Constructs the SHA-2/SHA-3/SHAKE digest algorithm definition and registers
     * its {@link zeroecho.core.Capability}.
     *
     * <p>
     * The default digest specification is {@link DigestSpec#sha256()}, ensuring
     * compatibility with common tests and catalog listings.
     * </p>
     */
    public Sha2Sha3Algorithm() {
        super("DIGEST", "SHA-2/SHA-3/SHAKE");

        capability(AlgorithmFamily.DIGEST, KeyUsage.DIGEST, DigestContext.class, NullKey.class, DigestSpec.class,
                (NullKey k, DigestSpec s) -> {
                    try {
                        MessageDigest md = MessageDigest.getInstance(s.algorithm().jca());
                        return new JcaDigestContext(this, md, s);
                    } catch (GeneralSecurityException e) {
                        throw new ProviderFailureException("Failed to initialize MessageDigest " + s.algorithm().jca(),
                                e);
                    }
                }, DigestSpec::sha256 // default for catalog/tests
        );
    }
}
