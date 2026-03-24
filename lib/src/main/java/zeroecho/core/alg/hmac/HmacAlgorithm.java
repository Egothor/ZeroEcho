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
package zeroecho.core.alg.hmac;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.context.MacContext;
import zeroecho.core.spi.SymmetricKeyBuilder;

/**
 * <h2>HMAC Algorithm Integration</h2>
 *
 * {@code HmacAlgorithm} registers the Hash-based Message Authentication Code
 * (HMAC) family into the ZeroEcho framework. It provides a single role,
 * {@link KeyUsage#MAC}, which can both produce and verify authentication tags.
 *
 * <p>
 * HMAC is a widely standardized construction that combines a cryptographic hash
 * function with a secret key to provide integrity and authenticity for
 * arbitrary messages. It is secure under the assumption that the underlying
 * hash function is pseudorandom and collision-resistant.
 * </p>
 *
 * <h2>Capabilities</h2>
 * <ul>
 * <li>Family: {@link AlgorithmFamily#SYMMETRIC}</li>
 * <li>Role: {@link KeyUsage#MAC}</li>
 * <li>Context: {@link MacContext}</li>
 * <li>Key type: {@link SecretKey}</li>
 * <li>Spec type: {@link HmacSpec}</li>
 * </ul>
 *
 * <h2>Key management</h2>
 * <ul>
 * <li>{@link HmacKeyGenSpec}: for generating fresh keys using a secure random
 * source and the specified key length.</li>
 * <li>{@link HmacKeyImportSpec}: for wrapping existing raw key material into a
 * {@link SecretKey} instance compatible with HMAC.</li>
 * </ul>
 *
 * <h2>Defaults</h2>
 * <ul>
 * <li>Default MAC spec: {@link HmacSpec#sha256()}</li>
 * <li>Default key generation: 256-bit key for SHA-256 HMAC</li>
 * </ul>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Generate a fresh key for HMAC-SHA256
 * SecretKey key = CryptoAlgorithms.generateSecret("HMAC",
 *     HmacKeyGenSpec.sha256(256));
 *
 * // Create a MAC context
 * MacContext ctx = CryptoAlgorithms.create("HMAC",
 *     KeyUsage.MAC, key, HmacSpec.sha256());
 *
 * ctx.update(data);
 * byte[] tag = ctx.doFinal();
 *
 * // Verification: set expected tag
 * ctx.setExpectedTag(tag);
 * boolean valid = ctx.verify(data);
 * }</pre>
 *
 * @since 1.0
 */
public final class HmacAlgorithm extends AbstractCryptoAlgorithm {
    /**
     * Constructs and registers the HMAC algorithm.
     *
     * <p>
     * The constructor wires the algorithm identifier, declares the MAC capability,
     * and registers symmetric key builders for generation and import. It sets
     * SHA-256 HMAC as the default spec for both catalog metadata and testing.
     * </p>
     *
     * <h4>Initialization steps</h4>
     * <ol>
     * <li>Registers a {@link KeyUsage#MAC} capability bound to {@link MacContext}
     * and {@link HmacSpec}.</li>
     * <li>Registers a symmetric key builder for {@link HmacKeyGenSpec}, which
     * generates keys using the JCA {@link KeyGenerator} API.</li>
     * <li>Registers a symmetric key builder for {@link HmacKeyImportSpec}, which
     * wraps raw byte arrays as {@link SecretKeySpec} instances.</li>
     * </ol>
     */
    public HmacAlgorithm() {
        super("HMAC", "HMAC (generic)");

        // Single capability: use KeyUsage.MAC for both produce and verify.
        // Verify is selected by calling setExpectedTag(...) on the returned MacContext.
        capability(AlgorithmFamily.SYMMETRIC, KeyUsage.MAC, MacContext.class, SecretKey.class, HmacSpec.class,
                (SecretKey k, HmacSpec s) -> {
                    try {
                        return new HmacMacContext(this, k, s.macName());
                    } catch (GeneralSecurityException e) {
                        throw new IOException("Init HMAC failed for " + s.macName(), e);
                    }
                }, HmacSpec::sha256 // default for catalog/tests
        );

        // Key builders (generation/import) — both respect macName in the spec.
        registerSymmetricKeyBuilder(HmacKeyGenSpec.class, new SymmetricKeyBuilder<>() {
            @Override
            public SecretKey generateSecret(HmacKeyGenSpec spec) throws GeneralSecurityException {
                KeyGenerator kg = KeyGenerator.getInstance(spec.macName());
                kg.init(spec.keySizeBits(), new SecureRandom());
                return kg.generateKey();
            }

            @Override
            public SecretKey importSecret(HmacKeyGenSpec spec) {
                throw new UnsupportedOperationException("Use HmacKeyImportSpec for import");
            }
        }, () -> HmacKeyGenSpec.sha256(256) // default keygen spec
        );

        registerSymmetricKeyBuilder(HmacKeyImportSpec.class, new SymmetricKeyBuilder<>() {
            @Override
            public SecretKey generateSecret(HmacKeyImportSpec spec) {
                throw new UnsupportedOperationException("Use HmacKeyGenSpec for generation");
            }

            @Override
            public SecretKey importSecret(HmacKeyImportSpec spec) {
                return new SecretKeySpec(spec.key(), spec.macName());
            }
        }, null);
    }
}
