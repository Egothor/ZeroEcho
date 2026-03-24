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
/**
 * Service Provider Interfaces (SPI) for extending ZeroEcho with custom
 * cryptographic algorithms and key builders.
 *
 * <p>
 * This package defines the provider-facing contracts used by algorithms to plug
 * new primitives into the framework while keeping the public API uniform. The
 * SPIs emphasize role-driven context construction, strict spec validation, and
 * safe key lifecycle handling.
 * </p>
 *
 * <h2>How algorithms plug in</h2>
 * <p>
 * An algorithm publishes capabilities and binds each supported
 * {@link zeroecho.core.KeyUsage role} to a factory that creates a matching
 * {@link zeroecho.core.context.CryptoContext}. The binding is registered in the
 * algorithm constructor using {@link ContextConstructorKS}; the role is implied
 * by the binding itself.
 * </p>
 *
 * <pre>{@code
 * // Inside an algorithm's constructor (illustrative):
 * capability(AlgorithmFamily.SYMMETRIC, KeyUsage.ENCRYPT,
 *           zeroecho.core.context.EncryptionContext.class,
 *           javax.crypto.SecretKey.class, zeroecho.core.alg.aes.AesSpec.class,
 *           (k, s) -> new zeroecho.core.alg.aes.AesCipherContext(this, k, true, s, new java.security.SecureRandom()),
 *           () -> zeroecho.core.alg.aes.AesSpec.gcm128(null));
 *
 * capability(AlgorithmFamily.SYMMETRIC, KeyUsage.DECRYPT,
 *           zeroecho.core.context.EncryptionContext.class,
 *           javax.crypto.SecretKey.class, zeroecho.core.alg.aes.AesSpec.class,
 *           (k, s) -> new zeroecho.core.alg.aes.AesCipherContext(this, k, false, s, new java.security.SecureRandom()),
 *           () -> zeroecho.core.alg.aes.AesSpec.gcm128(null));
 * }</pre>
 *
 * <h2>Key material builders and the spec-class keyed registry</h2>
 * <p>
 * Builders are registered per spec class. The algorithm maintains a single map
 * from {@code Class<? extends zeroecho.core.spec.AlgorithmKeySpec>} to a
 * builder instance; lookups are driven by the spec class, not by the high-level
 * operation. This keeps registration simple while letting providers model
 * different intents through different spec types.
 * </p>
 *
 * <ul>
 * <li>{@link AsymmetricKeyBuilder} provides key pair generation and
 * public/private key import for asymmetric algorithms.</li>
 * <li>{@link SymmetricKeyBuilder} provides key generation and key import for
 * {@link javax.crypto.SecretKey}-based algorithms.</li>
 * </ul>
 *
 * <h2>Why a single interface for both key pair generation and key import</h2>
 * <p>
 * There is one cohesive builder interface because the registry keys off the
 * spec class, not the operation. A single builder type per spec class gives one
 * lookup path and one place to enforce spec parsing, format checks, curve or
 * modulus validation, and provider constraints. The public facades in
 * {@link zeroecho.core.CryptoAlgorithm} and
 * {@link zeroecho.core.CryptoAlgorithms} remain compact: they resolve the
 * builder by spec class and then invoke
 * {@link AsymmetricKeyBuilder#generateKeyPair(zeroecho.core.spec.AlgorithmKeySpec)},
 * {@link AsymmetricKeyBuilder#importPublic(zeroecho.core.spec.AlgorithmKeySpec)},
 * {@link AsymmetricKeyBuilder#importPrivate(zeroecho.core.spec.AlgorithmKeySpec)},
 * {@link SymmetricKeyBuilder#generateSecret(zeroecho.core.spec.AlgorithmKeySpec)},
 * or
 * {@link SymmetricKeyBuilder#importSecret(zeroecho.core.spec.AlgorithmKeySpec)}
 * as appropriate.
 * </p>
 * <p>
 * Providers express differences in capability by choosing distinct spec classes
 * rather than multiplying interfaces. For example, a symmetric provider may
 * register {@code AesKeyGenSpec} for generation and {@code AesKeyImportSpec}
 * for import, each with its own builder. The unified interface still fits
 * because the registry discriminates by spec class.
 * </p>
 *
 * <h2>Pattern: separate specs for generation vs import with prescriptive
 * exceptions</h2>
 * <p>
 * It is idiomatic to register two builders for AES: one bound to a generation
 * spec that implements
 * {@link SymmetricKeyBuilder#generateSecret(zeroecho.core.spec.AlgorithmKeySpec)}
 * and rejects import, and one bound to an import spec that implements
 * {@link SymmetricKeyBuilder#importSecret(zeroecho.core.spec.AlgorithmKeySpec)}
 * and rejects generation. Unsupported paths should throw
 * {@link UnsupportedOperationException} with a clear, prescriptive message that
 * points to the correct spec.
 * </p>
 *
 * <pre>{@code
 * // Generation-only builder bound to AesKeyGenSpec
 * registerSymmetricKeyBuilder(zeroecho.core.alg.aes.AesKeyGenSpec.class, new SymmetricKeyBuilder<>() {
 *   &#64;Override public javax.crypto.SecretKey generateSecret(zeroecho.core.alg.aes.AesKeyGenSpec spec)
 *       throws java.security.GeneralSecurityException {
 *     // generate according to spec.keySizeBits()
 *     throw new UnsupportedOperationException("example");
 *   }
 *   &#64;Override public javax.crypto.SecretKey importSecret(zeroecho.core.alg.aes.AesKeyGenSpec spec) {
 *     throw new UnsupportedOperationException("Use AesKeyImportSpec for importing AES keys");
 *   }
 * }, zeroecho.core.alg.aes.AesKeyGenSpec::aes256);
 *
 * // Import-only builder bound to AesKeyImportSpec
 * registerSymmetricKeyBuilder(zeroecho.core.alg.aes.AesKeyImportSpec.class, new SymmetricKeyBuilder<>() {
 *   &#64;Override public javax.crypto.SecretKey generateSecret(zeroecho.core.alg.aes.AesKeyImportSpec spec) {
 *     throw new UnsupportedOperationException("Use AesKeyGenSpec to generate AES keys");
 *   }
 *   @Override public javax.crypto.SecretKey importSecret(zeroecho.core.alg.aes.AesKeyImportSpec spec) {
 *     return new javax.crypto.spec.SecretKeySpec(spec.key(), "AES");
 *   }
 * }, null);
 * }</pre>
 *
 * <p>
 * The same separation can be applied to asymmetric algorithms by using, for
 * example, {@code RsaKeyGenSpec} and {@code RsaKeyImportSpec}. Each spec class
 * maps to exactly one {@link AsymmetricKeyBuilder} in the algorithm's registry.
 * </p>
 *
 * <h2>Context sharing and parameter flow</h2>
 * <p>
 * Contexts that need per-session values (IV, nonce, salt, AAD) may implement
 * {@link ContextAware} to read and write through a shared
 * {@link conflux.CtxInterface}. For symmetric streams that carry lightweight
 * headers, algorithms in {@code zeroecho.core} can use
 * {@link zeroecho.core.SymmetricHeaderCodec}.
 * </p>
 *
 * <h2>Error handling and validation</h2>
 * <ul>
 * <li>Fail fast when keys or specs are incompatible with the bound role.</li>
 * <li>Use {@link java.security.GeneralSecurityException} for key generation or
 * import failures.</li>
 * <li>Use {@link java.io.IOException} from
 * {@link ContextConstructorKS#create(java.security.Key, zeroecho.core.spec.ContextSpec)}
 * when context setup performs I/O.</li>
 * <li>Use {@link UnsupportedOperationException} with a precise message when an
 * operation is intentionally unsupported by the spec or provider, for example
 * "Use AesKeyImportSpec for importing AES keys".</li>
 * </ul>
 *
 * <h2>Thread safety</h2>
 * <p>
 * SPI implementations should be stateless or otherwise safe for concurrent use.
 * Created contexts are not necessarily thread-safe unless explicitly documented
 * by the provider.
 * </p>
 *
 * @since 1.0
 */
package zeroecho.core.spi;
