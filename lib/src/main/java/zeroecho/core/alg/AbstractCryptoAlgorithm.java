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
package zeroecho.core.alg;

import java.security.Key;
import java.util.Objects;
import java.util.function.Supplier;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.Capability;
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.CryptoContext;
import zeroecho.core.spec.ContextSpec;
import zeroecho.core.spi.ContextFactoryKS;

/**
 * Convenience base class for concrete {@link CryptoAlgorithm} implementations.
 *
 * <p>
 * {@code AbstractCryptoAlgorithm} streamlines two common tasks during algorithm
 * construction:
 * </p>
 *
 * <ol>
 * <li><b>Binding roles to runtime factories</b> via
 * {@link #capability(AlgorithmFamily, KeyUsage, Class, Class, Class, ContextFactoryKS, Supplier)},
 * which registers a {@link KeyUsage role} together with its expected
 * {@link CryptoContext} type, accepted {@link Key} type, optional
 * {@link ContextSpec} type, the constructor factory, and a default spec
 * supplier.</li>
 * <li><b>Publishing descriptive capabilities</b> by automatically creating and
 * adding a {@link Capability} record that higher layers can inspect for feature
 * discovery, documentation, or automated selection.</li>
 * </ol>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * public final class AesGcmAlgorithm extends AbstractCryptoAlgorithm {
 *   public AesGcmAlgorithm() {
 *     super("AES/GCM", "AES-GCM", "JCA");
 *
 *     capability(
 *         AlgorithmFamily.SYMMETRIC,
 *         KeyUsage.ENCRYPT,
 *         AeadEncryptContext.class,
 *         javax.crypto.SecretKey.class,
 *         AeadSpec.class,
 *         (key, spec) -> new JcaAesGcmEncryptContext(key, spec),
 *         AeadSpec::withRandomNonce);
 *
 *     capability(
 *         AlgorithmFamily.SYMMETRIC,
 *         KeyUsage.DECRYPT,
 *         AeadDecryptContext.class,
 *         javax.crypto.SecretKey.class,
 *         AeadSpec.class,
 *         (key, spec) -> new JcaAesGcmDecryptContext(key, spec),
 *         AeadSpec::withRandomNonce);
 *   }
 * }
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances are immutable once constructed and safe to
 * share across threads. The contexts created by registered factories are not
 * necessarily thread-safe.
 *
 * @since 1.0
 */
public abstract class AbstractCryptoAlgorithm extends CryptoAlgorithm {
    /**
     * Constructs an algorithm with default priority ({@code 0}) and provider
     * {@code "default"}.
     *
     * @param id          canonical, provider-independent identifier (e.g.,
     *                    {@code "AES/GCM"})
     * @param displayName human-friendly name for logs and diagnostics
     * @throws NullPointerException if {@code id} or {@code displayName} is
     *                              {@code null}
     */
    protected AbstractCryptoAlgorithm(String id, String displayName) {
        super(id, displayName);
    }

    /**
     * Constructs an algorithm with default priority ({@code 0}) and an explicit
     * provider name.
     *
     * @param id           canonical, provider-independent identifier
     * @param displayName  human-friendly name for logs and diagnostics
     * @param providerName provider label (e.g., {@code "JCA"}, {@code "BC"},
     *                     {@code "default"})
     * @throws NullPointerException if any argument is {@code null}
     */
    protected AbstractCryptoAlgorithm(String id, String displayName, String providerName) {
        super(id, displayName, providerName);
    }

    /**
     * Declares a capability for this algorithm and binds a runtime factory for the
     * given role.
     *
     * <p>
     * This single call performs two actions atomically:
     * </p>
     * <ul>
     * <li><b>Runtime binding:</b> delegates to
     * {@link CryptoAlgorithm#bindContext(KeyUsage, Class, Class, Class, ContextFactoryKS, Supplier)}
     * so that {@link CryptoAlgorithm#createContext(KeyUsage, Key, ContextSpec)} can
     * construct the appropriate {@link CryptoContext} when invoked.</li>
     * <li><b>Metadata publication:</b> creates a {@link Capability} describing this
     * role (algorithm id, {@link AlgorithmFamily family}, role, context/key/spec
     * types, and default spec supplier) and adds it to the algorithm’s advertised
     * capabilities, discoverable via
     * {@link CryptoAlgorithm#listCapabilities()}.</li>
     * </ul>
     *
     * <h4>Validation</h4> Type checks happen at creation time (via {@code bind})
     * and again when
     * {@link CryptoAlgorithm#createContext(KeyUsage, Key, ContextSpec)} is called.
     * If a factory returns a context not assignable to {@code ctxType}, an
     * {@link IllegalStateException} will be thrown.
     *
     * @param family      high-level algorithm family classification
     * @param role        supported {@link KeyUsage} role (e.g., {@code ENCRYPT},
     *                    {@code VERIFY})
     * @param ctxType     concrete {@link CryptoContext} type constructed by
     *                    {@code factory}
     * @param keyType     accepted {@link Key} type for this role
     * @param specType    accepted {@link ContextSpec} type (may be a marker type)
     * @param factory     constructor that builds a context for (key, spec)
     * @param defaultSpec supplier of the default spec used when callers pass
     *                    {@code null}; capability metadata resolves one stable
     *                    value during registration, while runtime creation retains
     *                    the supplier contract
     * @param <C>         context type
     * @param <K>         key type
     * @param <S>         spec type
     * @throws NullPointerException if any class, factory, supplier, or metadata
     *                              default value is {@code null}
     */
    protected <C extends CryptoContext, K extends Key, S extends ContextSpec> void capability(AlgorithmFamily family,
            KeyUsage role, Class<C> ctxType, Class<K> keyType, Class<S> specType, ContextFactoryKS<C, K, S> factory,
            Supplier<? extends S> defaultSpec) {

        S resolvedDefault = Objects.requireNonNull(defaultSpec.get(), "defaultSpec value must not be null");
        // bind runtime factory
        bindContext(role, ctxType, keyType, specType, factory, defaultSpec);
        // publish metadata
        addCapability(new Capability(id(), family, role, ctxType, keyType, specType, resolvedDefault));
    }
}
