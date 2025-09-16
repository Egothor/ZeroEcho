/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;

import javax.crypto.SecretKey;

import zeroecho.core.audit.AuditListener;
import zeroecho.core.audit.AuditedContexts;
import zeroecho.core.context.CryptoContext;
import zeroecho.core.context.DigestContext;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.context.KemContext;
import zeroecho.core.context.MacContext;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.err.UnsupportedRoleException;
import zeroecho.core.err.UnsupportedSpecException;
import zeroecho.core.policy.CryptoPolicy;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spec.ContextSpec;

/**
 * Static façade and registry for {@link CryptoAlgorithm} providers.
 *
 * <p>
 * {@code CryptoAlgorithms} discovers algorithms via {@link ServiceLoader} and
 * exposes:
 * </p>
 * <ul>
 * <li>a registry from canonical algorithm id to implementation,</li>
 * <li>policy hooks that validate requested operations before contexts are
 * created,</li>
 * <li>global audit wiring (listener + wrapping mode), and</li>
 * <li>convenience methods for context creation and key generation/import.</li>
 * </ul>
 *
 * <h2>Discovery &amp; identity</h2> Implementations register themselves using
 * the Java SPI for {@link CryptoAlgorithm}. If multiple providers advertise the
 * same {@linkplain CryptoAlgorithm#id() id}, the registry throws at startup to
 * avoid ambiguous resolution.
 *
 * <h2>Policy</h2> The active {@link CryptoPolicy} is consulted before any
 * context is created. Policies can deny weak parameters, enforce key-usage
 * separation, or restrict algorithms. If {@link #setPolicy(CryptoPolicy)} is
 * never called or is set to {@code null}, a permissive policy is used.
 *
 * <h2>Auditing</h2> All key lifecycle events and context creation can be
 * reported to a global {@link AuditListener}. The {@link AuditMode} determines
 * whether contexts are wrapped with auditing proxies or relied upon to emit
 * events directly.
 *
 * <h2>Thread-safety</h2> The registry map and global hooks are safe to read
 * concurrently. Hooks are backed by {@code volatile} fields and can be swapped
 * at runtime; there is no global lock.
 *
 * @since 1.0
 */
public final class CryptoAlgorithms {

    private static final Map<String, CryptoAlgorithm> BY_ID;
    private static volatile CryptoPolicy<ContextSpec, Key> POLICY = CryptoPolicy.permissive(); // NOPMD
    private static volatile AuditListener AUDIT = AuditListener.noop(); // NOPMD
    private static volatile AuditMode AUDIT_MODE = AuditMode.OFF; // NOPMD

    private CryptoAlgorithms() {
    }

    static {
        Map<String, CryptoAlgorithm> m = new HashMap<>();
        for (CryptoAlgorithm a : ServiceLoader.load(CryptoAlgorithm.class)) {
            CryptoAlgorithm prev = m.put(a.id(), a);
            if (prev != null) {
                throw new IllegalStateException("Duplicate algorithm id: " + a.id());
            }
        }
        BY_ID = Collections.unmodifiableMap(m);
    }

    /**
     * Returns the set of available algorithm identifiers discovered via
     * {@link ServiceLoader}.
     *
     * <p>
     * The returned set is backed by an unmodifiable registry snapshot. Use these
     * identifiers with {@link #require(String)} or the convenience methods below.
     * </p>
     *
     * @return unmodifiable set of canonical algorithm ids
     */
    public static Set<String> available() {
        return BY_ID.keySet();
    }

    /**
     * Looks up an algorithm implementation by its canonical identifier.
     *
     * <p>
     * If the id is unknown, an {@link IllegalArgumentException} is thrown. This
     * method is preferred over direct access to ensure consistent error handling
     * and to centralize future selection logic.
     * </p>
     *
     * @param id canonical algorithm identifier (e.g., {@code "AES/GCM"} or
     *           {@code "Ed25519"})
     * @return the corresponding {@link CryptoAlgorithm} implementation
     * @throws IllegalArgumentException if no algorithm is registered under
     *                                  {@code id}
     */
    public static CryptoAlgorithm require(String id) {
        CryptoAlgorithm a = BY_ID.get(id);
        if (a == null) {
            throw new IllegalArgumentException("Unknown algorithm id: " + id);
        }
        return a;
    }

    /**
     * Sets the global cryptographic policy applied before any context creation.
     *
     * <p>
     * Pass {@code null} to revert to a permissive policy. Policies should be fast
     * and side-effect free; they are invoked on every
     * {@link #create(String, KeyUsage, Key, ContextSpec)} call.
     * </p>
     *
     * @param p policy to install, or {@code null} to use
     *          {@link CryptoPolicy#permissive()}
     */
    public static void setPolicy(CryptoPolicy<ContextSpec, Key> p) {
        POLICY = (p == null ? CryptoPolicy.<ContextSpec, Key>permissive() : p);
    }

    /**
     * Sets the global {@link AuditListener}.
     *
     * <p>
     * Pass {@code null} to disable custom auditing (a no-op listener will be
     * installed). The listener may be invoked by context proxies (in
     * {@link AuditMode#WRAP}) and by the convenience key factory methods below.
     * </p>
     *
     * @param l listener instance or {@code null} for a no-op listener
     */
    public static void setAuditListener(AuditListener l) {
        AUDIT = (l == null ? AuditListener.noop() : l);
    }

    /**
     * Returns the current global {@link AuditListener}.
     *
     * @return the active audit listener (never {@code null})
     */
    public static AuditListener audit() {
        return AUDIT;
    }

    /**
     * Declares how auditing is applied to cryptographic contexts.
     *
     * <p>
     * The {@code AuditMode} controls whether contexts created by
     * {@link CryptoAlgorithms#create(String, KeyUsage, java.security.Key, zeroecho.core.spec.ContextSpec)}
     * are wrapped in auditing proxies or whether auditing is delegated entirely to
     * the caller.
     * </p>
     *
     * <h2>Modes</h2>
     * <ul>
     * <li>{@link #OFF} - No automatic wrapping of contexts (default). Only explicit
     * events triggered at creation are emitted; no per-operation auditing is
     * injected.</li>
     *
     * <li>{@link #WRAP} - Supported contexts are wrapped in dynamic proxies that
     * emit additional stream-level and per-operation auditing events. Creation
     * events originate from the proxy rather than the factory method.</li>
     *
     * <li>{@link #MANUAL} - No automatic wrapping and no automatic event emission.
     * The caller is fully responsible for invoking audit methods (e.g.,
     * {@link CryptoAlgorithms#audit()}) at the appropriate times.</li>
     * </ul>
     *
     * @since 1.0
     */
    public enum AuditMode {
        /**
         * No automatic wrapping of contexts (default).
         *
         * <p>
         * Only explicit events emitted here (e.g.,
         * {@link AuditListener#onContextCreated}) are sent to the listener;
         * stream-level or per-operation auditing is not injected.
         * </p>
         */
        OFF,
        /**
         * Wraps supported contexts in dynamic proxies that emit stream-level auditing.
         *
         * <p>
         * In this mode, creation events are emitted by the proxy rather than here, and
         * subsequent operations (e.g., updates, finalization) may also be audited
         * depending on the proxy implementation.
         * </p>
         */
        WRAP,
        /**
         * No wrapping and no automatic events.
         *
         * <p>
         * The caller is responsible for emitting all relevant audit events via the
         * {@link #audit()} listener.
         * </p>
         */
        MANUAL
    }

    /**
     * Sets the auditing mode for subsequently created contexts.
     *
     * <p>
     * Passing {@code null} resets the mode to {@link AuditMode#OFF}.
     * </p>
     *
     * @param mode desired auditing strategy or {@code null} for {@code OFF}
     */
    public static void setAuditMode(AuditMode mode) {
        AUDIT_MODE = (mode == null ? AuditMode.OFF : mode);
    }

    /**
     * Returns the current auditing mode.
     *
     * @return active {@link AuditMode}; never {@code null}
     */
    public static AuditMode getAuditMode() {
        return AUDIT_MODE;
    }

    /**
     * Creates a {@link CryptoContext} for the given algorithm id and role, applying
     * policy validation and optional auditing/wrapping.
     *
     * <p>
     * Flow:
     * </p>
     * <ol>
     * <li>Policy validation via
     * {@link CryptoPolicy#validate(String, KeyUsage, Key, ContextSpec)}.</li>
     * <li>Algorithm resolution via {@link #require(String)} and context
     * construction via
     * {@link CryptoAlgorithm#create(KeyUsage, Key, ContextSpec)}.</li>
     * <li>Auditing behavior based on {@link #getAuditMode()}:
     * <ul>
     * <li>{@link AuditMode#OFF}/{@link AuditMode#MANUAL}: emit a creation event
     * immediately via
     * {@link AuditListener#onContextCreated(String, String, KeyUsage, Key, ContextSpec)}.</li>
     * <li>{@link AuditMode#WRAP}: return a proxy (where supported) that emits
     * creation and stream-level events; unknown context types are returned
     * unwrapped.</li>
     * </ul>
     * </li>
     * </ol>
     *
     * @param id   canonical algorithm identifier
     * @param role desired {@link KeyUsage} (e.g., ENCRYPT, VERIFY)
     * @param key  key instance for the role
     * @param spec optional context specification; may be {@code null} to use
     *             algorithm defaults
     * @param <C>  context type
     * @param <K>  key type
     * @param <S>  spec type
     * @return a context ready for use; may be a proxy if {@link AuditMode#WRAP} is
     *         active
     * @throws IOException              if the underlying algorithm fails to create
     *                                  a context
     * @throws IllegalArgumentException if {@code id} is unknown
     * @throws UnsupportedRoleException if the algorithm does not support
     *                                  {@code role}
     * @throws UnsupportedSpecException if the provided key/spec are incompatible
     *                                  with the role
     */
    public static <C extends CryptoContext, K extends Key, S extends ContextSpec> C create(String id, KeyUsage role,
            K key, S spec) throws IOException {

        POLICY.validate(id, role, key, spec);

        CryptoAlgorithm algo = require(id);
        C ctx = algo.create(role, key, spec);

        // In WRAP mode, the proxy will emit creation metadata/events.
        if (AUDIT_MODE != AuditMode.WRAP) {
            AUDIT.onContextCreated(algo.id(), algo.providerName(), role, key, spec);
        }

        if (AUDIT_MODE == AuditMode.WRAP) {
            final AuditListener listener = AUDIT; // pass through the global listener
            if (ctx instanceof SignatureContext) {
                @SuppressWarnings("unchecked")
                C out = (C) AuditedContexts.wrap(ctx, listener, role);
                return out;
            } else if (ctx instanceof EncryptionContext) {
                @SuppressWarnings("unchecked")
                C out = (C) AuditedContexts.wrap(ctx, listener, role);
                return out;
            } else if (ctx instanceof KemContext) {
                @SuppressWarnings("unchecked")
                C out = (C) AuditedContexts.wrap(ctx, listener, role);
                return out;
            } else if (ctx instanceof DigestContext) {
                @SuppressWarnings("unchecked")
                C out = (C) AuditedContexts.wrap(ctx, listener, role);
                return out;
            } else if (ctx instanceof MacContext) {
                @SuppressWarnings("unchecked")
                C out = (C) AuditedContexts.wrap(ctx, listener, role);
                return out;
            }
            // Unknown context type: return as-is (no wrapping).
        }

        return ctx;
    }

    /**
     * Creates a {@link CryptoContext} using the algorithm’s default spec for the
     * role.
     *
     * <p>
     * Equivalent to {@code create(id, role, key, null)}.
     * </p>
     *
     * @param id   canonical algorithm identifier
     * @param role desired {@link KeyUsage}
     * @param key  key instance for the role
     * @param <C>  context type
     * @param <K>  key type
     * @return a context ready for use
     * @throws IOException              if the underlying algorithm fails to create
     *                                  a context
     * @throws IllegalArgumentException if {@code id} is unknown
     * @throws UnsupportedRoleException if the algorithm does not support
     *                                  {@code role}
     */
    public static <C extends CryptoContext, K extends Key> C create(String id, KeyUsage role, K key)
            throws IOException {
        return create(id, role, key, null);
    }

    /**
     * Generates a fresh asymmetric {@link KeyPair} for the given algorithm id and
     * spec.
     *
     * <p>
     * Emits
     * {@link AuditListener#onKeyGenerated(String, String, AlgorithmKeySpec, KeyPair)}
     * on success.
     * </p>
     *
     * @param id   canonical algorithm identifier
     * @param spec algorithm-specific key specification
     * @param <S>  spec type
     * @return newly generated key pair
     * @throws GeneralSecurityException if key generation fails
     * @throws IllegalArgumentException if {@code id} is unknown or the spec is
     *                                  unsupported
     */
    public static <S extends AlgorithmKeySpec> KeyPair keyPair(String id, S spec) throws GeneralSecurityException {
        CryptoAlgorithm algo = require(id);
        @SuppressWarnings("unchecked")
        KeyPair kp = algo.asymmetricKeyBuilder((Class<S>) spec.getClass()).generateKeyPair(spec);
        AUDIT.onKeyGenerated(algo.id(), algo.providerName(), spec, kp);
        return kp;
    }

    /**
     * Imports a {@link PublicKey} using the algorithm’s registered asymmetric
     * builder.
     *
     * <p>
     * Emits {@link AuditListener#onKeyBuilt(String, String, AlgorithmKeySpec, Key)}
     * on success.
     * </p>
     *
     * @param id   canonical algorithm identifier
     * @param spec algorithm-specific key specification containing encoded public
     *             material
     * @param <S>  spec type
     * @return imported public key
     * @throws GeneralSecurityException if import fails or material is invalid
     * @throws IllegalArgumentException if {@code id} is unknown or the spec is
     *                                  unsupported
     */
    public static <S extends AlgorithmKeySpec> PublicKey publicKey(String id, S spec) throws GeneralSecurityException {
        CryptoAlgorithm algo = require(id);
        @SuppressWarnings("unchecked")
        PublicKey k = algo.asymmetricKeyBuilder((Class<S>) spec.getClass()).importPublic(spec);
        AUDIT.onKeyBuilt(algo.id(), algo.providerName(), spec, k);
        return k;
    }

    /**
     * Imports a {@link PrivateKey} using the algorithm’s registered asymmetric
     * builder.
     *
     * <p>
     * Emits {@link AuditListener#onKeyBuilt(String, String, AlgorithmKeySpec, Key)}
     * on success.
     * </p>
     *
     * @param id   canonical algorithm identifier
     * @param spec algorithm-specific key specification containing encoded private
     *             material
     * @param <S>  spec type
     * @return imported private key
     * @throws GeneralSecurityException if import fails or material is invalid
     * @throws IllegalArgumentException if {@code id} is unknown or the spec is
     *                                  unsupported
     */
    public static <S extends AlgorithmKeySpec> PrivateKey privateKey(String id, S spec)
            throws GeneralSecurityException {
        CryptoAlgorithm algo = require(id);
        @SuppressWarnings("unchecked")
        PrivateKey k = algo.asymmetricKeyBuilder((Class<S>) spec.getClass()).importPrivate(spec);
        AUDIT.onKeyBuilt(algo.id(), algo.providerName(), spec, k);
        return k;
    }

    /**
     * Imports a symmetric {@link SecretKey} using the algorithm’s registered
     * builder.
     *
     * <p>
     * Emits {@link AuditListener#onKeyBuilt(String, String, AlgorithmKeySpec, Key)}
     * on success.
     * </p>
     *
     * @param id   canonical algorithm identifier
     * @param spec algorithm-specific key specification containing raw/encoded
     *             material
     * @param <S>  spec type
     * @return imported secret key
     * @throws GeneralSecurityException if import fails or material is invalid
     * @throws IllegalArgumentException if {@code id} is unknown or the spec is
     *                                  unsupported
     */
    public static <S extends AlgorithmKeySpec> SecretKey secretKey(String id, S spec) throws GeneralSecurityException {
        CryptoAlgorithm algo = require(id);
        @SuppressWarnings("unchecked")
        SecretKey k = algo.symmetricKeyBuilder((Class<S>) spec.getClass()).importSecret(spec);
        AUDIT.onKeyBuilt(algo.id(), algo.providerName(), spec, k);
        return k;
    }

    /**
     * Attempts to destroy a key via the JDK {@code Destroyable} interface.
     *
     * <p>
     * If destruction succeeds,
     * {@link AuditListener#onKeyDestroyed(String, String, Key)} is emitted. Any
     * exceptions from {@code destroy()} are swallowed; the method returns
     * {@code false} when destruction did not occur.
     * </p>
     *
     * @param algoId   algorithm identifier used for audit metadata
     * @param provider provider name used for audit metadata
     * @param key      key to destroy
     * @return {@code true} if the key reported destroyed, {@code false} otherwise
     */
    public static boolean destroyKey(String algoId, String provider, Key key) {
        boolean destroyed = false;
        try {
            if (key instanceof javax.security.auth.Destroyable) {
                javax.security.auth.Destroyable d = (javax.security.auth.Destroyable) key;
                if (!d.isDestroyed()) {
                    d.destroy();
                    destroyed = true;
                }
            }
        } catch (Exception ignored) { // NOPMD
            // swallow and report via audit only if destroyed
        }
        if (destroyed) {
            AUDIT.onKeyDestroyed(algoId, provider, key);
        }
        return destroyed;
    }

    /**
     * Convenience wrapper for
     * {@link CryptoAlgorithm#generateSecret(AlgorithmKeySpec)}.
     *
     * @param id   canonical algorithm identifier
     * @param spec algorithm-specific key specification
     * @param <S>  spec type
     * @return newly generated secret key
     * @throws GeneralSecurityException if key generation fails
     * @throws IllegalArgumentException if {@code id} is unknown
     */
    public static <S extends AlgorithmKeySpec> SecretKey generateSecret(String id, S spec)
            throws GeneralSecurityException {
        return require(id).generateSecret(spec);
    }

    /**
     * Convenience wrapper for
     * {@link CryptoAlgorithm#generateKeyPair(AlgorithmKeySpec)}.
     *
     * @param id   canonical algorithm identifier
     * @param spec algorithm-specific key specification
     * @param <S>  spec type
     * @return newly generated key pair
     * @throws GeneralSecurityException if key generation fails
     * @throws IllegalArgumentException if {@code id} is unknown
     */
    public static <S extends AlgorithmKeySpec> KeyPair generateKeyPair(String id, S spec)
            throws GeneralSecurityException {
        return require(id).generateKeyPair(spec);
    }

    /**
     * Convenience wrapper for
     * {@link CryptoAlgorithm#importPublic(AlgorithmKeySpec)}.
     *
     * @param id   canonical algorithm identifier
     * @param spec algorithm-specific key specification
     * @param <S>  spec type
     * @return imported public key
     * @throws GeneralSecurityException if import fails
     * @throws IllegalArgumentException if {@code id} is unknown
     */
    public static <S extends AlgorithmKeySpec> PublicKey importPublic(String id, S spec)
            throws GeneralSecurityException {
        return require(id).importPublic(spec);
    }

    /**
     * Convenience wrapper for
     * {@link CryptoAlgorithm#importPrivate(AlgorithmKeySpec)}.
     *
     * @param id   canonical algorithm identifier
     * @param spec algorithm-specific key specification
     * @param <S>  spec type
     * @return imported private key
     * @throws GeneralSecurityException if import fails
     * @throws IllegalArgumentException if {@code id} is unknown
     */
    public static <S extends AlgorithmKeySpec> PrivateKey importPrivate(String id, S spec)
            throws GeneralSecurityException {
        return require(id).importPrivate(spec);
    }

    /**
     * Convenience wrapper for
     * {@link CryptoAlgorithm#importSecret(AlgorithmKeySpec)}.
     *
     * @param id   canonical algorithm identifier
     * @param spec algorithm-specific key specification
     * @param <S>  spec type
     * @return imported secret key
     * @throws GeneralSecurityException if import fails
     * @throws IllegalArgumentException if {@code id} is unknown
     */
    public static <S extends AlgorithmKeySpec> SecretKey importSecret(String id, S spec)
            throws GeneralSecurityException {
        return require(id).importSecret(spec);
    }
}
