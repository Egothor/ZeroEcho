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
package zeroecho.sdk;

import java.security.Key;
import java.security.KeyPair;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.audit.AuditListener;
import zeroecho.core.audit.AuditListeners;
import zeroecho.core.audit.AuditMode;
import zeroecho.core.audit.AuditedContexts;
import zeroecho.core.context.AgreementContext;
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
 * Immutable, explicitly scoped runtime configuration for ZeroEcho operations.
 *
 * <p>
 * Each session owns one policy, audit listener, and audit mode. Configuration
 * methods return a new session and never mutate the receiver, so independently
 * created sessions cannot affect one another. The default configuration is a
 * permissive policy, a no-op listener, and {@link AuditMode#OFF}.
 * </p>
 *
 * <p>
 * Sessions share the immutable provider registry owned by
 * {@link CryptoAlgorithms}; provider discovery is therefore performed once for
 * the registry lifecycle. Session instances are safe for concurrent use.
 * Configured policy and listener implementations must themselves support any
 * concurrency with which the session is used.
 * </p>
 *
 * <p>
 * Audit callbacks may receive key and specification objects. Listeners are
 * trusted application components and must not log or retain keys, plaintext,
 * seeds, shared secrets, or sensitive specifications.
 * </p>
 *
 * @since 1.0
 */
public final class ZeroEchoSession {
    private static final int DESTROY_LOCK_STRIPES = 64;
    private static final ReentrantLock[] DESTROY_LOCKS = createDestroyLocks();
    private final CryptoPolicy<ContextSpec, Key> policy;
    private final AuditListener auditListener;
    private final AuditListener auditSink;
    private final AuditMode auditMode;
    private final KeyBuilders keyBuilders;
    private final Pbkdf2Limits pbkdf2Limits;

    /**
     * Creates a session with a permissive policy, no-op audit listener, and
     * {@link AuditMode#OFF}.
     */
    public ZeroEchoSession() {
        this(CryptoPolicy.permissive(), AuditListener.noop(), AuditMode.OFF, null);
    }

    private ZeroEchoSession(CryptoPolicy<ContextSpec, Key> policy, AuditListener auditListener, AuditMode auditMode,
            Pbkdf2Limits pbkdf2Limits) {
        this.policy = Objects.requireNonNull(policy, "policy must not be null");
        this.auditListener = Objects.requireNonNull(auditListener, "auditListener must not be null");
        this.auditSink = AuditListeners.bestEffort(auditListener);
        this.auditMode = Objects.requireNonNull(auditMode, "auditMode must not be null");
        this.pbkdf2Limits = pbkdf2Limits;
        this.keyBuilders = new KeyBuilders(this);
    }

    /**
     * Returns a session with the supplied policy and this session's audit
     * configuration.
     *
     * @param newPolicy policy applied before context creation; must not be
     *                  {@code null}
     * @return a new independently configured session
     * @throws NullPointerException if {@code newPolicy} is {@code null}
     */
    public ZeroEchoSession withPolicy(CryptoPolicy<ContextSpec, Key> newPolicy) {
        return new ZeroEchoSession(Objects.requireNonNull(newPolicy, "newPolicy must not be null"), auditListener,
                auditMode, pbkdf2Limits);
    }

    /**
     * Returns a session with the supplied audit listener and this session's policy
     * and audit mode.
     *
     * @param newAuditListener listener receiving audit callbacks; must not be
     *                         {@code null}
     * @return a new independently configured session
     * @throws NullPointerException if {@code newAuditListener} is {@code null}
     */
    public ZeroEchoSession withAuditListener(AuditListener newAuditListener) {
        return new ZeroEchoSession(policy,
                Objects.requireNonNull(newAuditListener, "newAuditListener must not be null"), auditMode, pbkdf2Limits);
    }

    /**
     * Returns a session with the supplied audit mode and this session's policy and
     * listener.
     *
     * @param newAuditMode audit strategy; must not be {@code null}
     * @return a new independently configured session
     * @throws NullPointerException if {@code newAuditMode} is {@code null}
     */
    public ZeroEchoSession withAuditMode(AuditMode newAuditMode) {
        return new ZeroEchoSession(policy, auditListener,
                Objects.requireNonNull(newAuditMode, "newAuditMode must not be null"), pbkdf2Limits);
    }

    /**
     * Returns a session with explicit PBKDF2 work-factor limits.
     *
     * @param limits deployment-selected limits
     * @return independently configured session
     * @throws NullPointerException if {@code limits} is {@code null}
     */
    public ZeroEchoSession withPbkdf2Limits(Pbkdf2Limits limits) {
        return new ZeroEchoSession(policy, auditListener, auditMode,
                Objects.requireNonNull(limits, "limits must not be null"));
    }

    /**
     * Returns configured PBKDF2 limits.
     *
     * @return explicit deployment limits
     * @throws IllegalStateException if limits were not configured
     */
    public Pbkdf2Limits pbkdf2Limits() {
        if (pbkdf2Limits == null) {
            throw new IllegalStateException("PBKDF2 limits must be configured explicitly");
        }
        return pbkdf2Limits;
    }

    /**
     * Returns the policy owned by this session.
     *
     * @return the non-null policy strategy
     */
    public CryptoPolicy<ContextSpec, Key> policy() {
        return policy;
    }

    /**
     * Returns the audit listener owned by this session.
     *
     * <p>
     * The returned listener is the configured strategy, not mutable session state.
     * It is exposed to support manual audit mode.
     * </p>
     *
     * @return the non-null audit listener
     */
    public AuditListener auditListener() {
        return auditListener;
    }

    /**
     * Returns the audit mode owned by this session.
     *
     * @return the non-null audit mode
     */
    public AuditMode auditMode() {
        return auditMode;
    }

    /**
     * Returns the available algorithm identifiers in deterministic registry order.
     *
     * @return an unmodifiable set of canonical algorithm identifiers
     */
    public Set<String> available() {
        return CryptoAlgorithms.available();
    }

    /**
     * Resolves an algorithm from the authoritative registry.
     *
     * @param id canonical algorithm identifier
     * @return the registered algorithm
     * @throws IllegalArgumentException if no algorithm is registered under
     *                                  {@code id}
     */
    public CryptoAlgorithm require(String id) {
        return CryptoAlgorithms.require(id);
    }

    /**
     * Returns exact session-bound key operations.
     *
     * @return immutable grouped key-operation entry point
     */
    public KeyBuilders keyBuilders() {
        return keyBuilders;
    }

    /**
     * Creates a context after applying this session's policy and audit
     * configuration.
     *
     * @param id   canonical algorithm identifier
     * @param role intended key usage
     * @param key  key compatible with the selected algorithm and role
     * @param spec optional context specification, or {@code null} for the algorithm
     *             default
     * @param <C>  context type
     * @param <K>  key type
     * @param <S>  context specification type
     * @return a ready context, possibly audit-wrapped in {@link AuditMode#WRAP}
     * @throws IllegalArgumentException if the algorithm identifier is unknown or
     *                                  policy validation rejects the operation
     * @throws UnsupportedRoleException if the algorithm does not support
     *                                  {@code role}
     * @throws UnsupportedSpecException if the key or specification is incompatible
     */
    public <C extends CryptoContext, K extends Key, S extends ContextSpec> C createContext(String id, KeyUsage role,
            K key, S spec) {
        policy.validate(id, role, key, spec);

        CryptoAlgorithm algorithm = require(id);
        C context = algorithm.createContext(role, key, spec);
        return finishContext(algorithm, context, role, spec);
    }

    private <C extends CryptoContext, S extends ContextSpec> C finishContext(CryptoAlgorithm algorithm, C context,
            KeyUsage role, S spec) {
        if (auditMode == AuditMode.OFF) {
            notifyContextCreated(algorithm, role, spec);
            return context;
        }
        if (auditMode == AuditMode.WRAP) {
            return wrapForAudit(context, role);
        }
        return context;
    }

    /**
     * Creates a context using the selected algorithm's default specification.
     *
     * @param id   canonical algorithm identifier
     * @param role intended key usage
     * @param key  key compatible with the selected algorithm and role
     * @param <C>  context type
     * @param <K>  key type
     * @return a ready context, possibly audit-wrapped in {@link AuditMode#WRAP}
     * @throws IllegalArgumentException if the algorithm identifier is unknown or
     *                                  policy validation rejects the operation
     * @throws UnsupportedRoleException if the algorithm does not support
     *                                  {@code role}
     */
    public <C extends CryptoContext, K extends Key> C createContext(String id, KeyUsage role, K key) {
        return createContext(id, role, key, null);
    }

    @SuppressWarnings("unchecked")
    private <C extends CryptoContext> C wrapForAudit(C context, KeyUsage role) {
        return (C) switch (context) {
            case SignatureContext signatureContext -> AuditedContexts.wrap(signatureContext, auditSink, role);
            case EncryptionContext encryptionContext -> AuditedContexts.wrap(encryptionContext, auditSink, role);
            case KemContext kemContext -> AuditedContexts.wrap(kemContext, auditSink, role);
            case DigestContext digestContext -> AuditedContexts.wrap(digestContext, auditSink, role);
            case MacContext macContext -> AuditedContexts.wrap(macContext, auditSink, role);
            case AgreementContext agreementContext -> AuditedContexts.wrap(agreementContext, auditSink, role);
        };
    }

    /**
     * Destroys a key and verifies that it entered the destroyed state.
     *
     * @param algorithmId algorithm identifier used as audit metadata
     * @param provider    provider name used as audit metadata
     * @param key         key to destroy; must not be {@code null}
     * @return {@code true} only when this call transitions the key to destroyed;
     *         {@code false} for a non-destroyable or already destroyed key
     * @throws NullPointerException   if {@code key} is {@code null}
     * @throws DestroyFailedException if destruction fails or the key does not
     *                                report itself destroyed afterward
     * @throws RuntimeException       if the key's lifecycle implementation throws
     *                                one
     */
    public boolean destroyKey(String algorithmId, String provider, Key key) throws DestroyFailedException {
        Objects.requireNonNull(key, "key must not be null");
        if (!(key instanceof Destroyable destroyable)) {
            return false;
        }
        ReentrantLock destroyLock = DESTROY_LOCKS[Math.floorMod(System.identityHashCode(key), DESTROY_LOCKS.length)];
        destroyLock.lock();
        try {
            if (destroyable.isDestroyed()) {
                return false;
            }
            destroyable.destroy();
            if (!destroyable.isDestroyed()) {
                throw new DestroyFailedException("Key did not enter the destroyed state");
            }
        } finally {
            destroyLock.unlock();
        }
        auditSink.onKeyDestroyed(algorithmId, provider, key);
        return true;
    }

    private <S extends ContextSpec> void notifyContextCreated(CryptoAlgorithm algorithm, KeyUsage role, S spec) {
        Map<String, Object> metadata = spec == null ? Map.of() : Map.of("specType", spec.getClass().getName());
        auditSink.onContextCreatedMeta(UUID.randomUUID().toString(), algorithm.id(), algorithm.providerName(), role,
                "n/a", metadata);
    }

    /* default */ void notifyKeyPairGenerated(CryptoAlgorithm algorithm, AlgorithmKeySpec spec, KeyPair keyPair) {
        auditSink.onKeyGenerated(algorithm.id(), algorithm.providerName(), spec, keyPair);
    }

    /* default */ void notifyKeyGenerated(CryptoAlgorithm algorithm, AlgorithmKeySpec spec, Key key) {
        notifyKeyBuilt(algorithm, spec, key);
    }

    /* default */ void notifyKeyBuilt(CryptoAlgorithm algorithm, AlgorithmKeySpec spec, Key key) {
        auditSink.onKeyBuilt(algorithm.id(), algorithm.providerName(), spec, key);
    }

    private static ReentrantLock[] createDestroyLocks() {
        ReentrantLock[] locks = new ReentrantLock[DESTROY_LOCK_STRIPES];
        for (int index = 0; index < locks.length; index++) {
            locks[index] = new ReentrantLock();
        }
        return locks;
    }
}
