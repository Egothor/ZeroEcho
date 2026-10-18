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
package zeroecho.sdk.builders;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;
import java.util.function.Supplier;

import conflux.CtxInterface;
import conflux.Key;
import zeroecho.core.KeyUsage;
import zeroecho.core.spec.ContextSpec;
import zeroecho.core.tag.TagEngine;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.hybrid.signature.HybridSignatureContexts;
import zeroecho.sdk.hybrid.signature.HybridSignatureProfile;

/**
 * Signature-specific trailer builder for {@link DataContent} pipelines.
 *
 * <p>
 * This class is intended as a convenient, signature-specialized replacement
 * for:
 * </p>
 *
 * <pre>
 * new TagTrailerDataContentBuilder&lt;Signature&gt;(engine).bufferSize(8192)
 * new TagTrailerDataContentBuilder&lt;Signature&gt;(engine).bufferSize(8192).throwOnMismatch()
 * </pre>
 *
 * <p>
 * It keeps {@link TagTrailerDataContentBuilder} as the generic implementation
 * while providing a compact API for {@code Signature} usage, including
 * construction of {@code SignatureContext} for both single-algorithm and hybrid
 * signatures.
 * </p>
 *
 * <h2>Mode selection</h2>
 * <ul>
 * <li>{@link #core(TagEngine)} / {@link #core(Supplier)}: wraps a ready engine
 * (same parameters as {@link TagTrailerDataContentBuilder}).</li>
 * <li>{@link #single(ZeroEchoSession)}: constructs a non-hybrid
 * {@code SignatureContext}.</li>
 * <li>{@link #hybrid(ZeroEchoSession)}: constructs a hybrid
 * {@code SignatureContext} via {@link HybridSignatureContexts}.</li>
 * </ul>
 *
 * <p>
 * Context construction is in-memory. Checked I/O failures arise only when a
 * built stream is attached or processed.
 * </p>
 *
 * @since 1.0
 */
public final class SignatureTrailerDataContentBuilder implements DataContentBuilder<DataContent> {

    private final TagTrailerDataContentBuilder<Signature> delegate;

    private SignatureTrailerDataContentBuilder(TagEngine<Signature> engine) {
        this.delegate = new TagTrailerDataContentBuilder<>(engine);
    }

    private SignatureTrailerDataContentBuilder(Supplier<? extends TagEngine<Signature>> engineFactory) {
        this.delegate = new TagTrailerDataContentBuilder<>(engineFactory);
    }

    /**
     * Core mode: wraps a fixed engine instance.
     *
     * <p>
     * This is the direct signature-specialized equivalent of:
     * {@code new TagTrailerDataContentBuilder<Signature>(engine)}.
     * </p>
     *
     * @param engine signature engine (typically a {@code SignatureContext}); must
     *               not be {@code null}
     * @return builder instance
     * @throws NullPointerException if {@code engine} is {@code null}
     * @since 1.0
     */
    public static SignatureTrailerDataContentBuilder core(TagEngine<Signature> engine) {
        Objects.requireNonNull(engine, "engine");
        return new SignatureTrailerDataContentBuilder(engine);
    }

    /**
     * Core mode: wraps an engine factory.
     *
     * <p>
     * This is the direct signature-specialized equivalent of:
     * {@code new TagTrailerDataContentBuilder<Signature>(engineFactory)}.
     * </p>
     *
     * @param engineFactory engine factory; must not be {@code null}
     * @return builder instance
     * @throws NullPointerException if {@code engineFactory} is {@code null}
     * @since 1.0
     */
    public static SignatureTrailerDataContentBuilder core(Supplier<? extends TagEngine<Signature>> engineFactory) {
        Objects.requireNonNull(engineFactory, "engineFactory");
        return new SignatureTrailerDataContentBuilder(engineFactory);
    }

    /**
     * Enters single-algorithm (non-hybrid) construction helpers.
     *
     * @param session active session used to create signature contexts
     * @return selector for creating signing/verifying builders
     * @since 1.0
     */
    public static SingleSelector single(ZeroEchoSession session) {
        return new SingleSelector(session);
    }

    /**
     * Enters hybrid signature construction helpers.
     *
     * @param session active session used to create signature contexts
     * @return selector for creating signing/verifying builders
     * @since 1.0
     */
    public static HybridSelector hybrid(ZeroEchoSession session) {
        return new HybridSelector(session);
    }

    /**
     * Sets the internal I/O buffer size used when stripping the trailer.
     *
     * @param bytes buffer size in bytes; must be at least 1
     * @return this builder for chaining
     * @throws IllegalArgumentException if {@code bytes < 1}
     * @since 1.0
     */
    public SignatureTrailerDataContentBuilder bufferSize(int bytes) {
        delegate.bufferSize(bytes);
        return this;
    }

    /**
     * Configures verification to throw on mismatch (default verification behavior).
     *
     * @return this builder for chaining
     * @since 1.0
     */
    public SignatureTrailerDataContentBuilder throwOnMismatch() {
        delegate.throwOnMismatch();
        return this;
    }

    /**
     * Instead of throwing on mismatch, records the verification outcome into a
     * context flag.
     *
     * @param ctx       context instance to receive the flag; must not be
     *                  {@code null}
     * @param verifyKey key under which the {@code Boolean} result is recorded; must
     *                  not be {@code null}
     * @return this builder for chaining
     * @throws NullPointerException if {@code ctx} or {@code verifyKey} is
     *                              {@code null}
     * @since 1.0
     */
    public SignatureTrailerDataContentBuilder flagInContext(CtxInterface ctx, Key<Boolean> verifyKey) {
        delegate.flagInContext(Objects.requireNonNull(ctx, "ctx"), Objects.requireNonNull(verifyKey, "verifyKey"));
        return this;
    }

    @Override
    public DataContent build(boolean encrypt) {
        return delegate.build(encrypt);
    }

    // ======================================================================
    // Single-algorithm helpers
    // ======================================================================

    /**
     * Helper entry for single-algorithm signature construction.
     *
     * @since 1.0
     */
    public static final class SingleSelector {

        private final ZeroEchoSession session;

        private SingleSelector(ZeroEchoSession session) {
            this.session = Objects.requireNonNull(session, "session");
        }

        /**
         * Creates a signing trailer for a single signature algorithm (no spec).
         *
         * @param algorithmId signature algorithm id
         * @param privateKey  private key for signing
         * @return builder ready to be added to a pipeline
         * @throws NullPointerException  if {@code algorithmId} or {@code privateKey} is
         *                               {@code null}
         * @throws IllegalStateException if the signature context cannot be created
         *                               (e.g., I/O/provider issues)
         * @since 1.0
         */
        public SignatureTrailerDataContentBuilder sign(String algorithmId, PrivateKey privateKey) {
            return sign(algorithmId, privateKey, null);
        }

        /**
         * Creates a signing trailer for a single signature algorithm with an optional
         * spec.
         *
         * @param algorithmId signature algorithm id
         * @param privateKey  private key for signing
         * @param spec        optional context spec (may be {@code null})
         * @return builder ready to be added to a pipeline
         * @throws NullPointerException  if {@code algorithmId} or {@code privateKey} is
         *                               {@code null}
         * @throws IllegalStateException if the signature context cannot be created
         *                               (e.g., I/O/provider issues)
         * @since 1.0
         */
        public SignatureTrailerDataContentBuilder sign(String algorithmId, PrivateKey privateKey, ContextSpec spec) {
            Objects.requireNonNull(algorithmId, "algorithmId");
            Objects.requireNonNull(privateKey, "privateKey");

            Supplier<TagEngine<Signature>> factory = () -> session.createContext(algorithmId, KeyUsage.SIGN, privateKey,
                    spec);

            return core(factory);
        }

        /**
         * Creates a verification trailer for a single signature algorithm (no spec).
         *
         * @param algorithmId signature algorithm id
         * @param publicKey   public key for verification
         * @return builder ready to be added to a pipeline
         * @throws NullPointerException  if {@code algorithmId} or {@code publicKey} is
         *                               {@code null}
         * @throws IllegalStateException if the signature context cannot be created
         *                               (e.g., I/O/provider issues)
         * @since 1.0
         */
        public SignatureTrailerDataContentBuilder verify(String algorithmId, PublicKey publicKey) {
            return verify(algorithmId, publicKey, null);
        }

        /**
         * Creates a verification trailer for a single signature algorithm with an
         * optional spec.
         *
         * @param algorithmId signature algorithm id
         * @param publicKey   public key for verification
         * @param spec        optional context spec (may be {@code null})
         * @return builder ready to be added to a pipeline
         * @throws NullPointerException  if {@code algorithmId} or {@code publicKey} is
         *                               {@code null}
         * @throws IllegalStateException if the signature context cannot be created
         *                               (e.g., I/O/provider issues)
         * @since 1.0
         */
        public SignatureTrailerDataContentBuilder verify(String algorithmId, PublicKey publicKey, ContextSpec spec) {
            Objects.requireNonNull(algorithmId, "algorithmId");
            Objects.requireNonNull(publicKey, "publicKey");

            Supplier<TagEngine<Signature>> factory = () -> session.createContext(algorithmId, KeyUsage.VERIFY,
                    publicKey, spec);

            return core(factory);
        }
    }

    // ======================================================================
    // Hybrid helpers
    // ======================================================================

    /**
     * Helper entry for hybrid signature construction.
     *
     * @since 1.0
     */
    public static final class HybridSelector {

        private static final int DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024;
        private final ZeroEchoSession session;

        private HybridSelector(ZeroEchoSession session) {
            this.session = Objects.requireNonNull(session, "session");
        }

        /**
         * Creates a hybrid signing trailer for the common case where both specs are
         * {@code null}.
         *
         * @param classicSigId   classic signature algorithm id
         * @param pqcSigId       post-quantum signature algorithm id
         * @param rule           aggregation rule
         * @param classicPrivate classic private key
         * @param pqcPrivate     PQC private key
         * @return builder ready to be added to a pipeline
         * @throws NullPointerException  if any required argument is {@code null}
         * @throws IllegalStateException if the hybrid context cannot be created
         * @since 1.0
         */
        public SignatureTrailerDataContentBuilder sign(String classicSigId, String pqcSigId,
                HybridSignatureProfile.VerifyRule rule, PrivateKey classicPrivate, PrivateKey pqcPrivate) {
            return sign(classicSigId, pqcSigId, null, null, rule, classicPrivate, pqcPrivate, DEFAULT_MAX_BODY_BYTES);
        }

        /**
         * Creates a hybrid verification trailer for the common case where both specs
         * are {@code null}.
         *
         * @param classicSigId  classic signature algorithm id
         * @param pqcSigId      post-quantum signature algorithm id
         * @param rule          aggregation rule
         * @param classicPublic classic public key
         * @param pqcPublic     PQC public key
         * @return builder ready to be added to a pipeline
         * @throws NullPointerException  if any required argument is {@code null}
         * @throws IllegalStateException if the hybrid context cannot be created
         * @since 1.0
         */
        public SignatureTrailerDataContentBuilder verify(String classicSigId, String pqcSigId,
                HybridSignatureProfile.VerifyRule rule, PublicKey classicPublic, PublicKey pqcPublic) {
            return verify(classicSigId, pqcSigId, null, null, rule, classicPublic, pqcPublic, DEFAULT_MAX_BODY_BYTES);
        }

        /**
         * Creates a hybrid signing trailer with optional specs and explicit
         * {@code maxBodyBytes}.
         *
         * @param classicSigId   classic signature algorithm id
         * @param pqcSigId       post-quantum signature algorithm id
         * @param classicSpec    optional classic spec (may be {@code null})
         * @param pqcSpec        optional PQC spec (may be {@code null})
         * @param rule           aggregation rule
         * @param classicPrivate classic private key
         * @param pqcPrivate     PQC private key
         * @param maxBodyBytes   maximum body size accepted by the hybrid context; must
         *                       be at least 1
         * @return builder ready to be added to a pipeline
         * @throws NullPointerException     if any required argument is {@code null}
         * @throws IllegalArgumentException if {@code maxBodyBytes < 1}
         * @throws IllegalStateException    if the hybrid context cannot be created
         * @since 1.0
         */
        public SignatureTrailerDataContentBuilder sign(String classicSigId, String pqcSigId, ContextSpec classicSpec,
                ContextSpec pqcSpec, HybridSignatureProfile.VerifyRule rule, PrivateKey classicPrivate,
                PrivateKey pqcPrivate, int maxBodyBytes) {
            Objects.requireNonNull(classicSigId, "classicSigId");
            Objects.requireNonNull(pqcSigId, "pqcSigId");
            Objects.requireNonNull(rule, "rule");
            Objects.requireNonNull(classicPrivate, "classicPrivate");
            Objects.requireNonNull(pqcPrivate, "pqcPrivate");
            if (maxBodyBytes < 1) { // NOPMD
                throw new IllegalArgumentException("maxBodyBytes must be >= 1");
            }

            HybridSignatureProfile profile = new HybridSignatureProfile(classicSigId, pqcSigId, classicSpec, pqcSpec,
                    rule);

            Supplier<TagEngine<Signature>> factory = () -> {
                try {
                    return HybridSignatureContexts.sign(session, profile, classicPrivate, pqcPrivate, maxBodyBytes);
                } catch (RuntimeException e) { // NOPMD
                    throw e;
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to create hybrid SIGN SignatureContext", e);
                }
            };

            return core(factory);
        }

        /**
         * Creates a hybrid verification trailer with optional specs and explicit
         * {@code maxBodyBytes}.
         *
         * @param classicSigId  classic signature algorithm id
         * @param pqcSigId      post-quantum signature algorithm id
         * @param classicSpec   optional classic spec (may be {@code null})
         * @param pqcSpec       optional PQC spec (may be {@code null})
         * @param rule          aggregation rule
         * @param classicPublic classic public key
         * @param pqcPublic     PQC public key
         * @param maxBodyBytes  maximum body size accepted by the hybrid context; must
         *                      be at least 1
         * @return builder ready to be added to a pipeline
         * @throws NullPointerException     if any required argument is {@code null}
         * @throws IllegalArgumentException if {@code maxBodyBytes < 1}
         * @throws IllegalStateException    if the hybrid context cannot be created
         * @since 1.0
         */
        public SignatureTrailerDataContentBuilder verify(String classicSigId, String pqcSigId, ContextSpec classicSpec,
                ContextSpec pqcSpec, HybridSignatureProfile.VerifyRule rule, PublicKey classicPublic,
                PublicKey pqcPublic, int maxBodyBytes) {
            Objects.requireNonNull(classicSigId, "classicSigId");
            Objects.requireNonNull(pqcSigId, "pqcSigId");
            Objects.requireNonNull(rule, "rule");
            Objects.requireNonNull(classicPublic, "classicPublic");
            Objects.requireNonNull(pqcPublic, "pqcPublic");
            if (maxBodyBytes < 1) { // NOPMD
                throw new IllegalArgumentException("maxBodyBytes must be >= 1");
            }

            HybridSignatureProfile profile = new HybridSignatureProfile(classicSigId, pqcSigId, classicSpec, pqcSpec,
                    rule);

            Supplier<TagEngine<Signature>> factory = () -> {
                try {
                    return HybridSignatureContexts.verify(session, profile, classicPublic, pqcPublic, maxBodyBytes);
                } catch (RuntimeException e) { // NOPMD
                    throw e;
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to create hybrid VERIFY SignatureContext", e);
                }
            };

            return core(factory);
        }
    }
}
