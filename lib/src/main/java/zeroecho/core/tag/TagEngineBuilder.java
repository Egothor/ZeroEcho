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
package zeroecho.core.tag;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;
import java.util.function.Supplier;

import javax.crypto.SecretKey;

import zeroecho.core.KeyUsage;
import zeroecho.core.NullKey;
import zeroecho.core.alg.digest.DigestSpec;
import zeroecho.core.alg.ecdsa.EcdsaCurveSpec;
import zeroecho.core.alg.hmac.HmacSpec;
import zeroecho.core.alg.rsa.RsaSigSpec;
import zeroecho.core.spec.ContextSpec;
import zeroecho.core.spec.VoidSpec;
import zeroecho.sdk.ZeroEchoSession;

/**
 * Factory-style builder that supplies fresh {@link TagEngine} instances on
 * demand.
 *
 * <p>
 * Each {@code TagEngineBuilder} holds a factory that typically delegates to
 * {@link ZeroEchoSession#createContext(String, KeyUsage, java.security.Key, ContextSpec)}
 * so that session policy and auditing are consistently enforced. A new engine
 * instance is created for each call to {@link #get()}.
 * </p>
 *
 * <p>
 * The type parameter {@code T} reflects the auxiliary type used by the concrete
 * engine (for example {@link java.security.Signature} for signature engines, or
 * {@code byte[]} for digest and HMAC engines).
 * </p>
 *
 * <h2>Usage</h2> <pre>
 * {@code
 * // Digest-based tag
 * TagTrailerDataContentBuilder tag =
 *     new TagTrailerDataContentBuilder(
 *         TagEngineBuilder.digest(DigestSpec.sha256()));
 *
 * // Digital signature tag (Ed25519)
 * TagTrailerDataContentBuilder sig =
 *     new TagTrailerDataContentBuilder(
 *         TagEngineBuilder.ed25519Sign(privateKey));
 * }
 * </pre>
 *
 * @param <T> auxiliary type used by the engine (for example
 *            {@link java.security.Signature})
 * @since 1.0
 */
public final class TagEngineBuilder<T> implements Supplier<TagEngine<T>> {
    /**
     * 
     */
    private static final String PUBLIC_KEY = "publicKey";
    /**
     * 
     */
    private static final String PRIVATE_KEY = "privateKey";
    private final Supplier<TagEngine<T>> factory;

    private TagEngineBuilder(Supplier<TagEngine<T>> factory) {
        this.factory = Objects.requireNonNull(factory, "factory");
    }

    /**
     * Returns a new {@link TagEngine} produced by the underlying factory.
     *
     * @return a fresh tag engine instance
     */
    @Override
    public TagEngine<T> get() {
        return factory.get();
    }

    /**
     * Creates a builder for an unkeyed digest engine.
     *
     * <p>
     * If {@code spec} is {@code null}, {@link DigestSpec#sha256()} is used.
     * </p>
     *
     * @param spec digest specification; may be {@code null} to select the default
     * @return a builder that produces digest-based {@link TagEngine} instances
     */
    public static TagEngineBuilder<byte[]> digest(final ZeroEchoSession session, final DigestSpec spec) {
        Objects.requireNonNull(session, "session");
        final DigestSpec s = spec == null ? DigestSpec.sha256() : spec;
        return new TagEngineBuilder<>(() -> session.createContext("DIGEST", KeyUsage.DIGEST, NullKey.INSTANCE, s));
    }

    /**
     * Creates a builder for a keyed HMAC engine.
     *
     * <p>
     * If {@code spec} is {@code null}, {@link HmacSpec#sha256()} is used.
     * </p>
     *
     * @param key  secret key used for MAC computation; must not be {@code null}
     * @param spec HMAC specification; may be {@code null} to select the default
     * @return a builder that produces HMAC-based {@link TagEngine} instances
     * @throws NullPointerException if {@code key} is {@code null}
     */
    public static TagEngineBuilder<byte[]> hmac(final ZeroEchoSession session, final SecretKey key,
            final HmacSpec spec) {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(key, "key");
        final HmacSpec s = spec == null ? HmacSpec.sha256() : spec;
        return new TagEngineBuilder<>(() -> session.createContext("HMAC", KeyUsage.MAC, key, s));
    }

    /**
     * Creates a builder for a signature engine of the given algorithm.
     *
     * <p>
     * The key type determines the role: a {@link PrivateKey} selects
     * {@link KeyUsage#SIGN}, and a {@link PublicKey} selects
     * {@link KeyUsage#VERIFY}.
     * </p>
     *
     * <p>
     * If {@code spec} is {@code null}, {@link VoidSpec#INSTANCE} is used.
     * </p>
     *
     * @param id   canonical algorithm identifier (for example "Ed25519", "RSA",
     *             "ECDSA"); must not be {@code null}
     * @param key  private or public key to bind the engine; must not be
     *             {@code null}
     * @param spec context specification; may be {@code null} to select the default
     * @return a builder that produces signature-based {@link TagEngine} instances
     * @throws IllegalArgumentException if {@code key} is not a supported type
     * @throws NullPointerException     if {@code id} or {@code key} is {@code null}
     */
    public static TagEngineBuilder<Signature> signature(final ZeroEchoSession session, final String id,
            final java.security.Key key, final ContextSpec spec) {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(key, "key");

        final KeyUsage role = (key instanceof PrivateKey) ? KeyUsage.SIGN
                : (key instanceof PublicKey) ? KeyUsage.VERIFY : null;
        if (role == null) {
            throw new IllegalArgumentException("Unsupported key type for signature engine: " + key.getClass());
        }

        final ContextSpec s = spec == null ? VoidSpec.INSTANCE : spec;
        return new TagEngineBuilder<>(() -> session.createContext(id, role, key, s));
    }

    /**
     * Creates a builder for an Ed25519 signing engine.
     *
     * @param privateKey private signing key; must not be {@code null}
     * @return a builder that produces Ed25519 signature engines in SIGN mode
     * @throws NullPointerException if {@code privateKey} is {@code null}
     */
    public static TagEngineBuilder<Signature> ed25519Sign(final ZeroEchoSession session, final PrivateKey privateKey) {
        Objects.requireNonNull(privateKey, PRIVATE_KEY);
        return signature(session, "Ed25519", privateKey, VoidSpec.INSTANCE);
    }

    /**
     * Creates a builder for an Ed25519 verification engine.
     *
     * @param publicKey public verification key; must not be {@code null}
     * @return a builder that produces Ed25519 signature engines in VERIFY mode
     * @throws NullPointerException if {@code publicKey} is {@code null}
     */
    public static TagEngineBuilder<Signature> ed25519Verify(final ZeroEchoSession session, final PublicKey publicKey) {
        Objects.requireNonNull(publicKey, PUBLIC_KEY);
        return signature(session, "Ed25519", publicKey, VoidSpec.INSTANCE);
    }

    /**
     * Creates a builder for an RSA signing engine.
     *
     * <p>
     * If {@code spec} is {@code null}, PKCS#1 PSS with SHA-256 and a 32-byte salt
     * is used.
     * </p>
     *
     * @param privateKey private signing key; must not be {@code null}
     * @param spec       RSA signature specification; may be {@code null} to select
     *                   the default
     * @return a builder that produces RSA signature engines in SIGN mode
     * @throws NullPointerException if {@code privateKey} is {@code null}
     */
    public static TagEngineBuilder<Signature> rsaSign(final ZeroEchoSession session, final PrivateKey privateKey,
            final RsaSigSpec spec) {
        Objects.requireNonNull(privateKey, PRIVATE_KEY);
        return signature(session, "RSA", privateKey, spec == null ? RsaSigSpec.pss(RsaSigSpec.Hash.SHA256, 32) : spec);
    }

    /**
     * Creates a builder for an RSA verification engine.
     *
     * <p>
     * If {@code spec} is {@code null}, PKCS#1 PSS with SHA-256 and a 32-byte salt
     * is used.
     * </p>
     *
     * @param publicKey public verification key; must not be {@code null}
     * @param spec      RSA signature specification; may be {@code null} to select
     *                  the default
     * @return a builder that produces RSA signature engines in VERIFY mode
     * @throws NullPointerException if {@code publicKey} is {@code null}
     */
    public static TagEngineBuilder<Signature> rsaVerify(final ZeroEchoSession session, final PublicKey publicKey,
            final RsaSigSpec spec) {
        Objects.requireNonNull(publicKey, PUBLIC_KEY);
        return signature(session, "RSA", publicKey, spec == null ? RsaSigSpec.pss(RsaSigSpec.Hash.SHA256, 32) : spec);
    }

    /**
     * Creates a builder for an ECDSA signing engine with the specified curve.
     *
     * <p>
     * If {@code spec} is {@code null}, {@link EcdsaCurveSpec#P256} is used.
     * </p>
     *
     * @param privateKey private signing key; must not be {@code null}
     * @param spec       curve specification; may be {@code null} to select the
     *                   default
     * @return a builder that produces ECDSA signature engines in SIGN mode
     * @throws NullPointerException if {@code privateKey} is {@code null}
     */
    public static TagEngineBuilder<Signature> ecdsaSign(final ZeroEchoSession session, final PrivateKey privateKey,
            final EcdsaCurveSpec spec) {
        Objects.requireNonNull(privateKey, PRIVATE_KEY);
        final EcdsaCurveSpec s = spec == null ? EcdsaCurveSpec.P256 : spec;
        return signature(session, "ECDSA", privateKey, s);
    }

    /**
     * Creates a builder for an ECDSA verification engine with the specified curve.
     *
     * <p>
     * If {@code spec} is {@code null}, {@link EcdsaCurveSpec#P256} is used.
     * </p>
     *
     * @param publicKey public verification key; must not be {@code null}
     * @param spec      curve specification; may be {@code null} to select the
     *                  default
     * @return a builder that produces ECDSA signature engines in VERIFY mode
     * @throws NullPointerException if {@code publicKey} is {@code null}
     */
    public static TagEngineBuilder<Signature> ecdsaVerify(final ZeroEchoSession session, final PublicKey publicKey,
            final EcdsaCurveSpec spec) {
        Objects.requireNonNull(publicKey, PUBLIC_KEY);
        final EcdsaCurveSpec s = spec == null ? EcdsaCurveSpec.P256 : spec;
        return signature(session, "ECDSA", publicKey, s);
    }

    /**
     * Creates a builder for an ECDSA P-256 signing engine.
     *
     * @param privateKey private signing key; must not be {@code null}
     * @return a builder that produces ECDSA signature engines in SIGN mode
     * @throws NullPointerException if {@code privateKey} is {@code null}
     */
    public static TagEngineBuilder<Signature> ecdsaP256Sign(final ZeroEchoSession session,
            final PrivateKey privateKey) {
        Objects.requireNonNull(privateKey, PRIVATE_KEY);
        return signature(session, "ECDSA", privateKey, EcdsaCurveSpec.P256);
    }

    /**
     * Creates a builder for an ECDSA P-256 verification engine.
     *
     * @param publicKey public verification key; must not be {@code null}
     * @return a builder that produces ECDSA signature engines in VERIFY mode
     * @throws NullPointerException if {@code publicKey} is {@code null}
     */
    public static TagEngineBuilder<Signature> ecdsaP256Verify(final ZeroEchoSession session,
            final PublicKey publicKey) {
        Objects.requireNonNull(publicKey, PUBLIC_KEY);
        return signature(session, "ECDSA", publicKey, EcdsaCurveSpec.P256);
    }

    /**
     * Creates a builder for a SPHINCS+ signing engine.
     *
     * <p>
     * Requires the BouncyCastle PQC provider and a registered "SPHINCS+" algorithm
     * in the supplied {@link ZeroEchoSession}.
     * </p>
     *
     * @param privateKey private signing key; must not be {@code null}
     * @return a builder that produces SPHINCS+ signature engines in SIGN mode
     * @throws NullPointerException if {@code privateKey} is {@code null}
     */
    public static TagEngineBuilder<Signature> sphincsPlusSign(final ZeroEchoSession session,
            final PrivateKey privateKey) {
        Objects.requireNonNull(privateKey, PRIVATE_KEY);
        return signature(session, "SPHINCS+", privateKey, VoidSpec.INSTANCE);
    }

    /**
     * Creates a builder for a SPHINCS+ verification engine.
     *
     * <p>
     * Requires the BouncyCastle PQC provider and a registered "SPHINCS+" algorithm
     * in the supplied {@link ZeroEchoSession}.
     * </p>
     *
     * @param publicKey public verification key; must not be {@code null}
     * @return a builder that produces SPHINCS+ signature engines in VERIFY mode
     * @throws NullPointerException if {@code publicKey} is {@code null}
     */
    public static TagEngineBuilder<Signature> sphincsPlusVerify(final ZeroEchoSession session,
            final PublicKey publicKey) {
        Objects.requireNonNull(publicKey, PUBLIC_KEY);
        return signature(session, "SPHINCS+", publicKey, VoidSpec.INSTANCE);
    }

    /**
     * Creates a builder for an SLH-DSA signing engine.
     *
     * <p>
     * SLH-DSA is the NIST-standardized hash-based signature scheme (FIPS 205). The
     * concrete parameter set is encoded in the key material and interpreted by the
     * algorithm resolved through the supplied {@link ZeroEchoSession}.
     * </p>
     *
     * @param privateKey private signing key; must not be {@code null}
     * @return a builder that produces SLH-DSA signature engines in SIGN mode
     * @throws NullPointerException if {@code privateKey} is {@code null}
     */
    public static TagEngineBuilder<Signature> slhDsaSign(final ZeroEchoSession session, final PrivateKey privateKey) {
        Objects.requireNonNull(privateKey, PRIVATE_KEY);
        return signature(session, "SLH-DSA", privateKey, VoidSpec.INSTANCE);
    }

    /**
     * Creates a builder for an SLH-DSA verification engine.
     *
     * <p>
     * SLH-DSA is the NIST-standardized hash-based signature scheme (FIPS 205). The
     * concrete parameter set is encoded in the key material and interpreted by the
     * algorithm resolved through the supplied {@link ZeroEchoSession}.
     * </p>
     *
     * @param publicKey public verification key; must not be {@code null}
     * @return a builder that produces SLH-DSA signature engines in VERIFY mode
     * @throws NullPointerException if {@code publicKey} is {@code null}
     */
    public static TagEngineBuilder<Signature> slhDsaVerify(final ZeroEchoSession session, final PublicKey publicKey) {
        Objects.requireNonNull(publicKey, PUBLIC_KEY);
        return signature(session, "SLH-DSA", publicKey, VoidSpec.INSTANCE);
    }

    /**
     * Creates a builder for an ML-DSA signing engine.
     *
     * <p>
     * ML-DSA is the NIST-standardized module-lattice signature scheme (FIPS 204).
     * The concrete parameter set and any pre-hash variant is encoded in the key
     * material and interpreted by the algorithm resolved through the supplied
     * {@link ZeroEchoSession}.
     * </p>
     *
     * @param privateKey private signing key; must not be {@code null}
     * @return a builder that produces ML-DSA signature engines in SIGN mode
     * @throws NullPointerException if {@code privateKey} is {@code null}
     */
    public static TagEngineBuilder<Signature> mldsaSign(final ZeroEchoSession session, final PrivateKey privateKey) {
        Objects.requireNonNull(privateKey, PRIVATE_KEY);
        return signature(session, "ML-DSA", privateKey, VoidSpec.INSTANCE);
    }

    /**
     * Creates a builder for an ML-DSA verification engine.
     *
     * <p>
     * ML-DSA is the NIST-standardized module-lattice signature scheme (FIPS 204).
     * The concrete parameter set and any pre-hash variant is encoded in the key
     * material and interpreted by the algorithm resolved through the supplied
     * {@link ZeroEchoSession}.
     * </p>
     *
     * @param publicKey public verification key; must not be {@code null}
     * @return a builder that produces ML-DSA signature engines in VERIFY mode
     * @throws NullPointerException if {@code publicKey} is {@code null}
     */
    public static TagEngineBuilder<Signature> mldsaVerify(final ZeroEchoSession session, final PublicKey publicKey) {
        Objects.requireNonNull(publicKey, PUBLIC_KEY);
        return signature(session, "ML-DSA", publicKey, VoidSpec.INSTANCE);
    }
}
