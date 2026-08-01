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

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmIdentityCatalog;
import zeroecho.core.spec.AlgorithmSuite;

/**
 * Immutable bootstrap identities required by current ZeroEcho PKI behavior.
 *
 * <p>
 * These identities are mandatory defaults, not a permanent maximum algorithm
 * set. Trusted installed extensions may add identities in other namespaces.
 * Provider aliases are accepted only by {@link #fromCompatibilityAlias(String)}
 * and never become canonical identity data.
 * </p>
 */
public final class BootstrapAlgorithmIdentities {

    private static final AlgorithmIdentity.Family SHA2_256 = family("sha2-256");
    private static final AlgorithmIdentity.Family SHA2_384 = family("sha2-384");
    private static final AlgorithmIdentity.Family SHA2_512 = family("sha2-512");
    private static final AlgorithmIdentity.Family MGF1_FAMILY = family("mgf1");
    private static final AlgorithmIdentity.Family RSA_PKCS1 = family("rsa-pkcs1-v1_5");
    private static final AlgorithmIdentity.Family RSA_PSS = family("rsa-pss");
    private static final AlgorithmIdentity.Family ECDSA = family("ecdsa");
    private static final AlgorithmIdentity.Family ED25519_FAMILY = family("ed25519");
    private static final AlgorithmIdentity.Family ED448_FAMILY = family("ed448");
    private static final AlgorithmIdentity.Family RSA_KEY = family("rsa");
    private static final AlgorithmIdentity.Family EC_KEY = family("ec");

    /** SHA-256 digest identity. */
    public static final AlgorithmIdentity SHA256 = identity(AlgorithmIdentity.Kind.DIGEST, SHA2_256,
            AlgorithmIdentity.NoParameters.INSTANCE);
    /** SHA-384 digest identity. */
    public static final AlgorithmIdentity SHA384 = identity(AlgorithmIdentity.Kind.DIGEST, SHA2_384,
            AlgorithmIdentity.NoParameters.INSTANCE);
    /** SHA-512 digest identity. */
    public static final AlgorithmIdentity SHA512 = identity(AlgorithmIdentity.Kind.DIGEST, SHA2_512,
            AlgorithmIdentity.NoParameters.INSTANCE);
    /** MGF1 mask-generation identity. */
    public static final AlgorithmIdentity MGF1 = identity(AlgorithmIdentity.Kind.MASK_GENERATION, MGF1_FAMILY,
            AlgorithmIdentity.NoParameters.INSTANCE);

    /** RSA PKCS#1 v1.5 with SHA-256. */
    public static final AlgorithmIdentity RSA_PKCS1_SHA256 = digestSignature(RSA_PKCS1, SHA256);
    /** RSA PKCS#1 v1.5 with SHA-384. */
    public static final AlgorithmIdentity RSA_PKCS1_SHA384 = digestSignature(RSA_PKCS1, SHA384);
    /** RSA PKCS#1 v1.5 with SHA-512. */
    public static final AlgorithmIdentity RSA_PKCS1_SHA512 = digestSignature(RSA_PKCS1, SHA512);
    /** RSA-PSS SHA-256/MGF1-SHA-256/salt-32/trailer-1 bootstrap identity. */
    public static final AlgorithmIdentity RSA_PSS_SHA256 = rsaPss(SHA256, SHA256, 32);
    /** ECDSA with SHA-256, independent of the EC curve. */
    public static final AlgorithmIdentity ECDSA_SHA256 = digestSignature(ECDSA, SHA256);
    /** ECDSA with SHA-384, independent of the EC curve. */
    public static final AlgorithmIdentity ECDSA_SHA384 = digestSignature(ECDSA, SHA384);
    /** ECDSA with SHA-512, independent of the EC curve. */
    public static final AlgorithmIdentity ECDSA_SHA512 = digestSignature(ECDSA, SHA512);
    /** Ed25519 signature identity. */
    public static final AlgorithmIdentity ED25519_SIGNATURE = identity(AlgorithmIdentity.Kind.SIGNATURE,
            ED25519_FAMILY, AlgorithmIdentity.NoParameters.INSTANCE);
    /** Ed448 signature identity. */
    public static final AlgorithmIdentity ED448_SIGNATURE = identity(AlgorithmIdentity.Kind.SIGNATURE, ED448_FAMILY,
            AlgorithmIdentity.NoParameters.INSTANCE);

    /** RSA public-key identity. */
    public static final AlgorithmIdentity RSA_PUBLIC_KEY = identity(AlgorithmIdentity.Kind.PUBLIC_KEY, RSA_KEY,
            AlgorithmIdentity.NoParameters.INSTANCE);
    /** EC P-256 public-key identity. */
    public static final AlgorithmIdentity EC_P256_PUBLIC_KEY = namedKey(EC_KEY, "p-256");
    /** EC P-384 public-key identity. */
    public static final AlgorithmIdentity EC_P384_PUBLIC_KEY = namedKey(EC_KEY, "p-384");
    /** EC P-521 public-key identity. */
    public static final AlgorithmIdentity EC_P521_PUBLIC_KEY = namedKey(EC_KEY, "p-521");
    /** Ed25519 public-key identity. */
    public static final AlgorithmIdentity ED25519_PUBLIC_KEY = identity(AlgorithmIdentity.Kind.PUBLIC_KEY,
            ED25519_FAMILY, AlgorithmIdentity.NoParameters.INSTANCE);
    /** Ed448 public-key identity. */
    public static final AlgorithmIdentity ED448_PUBLIC_KEY = identity(AlgorithmIdentity.Kind.PUBLIC_KEY, ED448_FAMILY,
            AlgorithmIdentity.NoParameters.INSTANCE);

    /** Current ECDSA P-256 signing suite. */
    public static final AlgorithmSuite ECDSA_SHA256_P256 = new AlgorithmSuite(ECDSA_SHA256, EC_P256_PUBLIC_KEY);
    /** Current ECDSA P-384 signing suite. */
    public static final AlgorithmSuite ECDSA_SHA384_P384 = new AlgorithmSuite(ECDSA_SHA384, EC_P384_PUBLIC_KEY);
    /** Current ECDSA P-521 signing suite. */
    public static final AlgorithmSuite ECDSA_SHA512_P521 = new AlgorithmSuite(ECDSA_SHA512, EC_P521_PUBLIC_KEY);
    /** Current immutable PKI signing default. */
    public static final AlgorithmSuite PKI_SIGNATURE_DEFAULT_V1 = new AlgorithmSuite(RSA_PKCS1_SHA256, RSA_PUBLIC_KEY);

    private static final List<AlgorithmIdentity> IDENTITIES = List.of(SHA256, SHA384, SHA512, MGF1, RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512,
            ED25519_SIGNATURE, ED448_SIGNATURE, RSA_PUBLIC_KEY, EC_P256_PUBLIC_KEY, EC_P384_PUBLIC_KEY,
            EC_P521_PUBLIC_KEY, ED25519_PUBLIC_KEY, ED448_PUBLIC_KEY);

    private static final AlgorithmIdentityCatalog CATALOG = AlgorithmIdentityCatalog.builtIn(IDENTITIES);

    private static final Map<String, AlgorithmIdentity> ALIASES = Map.ofEntries(
            Map.entry("SHA256withRSA", RSA_PKCS1_SHA256),
            Map.entry("SHA384withRSA", RSA_PKCS1_SHA384),
            Map.entry("SHA512withRSA", RSA_PKCS1_SHA512),
            Map.entry("SHA256withRSAandMGF1", RSA_PSS_SHA256),
            Map.entry("SHA256withECDSA", ECDSA_SHA256),
            Map.entry("SHA384withECDSA", ECDSA_SHA384),
            Map.entry("SHA512withECDSA", ECDSA_SHA512),
            Map.entry("Ed25519", ED25519_SIGNATURE),
            Map.entry("Ed448", ED448_SIGNATURE));

    private BootstrapAlgorithmIdentities() {
    }

    /**
     * Returns the immutable bootstrap identity catalog.
     *
     * @return built-in catalog
     */
    public static AlgorithmIdentityCatalog catalog() {
        return CATALOG;
    }

    /**
     * Creates an exact RSA-PSS identity without requiring a central enum entry.
     *
     * @param hash       message digest
     * @param mgfHash    MGF1 digest
     * @param saltLength salt length in bytes
     * @return exact RSA-PSS identity
     * @throws IllegalArgumentException if the tuple is contradictory
     */
    public static AlgorithmIdentity rsaPss(AlgorithmIdentity hash, AlgorithmIdentity mgfHash, int saltLength) {
        return identity(AlgorithmIdentity.Kind.SIGNATURE, RSA_PSS,
                new AlgorithmIdentity.RsaPssParameters(hash, MGF1, mgfHash, saltLength, 1));
    }

    /**
     * Resolves a finite legacy provider alias at the compatibility boundary.
     *
     * <p>
     * SHA-1 and unknown aliases are rejected. The returned identity, rather than
     * the alias, is authoritative.
     * </p>
     *
     * @param alias legacy provider spelling
     * @return exact bootstrap identity, or empty when unknown or forbidden
     */
    public static Optional<AlgorithmIdentity> fromCompatibilityAlias(String alias) {
        Objects.requireNonNull(alias, "alias");
        return Optional.ofNullable(ALIASES.get(alias));
    }

    /**
     * Returns the immutable finite built-in compatibility aliases.
     *
     * @return alias-to-exact-identity map
     */
    public static Map<String, AlgorithmIdentity> compatibilityAliases() {
        return ALIASES;
    }

    /**
     * Resolves either a canonical identity or an approved compatibility alias.
     *
     * @param value canonical identity or finite legacy alias
     * @return exact identity, or empty when unsupported
     */
    public static Optional<AlgorithmIdentity> resolve(String value) {
        Objects.requireNonNull(value, "value");
        Optional<AlgorithmIdentity> canonical = CATALOG.resolve(value);
        return canonical.isPresent() ? canonical : fromCompatibilityAlias(value);
    }

    private static AlgorithmIdentity digestSignature(AlgorithmIdentity.Family family, AlgorithmIdentity digest) {
        return identity(AlgorithmIdentity.Kind.SIGNATURE, family, new AlgorithmIdentity.DigestParameters(digest));
    }

    private static AlgorithmIdentity namedKey(AlgorithmIdentity.Family family, String name) {
        return identity(AlgorithmIdentity.Kind.PUBLIC_KEY, family,
                new AlgorithmIdentity.NamedParameters(new AlgorithmIdentity.Family("zeroecho", name)));
    }

    private static AlgorithmIdentity identity(AlgorithmIdentity.Kind kind, AlgorithmIdentity.Family family,
            AlgorithmIdentity.Parameters parameters) {
        return new AlgorithmIdentity(kind, family, parameters);
    }

    private static AlgorithmIdentity.Family family(String name) {
        return new AlgorithmIdentity.Family("zeroecho", name);
    }
}
