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
package zeroecho.pki.impl.framework.x509;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;

/**
 * Immutable authoritative standard X.509 bootstrap bindings.
 *
 * <p>
 * Standard OIDs and parameter semantics are code-owned and cannot be overridden
 * by configuration or extension ordering. RSA-PSS and EC SubjectPublicKeyInfo
 * are represented by typed parameterized rules.
 * </p>
 */
public final class StandardX509Bindings {

    /** RSA PKCS#1 SHA-256 signature OID. */
    public static final String OID_RSA_SHA256 = "1.2.840.113549.1.1.11";
    /** RSA PKCS#1 SHA-384 signature OID. */
    public static final String OID_RSA_SHA384 = "1.2.840.113549.1.1.12";
    /** RSA PKCS#1 SHA-512 signature OID. */
    public static final String OID_RSA_SHA512 = "1.2.840.113549.1.1.13";
    /** RSA-PSS signature OID. */
    public static final String OID_RSA_PSS = "1.2.840.113549.1.1.10";
    /** ECDSA SHA-256 signature OID. */
    public static final String OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
    /** ECDSA SHA-384 signature OID. */
    public static final String OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";
    /** ECDSA SHA-512 signature OID. */
    public static final String OID_ECDSA_SHA512 = "1.2.840.10045.4.3.4";
    /** Ed25519 OID. */
    public static final String OID_ED25519 = String.join(".", "1", "3", "101", "112");
    /** Ed448 OID. */
    public static final String OID_ED448 = String.join(".", "1", "3", "101", "113");
    /** RSA public-key OID. */
    public static final String OID_RSA_PUBLIC_KEY = "1.2.840.113549.1.1.1";
    /** EC public-key OID. */
    public static final String OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
    /** P-256 named-curve OID. */
    public static final String OID_P256 = "1.2.840.10045.3.1.7";
    /** P-384 named-curve OID. */
    public static final String OID_P384 = "1.3.132.0.34";
    /** P-521 named-curve OID. */
    public static final String OID_P521 = "1.3.132.0.35";
    /** ML-DSA-44 OID (FIPS 204). */
    public static final String OID_ML_DSA_44 = "2.16.840.1.101.3.4.3.17";
    /** ML-DSA-65 OID (FIPS 204). */
    public static final String OID_ML_DSA_65 = "2.16.840.1.101.3.4.3.18";
    /** ML-DSA-87 OID (FIPS 204). */
    public static final String OID_ML_DSA_87 = "2.16.840.1.101.3.4.3.19";
    /** SLH-DSA-SHA2-128s OID (FIPS 205). */
    public static final String OID_SLH_DSA_SHA2_128S = "2.16.840.1.101.3.4.3.20";
    /** SLH-DSA-SHA2-128f OID (FIPS 205). */
    public static final String OID_SLH_DSA_SHA2_128F = "2.16.840.1.101.3.4.3.21";
    /** SLH-DSA-SHA2-192s OID (FIPS 205). */
    public static final String OID_SLH_DSA_SHA2_192S = "2.16.840.1.101.3.4.3.22";
    /** SLH-DSA-SHA2-192f OID (FIPS 205). */
    public static final String OID_SLH_DSA_SHA2_192F = "2.16.840.1.101.3.4.3.23";
    /** SLH-DSA-SHA2-256s OID (FIPS 205). */
    public static final String OID_SLH_DSA_SHA2_256S = "2.16.840.1.101.3.4.3.24";
    /** SLH-DSA-SHA2-256f OID (FIPS 205). */
    public static final String OID_SLH_DSA_SHA2_256F = "2.16.840.1.101.3.4.3.25";
    /** SLH-DSA-SHAKE-128s OID (FIPS 205). */
    public static final String OID_SLH_DSA_SHAKE_128S = "2.16.840.1.101.3.4.3.26";
    /** SLH-DSA-SHAKE-128f OID (FIPS 205). */
    public static final String OID_SLH_DSA_SHAKE_128F = "2.16.840.1.101.3.4.3.27";
    /** SLH-DSA-SHAKE-192s OID (FIPS 205). */
    public static final String OID_SLH_DSA_SHAKE_192S = "2.16.840.1.101.3.4.3.28";
    /** SLH-DSA-SHAKE-192f OID (FIPS 205). */
    public static final String OID_SLH_DSA_SHAKE_192F = "2.16.840.1.101.3.4.3.29";
    /** SLH-DSA-SHAKE-256s OID (FIPS 205). */
    public static final String OID_SLH_DSA_SHAKE_256S = "2.16.840.1.101.3.4.3.30";
    /** SLH-DSA-SHAKE-256f OID (FIPS 205). */
    public static final String OID_SLH_DSA_SHAKE_256F = "2.16.840.1.101.3.4.3.31";
    private static final X509BindingCatalog CATALOG = createCatalog(X509ComponentCatalog.builtIn());
    private static final List<X509AlgorithmBinding> DESCRIPTORS = CATALOG.rules().stream()
            .flatMap(rule -> rule.bindings().stream())
            .sorted(java.util.Comparator.comparing(X509AlgorithmBinding::bindingId)).toList();

    private StandardX509Bindings() {
    }

    private static X509BindingCatalog createCatalog(X509ComponentCatalog components) {
        Objects.requireNonNull(components, "components");
        return X509BindingCatalog.builtIn(List.of(
            fixed("zeroecho.signature.rsa-pkcs1-sha256", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, X509AlgorithmIdentifier.derNull(OID_RSA_SHA256),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.rsa-pkcs1-sha384", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384, X509AlgorithmIdentifier.derNull(OID_RSA_SHA384),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.rsa-pkcs1-sha512", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA512, X509AlgorithmIdentifier.derNull(OID_RSA_SHA512),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            new RsaPssRule(components),
            fixed("zeroecho.signature.ecdsa-sha256", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.ECDSA_SHA256, X509AlgorithmIdentifier.absent(OID_ECDSA_SHA256),
                    X509BindingRule.SignatureEncoding.ECDSA_DER,
                    X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.ecdsa-sha384", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.ECDSA_SHA384, X509AlgorithmIdentifier.absent(OID_ECDSA_SHA384),
                    X509BindingRule.SignatureEncoding.ECDSA_DER,
                    X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.ecdsa-sha512", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.ECDSA_SHA512, X509AlgorithmIdentifier.absent(OID_ECDSA_SHA512),
                    X509BindingRule.SignatureEncoding.ECDSA_DER,
                    X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.ed25519", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.ED25519_SIGNATURE, X509AlgorithmIdentifier.absent(OID_ED25519),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.ed448", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.ED448_SIGNATURE, X509AlgorithmIdentifier.absent(OID_ED448),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.spki.rsa", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY, X509AlgorithmIdentifier.derNull(OID_RSA_PUBLIC_KEY),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RSA_PKCS1_DER),
            new EcPublicKeyRule(components),
            fixed("zeroecho.spki.ed25519", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.ED25519_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_ED25519),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.spki.ed448", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.ED448_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_ED448),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.signature.ml-dsa-44", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.ML_DSA_44_SIGNATURE, X509AlgorithmIdentifier.absent(OID_ML_DSA_44),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.ml-dsa-65", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.ML_DSA_65_SIGNATURE, X509AlgorithmIdentifier.absent(OID_ML_DSA_65),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.ml-dsa-87", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE, X509AlgorithmIdentifier.absent(OID_ML_DSA_87),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.spki.ml-dsa-44", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.ML_DSA_44_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_ML_DSA_44),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.spki.ml-dsa-65", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.ML_DSA_65_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_ML_DSA_65),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.spki.ml-dsa-87", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.ML_DSA_87_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_ML_DSA_87),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.signature.slh-dsa-sha2-128s", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHA2_128S_SIGNATURE, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHA2_128S),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.slh-dsa-sha2-128f", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHA2_128F_SIGNATURE, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHA2_128F),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.slh-dsa-sha2-192s", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHA2_192S_SIGNATURE, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHA2_192S),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.slh-dsa-sha2-192f", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHA2_192F_SIGNATURE, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHA2_192F),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.slh-dsa-sha2-256s", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHA2_256S_SIGNATURE, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHA2_256S),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.slh-dsa-sha2-256f", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHA2_256F_SIGNATURE, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHA2_256F),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.slh-dsa-shake-128s", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_128S_SIGNATURE, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHAKE_128S),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.slh-dsa-shake-128f", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_128F_SIGNATURE, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHAKE_128F),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.slh-dsa-shake-192s", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_192S_SIGNATURE, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHAKE_192S),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.slh-dsa-shake-192f", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_192F_SIGNATURE, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHAKE_192F),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.slh-dsa-shake-256s", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_256S_SIGNATURE, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHAKE_256S),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.signature.slh-dsa-shake-256f", X509AlgorithmRole.SIGNATURE_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_256F_SIGNATURE, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHAKE_256F),
                    X509BindingRule.SignatureEncoding.OPAQUE, X509BindingRule.PublicKeyEncoding.NOT_APPLICABLE),
            fixed("zeroecho.spki.slh-dsa-sha2-128s", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHA2_128S_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHA2_128S),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.spki.slh-dsa-sha2-128f", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHA2_128F_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHA2_128F),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.spki.slh-dsa-sha2-192s", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHA2_192S_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHA2_192S),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.spki.slh-dsa-sha2-192f", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHA2_192F_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHA2_192F),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.spki.slh-dsa-sha2-256s", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHA2_256S_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHA2_256S),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.spki.slh-dsa-sha2-256f", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHA2_256F_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHA2_256F),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.spki.slh-dsa-shake-128s", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_128S_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHAKE_128S),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.spki.slh-dsa-shake-128f", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_128F_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHAKE_128F),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.spki.slh-dsa-shake-192s", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_192S_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHAKE_192S),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.spki.slh-dsa-shake-192f", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_192F_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHAKE_192F),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.spki.slh-dsa-shake-256s", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_256S_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHAKE_256S),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW),
            fixed("zeroecho.spki.slh-dsa-shake-256f", X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM,
                    BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_256F_PUBLIC_KEY, X509AlgorithmIdentifier.absent(OID_SLH_DSA_SHAKE_256F),
                    X509BindingRule.SignatureEncoding.NOT_APPLICABLE, X509BindingRule.PublicKeyEncoding.RAW)));
    }

    /**
     * Returns the immutable built-in standard catalog.
     *
     * @return authoritative binding snapshot
     */
    public static X509BindingCatalog catalog() {
        return CATALOG;
    }

    /**
     * Creates the built-in rules against an immutable component authority.
     *
     * @param components exact component catalog used by parameterized rules
     * @return immutable built-in binding catalog
     */
    public static X509BindingCatalog catalog(X509ComponentCatalog components) {
        return createCatalog(components);
    }

    /**
     * Returns deterministic safe descriptors for every sealed standard binding.
     *
     * @return immutable standard binding descriptors
     */
    public static List<X509AlgorithmBinding> descriptors() {
        return DESCRIPTORS;
    }

    // Only this closed implementation proves a complete, exact identity domain.
    /* default */ static Optional<AlgorithmIdentity> fixedIdentity(X509BindingRule rule) {
        return rule instanceof FixedRule fixed ? Optional.of(fixed.identity()) : Optional.empty();
    }

    private static X509BindingRule fixed(String id, X509AlgorithmRole role, AlgorithmIdentity identity,
            X509AlgorithmIdentifier identifier, X509BindingRule.SignatureEncoding signatureEncoding,
            X509BindingRule.PublicKeyEncoding publicKeyEncoding) {
        return new FixedRule(id, role, identity, identifier, signatureEncoding, publicKeyEncoding);
    }

    private record FixedRule(String id, X509AlgorithmRole role, AlgorithmIdentity identity,
            X509AlgorithmIdentifier identifier, SignatureEncoding signatureEncoding,
            PublicKeyEncoding publicKeyEncoding) implements X509BindingRule {

        private FixedRule {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(role, "role");
            Objects.requireNonNull(identity, "identity");
            Objects.requireNonNull(identifier, "identifier");
            Objects.requireNonNull(signatureEncoding, "signatureEncoding");
            Objects.requireNonNull(publicKeyEncoding, "publicKeyEncoding");
        }

        @Override
        public String oid() {
            return identifier.oid();
        }

        @Override
        public String semanticFingerprint() {
            return id + "|" + role + "|" + identity.canonicalForm() + "|" + identifier.canonicalForm() + "|"
                    + signatureEncoding + "|" + publicKeyEncoding;
        }

        @Override
        public List<X509AlgorithmBinding> bindings() {
            return descriptors(id, role, identity, identifier, signatureEncoding, publicKeyEncoding,
                    semanticFingerprint());
        }

        @Override
        public Optional<X509AlgorithmIdentifier> encode(AlgorithmIdentity candidate) {
            return identity.equals(candidate) ? Optional.of(identifier) : Optional.empty();
        }

        @Override
        public Optional<AlgorithmIdentity> decode(X509AlgorithmIdentifier candidate) {
            if (!identifier.oid().equals(candidate.oid())) {
                return Optional.empty();
            }
            if (!identifier.equals(candidate)) {
                throw new IllegalArgumentException("Non-canonical X.509 algorithm parameters");
            }
            return Optional.of(identity);
        }
    }

    /** Parameterized authority for RSA-PSS signature identifiers. */
    private static final class RsaPssRule implements X509BindingRule {

        private final X509ComponentCatalog components;

        private RsaPssRule(X509ComponentCatalog components) {
            this.components = components;
        }

        @Override
        public String id() {
            return "zeroecho.signature.rsa-pss";
        }

        @Override
        public X509AlgorithmRole role() {
            return X509AlgorithmRole.SIGNATURE_ALGORITHM;
        }

        @Override
        public String oid() {
            return OID_RSA_PSS;
        }

        @Override
        public String semanticFingerprint() {
            return "rsa-pss-v1|sha2-256,sha2-384,sha2-512|mgf1|salt-nonnegative|trailer-1|canonical-explicit";
        }

        @Override
        public SignatureEncoding signatureEncoding() {
            return SignatureEncoding.OPAQUE;
        }

        @Override
        public PublicKeyEncoding publicKeyEncoding() {
            return PublicKeyEncoding.NOT_APPLICABLE;
        }

        @Override
        public List<X509AlgorithmBinding> bindings() {
            X509AlgorithmIdentifier identifier = encode(BootstrapAlgorithmIdentities.RSA_PSS_SHA256).orElseThrow();
            return descriptors(id(), role(), BootstrapAlgorithmIdentities.RSA_PSS_SHA256, identifier,
                    signatureEncoding(), publicKeyEncoding(), semanticFingerprint());
        }

        @Override
        public Optional<X509AlgorithmIdentifier> encode(AlgorithmIdentity identity) {
            if (identity.kind() != AlgorithmIdentity.Kind.SIGNATURE
                    || !"zeroecho/rsa-pss".equals(identity.family().canonicalForm())) {
                return Optional.empty();
            }
            if (!(identity.parameters() instanceof AlgorithmIdentity.RsaPssParameters parameters)) {
                throw new IllegalArgumentException("RSA-PSS identity has invalid typed parameters");
            }
            byte[] der = encodePss(parameters, components);
            return Optional.of(X509AlgorithmIdentifier.exact(OID_RSA_PSS, der));
        }

        @Override
        public Optional<AlgorithmIdentity> decode(X509AlgorithmIdentifier identifier) {
            if (!OID_RSA_PSS.equals(identifier.oid())) {
                return Optional.empty();
            }
            if (identifier.parameterForm() != X509AlgorithmIdentifier.ParameterForm.EXACT_DER) {
                throw new IllegalArgumentException("RSA-PSS parameters must be explicit");
            }
            AlgorithmIdentity.RsaPssParameters parameters = decodePss(identifier.parameters(), components);
            return Optional.of(BootstrapAlgorithmIdentities.rsaPss(parameters.hash(), parameters.maskHash(),
                    parameters.saltLength()));
        }
    }

    /** Parameterized authority for named-curve EC public-key identifiers. */
    private static final class EcPublicKeyRule implements X509BindingRule {

        private final X509ComponentCatalog components;

        private EcPublicKeyRule(X509ComponentCatalog components) {
            this.components = components;
        }

        @Override
        public String id() {
            return "zeroecho.spki.ec-named-curve";
        }

        @Override
        public X509AlgorithmRole role() {
            return X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM;
        }

        @Override
        public String oid() {
            return OID_EC_PUBLIC_KEY;
        }

        @Override
        public String semanticFingerprint() {
            return "ec-spki-v1|named-only|p-256,p-384,p-521|sec1-point";
        }

        @Override
        public SignatureEncoding signatureEncoding() {
            return SignatureEncoding.NOT_APPLICABLE;
        }

        @Override
        public PublicKeyEncoding publicKeyEncoding() {
            return PublicKeyEncoding.EC_POINT;
        }

        @Override
        public List<X509AlgorithmBinding> bindings() {
            return List.of(BootstrapAlgorithmIdentities.EC_P256_PUBLIC_KEY,
                    BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY,
                    BootstrapAlgorithmIdentities.EC_P521_PUBLIC_KEY).stream()
                    .flatMap(identity -> descriptors(id() + "." + identity.parameters().canonicalForm(), role(),
                            identity, encode(identity).orElseThrow(), signatureEncoding(), publicKeyEncoding(),
                            semanticFingerprint()).stream()).toList();
        }

        @Override
        public Optional<X509AlgorithmIdentifier> encode(AlgorithmIdentity identity) {
            if (identity.kind() != AlgorithmIdentity.Kind.PUBLIC_KEY
                    || !"zeroecho/ec".equals(identity.family().canonicalForm())) {
                return Optional.empty();
            }
            String curveOid = components.oid(X509ComponentCatalog.Kind.NAMED_CURVE, identity);
            return Optional.of(X509AlgorithmIdentifier.exact(OID_EC_PUBLIC_KEY, StrictDer.oid(curveOid)));
        }

        @Override
        public Optional<AlgorithmIdentity> decode(X509AlgorithmIdentifier identifier) {
            if (!OID_EC_PUBLIC_KEY.equals(identifier.oid())) {
                return Optional.empty();
            }
            if (identifier.parameterForm() != X509AlgorithmIdentifier.ParameterForm.EXACT_DER) {
                throw new IllegalArgumentException("EC SubjectPublicKeyInfo requires named-curve parameters");
            }
            String curve = StrictDer.decodeOid(identifier.parameters());
            return Optional.of(components.identity(X509ComponentCatalog.Kind.NAMED_CURVE, curve));
        }
    }

    private static byte[] encodePss(AlgorithmIdentity.RsaPssParameters parameters,
            X509ComponentCatalog components) {
        String hashOid = requireDigestOid(parameters.hash(), components);
        String maskHashOid = requireDigestOid(parameters.maskHash(), components);
        if (!BootstrapAlgorithmIdentities.MGF1.equals(parameters.mask())) {
            throw new IllegalArgumentException("RSA-PSS requires MGF1");
        }
        byte[] hashAlgorithm = StrictDer.sequence(StrictDer.oid(hashOid), StrictDer.nullValue());
        byte[] maskHashAlgorithm = StrictDer.sequence(StrictDer.oid(maskHashOid), StrictDer.nullValue());
        byte[] maskAlgorithm = StrictDer.sequence(
                StrictDer.oid(components.oid(X509ComponentCatalog.Kind.MASK_GENERATION, parameters.mask())),
                maskHashAlgorithm);
        return StrictDer.sequence(StrictDer.explicit(0, hashAlgorithm), StrictDer.explicit(1, maskAlgorithm),
                StrictDer.explicit(2, StrictDer.integer(parameters.saltLength())));
    }

    private static List<X509AlgorithmBinding> descriptors(String id, X509AlgorithmRole role,
            AlgorithmIdentity identity, X509AlgorithmIdentifier identifier, X509BindingRule.SignatureEncoding signature,
            X509BindingRule.PublicKeyEncoding publicKey, String commitment) {
        X509AlgorithmBinding.ParameterRule parameters = switch (identifier.parameterForm()) {
            case ABSENT -> X509AlgorithmBinding.ParameterRule.ABSENT;
            case DER_NULL -> X509AlgorithmBinding.ParameterRule.DER_NULL;
            case EXACT_DER -> X509AlgorithmBinding.ParameterRule.STRUCTURED_DER;
        };
        X509AlgorithmBinding.PublicKeyEncoding keyEncoding = switch (publicKey) {
            case RSA_PKCS1_DER -> X509AlgorithmBinding.PublicKeyEncoding.RSA_PKCS1_DER;
            case EC_POINT -> X509AlgorithmBinding.PublicKeyEncoding.EC_POINT;
            case RAW -> X509AlgorithmBinding.PublicKeyEncoding.RAW;
            case NESTED_SPKI_DER -> X509AlgorithmBinding.PublicKeyEncoding.NESTED_SPKI_DER;
            case NOT_APPLICABLE -> X509AlgorithmBinding.PublicKeyEncoding.NOT_APPLICABLE;
        };
        X509AlgorithmBinding.SignatureEncoding signatureEncoding = switch (signature) {
            case OPAQUE -> X509AlgorithmBinding.SignatureEncoding.OPAQUE;
            case ECDSA_DER -> X509AlgorithmBinding.SignatureEncoding.ECDSA_DER;
            case NOT_APPLICABLE -> X509AlgorithmBinding.SignatureEncoding.NOT_APPLICABLE;
        };
        if (role == X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM) {
            return List.of(new X509AlgorithmBinding(id, identity, X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY,
                    identifier.oid(), X509AlgorithmBinding.Origin.STANDARD, 1, parameters, keyEncoding,
                    signatureEncoding, X509AlgorithmBinding.Interoperability.STANDARD_INTEROPERABLE,
                    Optional.empty(), commitment));
        }
        return List.of(X509AlgorithmBinding.Role.CSR_SIGNATURE, X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE,
                X509AlgorithmBinding.Role.CRL_SIGNATURE, X509AlgorithmBinding.Role.OCSP_REQUEST_SIGNATURE).stream()
                .map(bindingRole -> new X509AlgorithmBinding(id + "."
                        + bindingRole.name().toLowerCase(java.util.Locale.ROOT), identity,
                        bindingRole, identifier.oid(), X509AlgorithmBinding.Origin.STANDARD, 1, parameters, keyEncoding,
                        signatureEncoding, X509AlgorithmBinding.Interoperability.STANDARD_INTEROPERABLE,
                        Optional.empty(), commitment))
                .toList();
    }

    private static AlgorithmIdentity.RsaPssParameters decodePss(byte[] encoded, X509ComponentCatalog components) {
        StrictDer.Reader sequence = StrictDer.reader(encoded).readConstructed(0x30);
        byte[] hashAlgorithm = sequence.readConstructed(0xa0).readOnlyValue(0x30);
        byte[] maskAlgorithm = sequence.readConstructed(0xa1).readOnlyValue(0x30);
        int saltLength = sequence.readConstructed(0xa2).readOnlyInteger();
        if (sequence.hasRemaining()) {
            throw new IllegalArgumentException("RSA-PSS DEFAULT trailer must be omitted");
        }
        sequence.requireEnd();

        AlgorithmIdentity hash = decodeDigestAlgorithm(hashAlgorithm, components);
        StrictDer.Reader mask = StrictDer.readerContent(maskAlgorithm);
        String maskOid = mask.readOid();
        if (!BootstrapAlgorithmIdentities.MGF1.equals(
                components.identity(X509ComponentCatalog.Kind.MASK_GENERATION, maskOid))) {
            throw new IllegalArgumentException("RSA-PSS mask algorithm must be MGF1");
        }
        byte[] maskHashAlgorithm = mask.readOnlyValue(0x30);
        mask.requireEnd();
        AlgorithmIdentity maskHash = decodeDigestAlgorithm(maskHashAlgorithm, components);

        AlgorithmIdentity.RsaPssParameters parameters = new AlgorithmIdentity.RsaPssParameters(hash,
                BootstrapAlgorithmIdentities.MGF1, maskHash, saltLength, 1);
        if (!Arrays.equals(encoded, encodePss(parameters, components))) {
            throw new IllegalArgumentException("RSA-PSS parameters are not canonical");
        }
        return parameters;
    }

    private static AlgorithmIdentity decodeDigestAlgorithm(byte[] content, X509ComponentCatalog components) {
        StrictDer.Reader reader = StrictDer.readerContent(content);
        String oid = reader.readOid();
        reader.readNull();
        reader.requireEnd();
        return components.identity(X509ComponentCatalog.Kind.DIGEST, oid);
    }

    private static String requireDigestOid(AlgorithmIdentity digest, X509ComponentCatalog components) {
        return components.oid(X509ComponentCatalog.Kind.DIGEST, digest);
    }

    /**
     * Minimal strict DER support for the fixed standard parameter structures.
     */
    private enum StrictDer {
        ;

        private static final int MINIMUM_OID_COMPONENTS = 2;
        private static final int SHORT_LENGTH_BOUND = 128;

        private static byte[] sequence(byte[]... values) {
            return tagged(0x30, concatenate(values));
        }

        private static byte[] explicit(int tag, byte[] value) {
            return tagged(0xa0 + tag, value);
        }

        private static byte[] nullValue() {
            return new byte[] { 0x05, 0x00 };
        }

        private static byte[] integer(int value) {
            if (value < 0) {
                throw new IllegalArgumentException("DER integer must not be negative");
            }
            return tagged(0x02, BigInteger.valueOf(value).toByteArray());
        }

        private static byte[] oid(String dotted) {
            String[] components = dotted.split("\\.");
            if (components.length < MINIMUM_OID_COMPONENTS) {
                throw new IllegalArgumentException("Invalid OID");
            }
            int first = Integer.parseInt(components[0]);
            int second = Integer.parseInt(components[1]);
            ByteArrayOutputStream content = new ByteArrayOutputStream();
            writeBase128(content, 40L * first + second);
            for (int index = 2; index < components.length; index++) {
                writeBase128(content, Long.parseLong(components[index]));
            }
            return tagged(0x06, content.toByteArray());
        }

        private static String decodeOid(byte[] der) {
            Reader reader = reader(der);
            String oid = reader.readOid();
            reader.requireEnd();
            if (!Arrays.equals(der, oid(oid))) {
                throw new IllegalArgumentException("OID is not canonical DER");
            }
            return oid;
        }

        private static byte[] tagged(int tag, byte[] content) {
            ByteArrayOutputStream output = new ByteArrayOutputStream(content.length + 6);
            output.write(tag);
            writeLength(output, content.length);
            output.writeBytes(content);
            return output.toByteArray();
        }

        private static byte[] concatenate(byte[][] values) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            for (byte[] value : values) {
                output.writeBytes(value);
            }
            return output.toByteArray();
        }

        private static void writeLength(ByteArrayOutputStream output, int length) {
            if (length < SHORT_LENGTH_BOUND) {
                output.write(length);
                return;
            }
            int octets = 0;
            int current = length;
            while (current != 0) {
                octets++;
                current >>>= 8;
            }
            output.write(0x80 | octets);
            for (int shift = (octets - 1) * 8; shift >= 0; shift -= 8) {
                output.write(length >>> shift);
            }
        }

        private static void writeBase128(ByteArrayOutputStream output, long value) {
            if (value < 0) {
                throw new IllegalArgumentException("OID component must not be negative");
            }
            int groups = 1;
            long current = value;
            while ((current >>>= 7) != 0) {
                groups++;
            }
            for (int group = groups - 1; group >= 0; group--) {
                int octet = (int) ((value >>> (group * 7)) & 0x7f);
                output.write(group == 0 ? octet : octet | 0x80);
            }
        }

        private static Reader reader(byte[] encoded) {
            return new Reader(encoded.clone(), 0, encoded.length);
        }

        private static Reader readerContent(byte[] content) {
            return new Reader(content.clone(), 0, content.length);
        }

        /** Bounded cursor over one independently owned DER byte sequence. */
        private static final class Reader {

            private final byte[] data;
            private final int end;
            private int offset;

            private Reader(byte[] data, int offset, int end) {
                this.data = data;
                this.offset = offset;
                this.end = end;
            }

            private Reader readConstructed(int expectedTag) {
                byte[] value = readValue(expectedTag);
                return new Reader(value, 0, value.length);
            }

            private byte[] readOnlyValue(int expectedTag) {
                byte[] value = readValue(expectedTag);
                requireEnd();
                return value;
            }

            private int readOnlyInteger() {
                byte[] value = readValue(0x02);
                requireEnd();
                if (value.length == 0 || value.length > 5 || (value[0] & 0x80) != 0) {
                    throw new IllegalArgumentException("Invalid non-negative DER integer");
                }
                BigInteger integer = new BigInteger(value);
                if (!Arrays.equals(value, integer.toByteArray()) || integer.bitLength() > 31) {
                    throw new IllegalArgumentException("Non-canonical or excessive DER integer");
                }
                return integer.intValue();
            }

            private String readOid() {
                byte[] value = readValue(0x06);
                if (value.length == 0) {
                    throw new IllegalArgumentException("Empty DER OID");
                }
                StringBuilder dotted = new StringBuilder();
                long component = 0;
                boolean first = true;
                boolean continued = false;
                for (byte octetValue : value) {
                    if (component > (Long.MAX_VALUE >>> 7)) {
                        throw new IllegalArgumentException("DER OID component overflow");
                    }
                    int octet = octetValue & 0xff;
                    component = (component << 7) | (octet & 0x7f);
                    continued = (octet & 0x80) != 0;
                    if (!continued) {
                        if (first) {
                            int firstArc = component < 40 ? 0 : component < 80 ? 1 : 2;
                            dotted.append(firstArc).append('.').append(component - 40L * firstArc);
                            first = false;
                        } else {
                            dotted.append('.').append(component);
                        }
                        component = 0;
                    }
                }
                if (continued || first) {
                    throw new IllegalArgumentException("Truncated DER OID");
                }
                return dotted.toString();
            }

            private void readNull() {
                if (readValue(0x05).length != 0) {
                    throw new IllegalArgumentException("Invalid DER NULL");
                }
            }

            private byte[] readValue(int expectedTag) {
                if (offset >= end || (data[offset++] & 0xff) != expectedTag) {
                    throw new IllegalArgumentException("Unexpected DER tag");
                }
                int length = readLength();
                if (length > end - offset) {
                    throw new IllegalArgumentException("Truncated DER value");
                }
                byte[] value = Arrays.copyOfRange(data, offset, offset + length);
                offset += length;
                return value;
            }

            private int readLength() {
                if (offset >= end) {
                    throw new IllegalArgumentException("Truncated DER length");
                }
                int first = data[offset++] & 0xff;
                if (first < SHORT_LENGTH_BOUND) {
                    return first;
                }
                int octets = first & 0x7f;
                if (octets == 0 || octets > 4 || octets > end - offset) {
                    throw new IllegalArgumentException("Invalid DER length");
                }
                int length = 0;
                for (int index = 0; index < octets; index++) {
                    if (length > (Integer.MAX_VALUE >>> 8)) {
                        throw new IllegalArgumentException("DER length overflow");
                    }
                    length = (length << 8) | (data[offset++] & 0xff);
                }
                if (length < SHORT_LENGTH_BOUND) {
                    throw new IllegalArgumentException("Non-canonical DER length");
                }
                return length;
            }

            private void requireEnd() {
                if (offset != end) {
                    throw new IllegalArgumentException("Trailing DER data");
                }
            }

            private boolean hasRemaining() {
                return offset != end;
            }
        }
    }
}
