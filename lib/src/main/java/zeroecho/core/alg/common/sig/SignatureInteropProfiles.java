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
package zeroecho.core.alg.common.sig;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.alg.ecdsa.EcdsaCurveSpec;
import zeroecho.core.alg.rsa.RsaSigSpec;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.VoidSpec;

/**
 * Resolves standard signature algorithm identifiers to explicit ZeroEcho
 * signature profiles.
 *
 * <p>
 * This helper centralizes the translation from canonical external signature
 * names such as {@code SHA256withRSA} into a pair of ZeroEcho coordinates:
 * </p>
 * <ul>
 * <li>the key algorithm used for key import and algorithm matching, and</li>
 * <li>the signature context algorithm plus a mandatory explicit
 * specification.</li>
 * </ul>
 *
 * <p>
 * The class exists to avoid accidental reliance on algorithm default specs.
 * Such defaults are often reasonable for native ZeroEcho usage, but they are
 * not sufficient for standards interoperability because names like
 * {@code SHA256withRSA} encode semantics that include digest selection,
 * padding, and sometimes signature-byte representation.
 * </p>
 *
 * <h2>Scope</h2>
 * <p>
 * The current mapping covers classic interoperable signature names that are
 * commonly encountered in X.509 and PKCS#10 workflows:
 * </p>
 * <ul>
 * <li>RSA PKCS#1 v1.5 with SHA-256/384/512</li>
 * <li>ECDSA with SHA-256/384/512</li>
 * <li>Ed25519 and Ed448</li>
 * </ul>
 *
 * <p>
 * Algorithms not known to this helper are intentionally returned as
 * {@link Optional#empty()}, allowing callers to preserve current
 * ZeroEcho-native behavior for PQC, hybrid, or application-specific
 * identifiers.
 * </p>
 */
public final class SignatureInteropProfiles {

    private static final Map<String, SignatureInteropProfile> PROFILES = Map.ofEntries(
            Map.entry("SHA256withRSA", new SignatureInteropProfile("SHA256withRSA", "RSA", "RSA", // NOPMD
                    RsaSigSpec.pkcs1v15(RsaSigSpec.Hash.SHA256),
                    SignatureInteropProfile.SignatureRepresentation.IDENTITY, 0)),
            Map.entry("SHA384withRSA",
                    new SignatureInteropProfile("SHA384withRSA", "RSA", "RSA",
                            RsaSigSpec.pkcs1v15(RsaSigSpec.Hash.SHA384),
                            SignatureInteropProfile.SignatureRepresentation.IDENTITY, 0)),
            Map.entry("SHA512withRSA",
                    new SignatureInteropProfile("SHA512withRSA", "RSA", "RSA",
                            RsaSigSpec.pkcs1v15(RsaSigSpec.Hash.SHA512),
                            SignatureInteropProfile.SignatureRepresentation.IDENTITY, 0)),
            Map.entry("SHA256withRSAandMGF1",
                    new SignatureInteropProfile("SHA256withRSAandMGF1", "RSA", "RSA",
                            RsaSigSpec.pss(RsaSigSpec.Hash.SHA256, 32),
                            SignatureInteropProfile.SignatureRepresentation.IDENTITY, 0)),
            Map.entry("SHA256withECDSA", new SignatureInteropProfile("SHA256withECDSA", "ECDSA", "ECDSA", // NOPMD
                    EcdsaCurveSpec.P256,
                    SignatureInteropProfile.SignatureRepresentation.ECDSA_DER_EXTERNAL_P1363_INTERNAL,
                    EcdsaCurveSpec.P256.signFixedLength())),
            Map.entry("SHA384withECDSA",
                    new SignatureInteropProfile("SHA384withECDSA", "ECDSA", "ECDSA", EcdsaCurveSpec.P384,
                            SignatureInteropProfile.SignatureRepresentation.ECDSA_DER_EXTERNAL_P1363_INTERNAL,
                            EcdsaCurveSpec.P384.signFixedLength())),
            Map.entry("SHA512withECDSA",
                    new SignatureInteropProfile("SHA512withECDSA", "ECDSA", "ECDSA", EcdsaCurveSpec.P512,
                            SignatureInteropProfile.SignatureRepresentation.ECDSA_DER_EXTERNAL_P1363_INTERNAL,
                            EcdsaCurveSpec.P512.signFixedLength())),
            Map.entry("Ed25519",
                    new SignatureInteropProfile("Ed25519", "Ed25519", "Ed25519", VoidSpec.INSTANCE,
                            SignatureInteropProfile.SignatureRepresentation.IDENTITY, 0)),
            Map.entry("Ed448", new SignatureInteropProfile("Ed448", "Ed448", "Ed448", VoidSpec.INSTANCE,
                    SignatureInteropProfile.SignatureRepresentation.IDENTITY, 0)));

    private static final Map<String, SignatureInteropProfile> CANONICAL_PROFILES = Map.ofEntries(
            canonical(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, "SHA256withRSA"),
            canonical(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384, "SHA384withRSA"),
            canonical(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA512, "SHA512withRSA"),
            canonical(BootstrapAlgorithmIdentities.RSA_PSS_SHA256, "SHA256withRSAandMGF1"),
            canonical(BootstrapAlgorithmIdentities.ECDSA_SHA256, "SHA256withECDSA"),
            canonical(BootstrapAlgorithmIdentities.ECDSA_SHA384, "SHA384withECDSA"),
            canonical(BootstrapAlgorithmIdentities.ECDSA_SHA512, "SHA512withECDSA"),
            canonical(BootstrapAlgorithmIdentities.ED25519_SIGNATURE, "Ed25519"),
            canonical(BootstrapAlgorithmIdentities.ED448_SIGNATURE, "Ed448"));

    private SignatureInteropProfiles() {
    }

    /**
     * Resolves an external signature algorithm identifier.
     *
     * @param algorithmId canonical signature algorithm identifier
     * @return a profile when the algorithm has standard interop semantics known to
     *         ZeroEcho; otherwise {@link Optional#empty()}
     */
    public static Optional<SignatureInteropProfile> resolve(String algorithmId) {
        Objects.requireNonNull(algorithmId, "algorithmId");
        if (algorithmId.isBlank()) {
            return Optional.empty();
        }
        SignatureInteropProfile profile = CANONICAL_PROFILES.get(algorithmId);
        return Optional.ofNullable(profile == null ? PROFILES.get(algorithmId) : profile);
    }

    /**
     * Returns the set of canonical interop algorithm identifiers known to this
     * helper.
     *
     * @return immutable set of supported standard signature names
     */
    public static Set<String> algorithmIds() {
        Set<String> identifiers = new java.util.LinkedHashSet<>(PROFILES.keySet());
        identifiers.addAll(CANONICAL_PROFILES.keySet());
        return Set.copyOf(identifiers);
    }

    /**
     * Returns the key algorithm identifier associated with a signature algorithm.
     *
     * <p>
     * If the signature algorithm is unknown to this helper, the original value is
     * returned unchanged. This makes the method safe for callers that want a best
     * effort key-algorithm normalization without losing PQC or application-specific
     * identifiers.
     * </p>
     *
     * @param algorithmId signature algorithm identifier
     * @return the matching key algorithm id, or the original value when no standard
     *         mapping exists
     */
    public static String keyAlgorithmIdOrSelf(String algorithmId) {
        Objects.requireNonNull(algorithmId, "algorithmId");
        Optional<SignatureInteropProfile> profile = resolve(algorithmId);
        if (profile.isPresent()) {
            return profile.get().keyAlgorithmId();
        }
        return algorithmId;
    }

    private static Map.Entry<String, SignatureInteropProfile> canonical(AlgorithmIdentity identity, String alias) {
        return Map.entry(identity.canonicalForm(), PROFILES.get(alias));
    }
}
