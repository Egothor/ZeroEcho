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
package zeroecho.pki.impl.framework.x509;

import java.util.Optional;
import java.util.List;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;

/**
 * Immutable trusted-code rule between exact ZeroEcho identities and X.509
 * representations.
 *
 * <p>
 * A rule may own one exact binding or a typed non-ambiguous parameter domain,
 * such as RSA-PSS parameters or EC named curves. It is not administrative
 * configuration and cannot override an existing catalog rule.
 * </p>
 */
public interface X509BindingRule {

    /**
     * Returns the finite safe descriptors owned by this encoding rule.
     *
     * <p>A parameterized rule may expose one descriptor for every currently
     * registered exact identity. Descriptors do not expose implementation
     * classes or mutable codec state.</p>
     *
     * @return immutable descriptors
     */
    default List<X509AlgorithmBinding> bindings() {
        return List.of();
    }

    /**
     * Signature byte representation owned by a signature rule.
     */
    enum SignatureEncoding {
        /** Algorithm-defined opaque signature bytes. */
        OPAQUE,
        /** ASN.1 DER {@code SEQUENCE { r, s }}. */
        ECDSA_DER,
        /** Not applicable to a public-key-only rule. */
        NOT_APPLICABLE
    }

    /**
     * Subject-public-key bit-string representation.
     */
    enum PublicKeyEncoding {
        /** Algorithm-defined PKCS#1 RSA public-key structure. */
        RSA_PKCS1_DER,
        /** SEC1 encoded elliptic-curve point. */
        EC_POINT,
        /** Algorithm-defined raw public-key bytes. */
        RAW,
        /** Canonical native SubjectPublicKeyInfo DER nested in the BIT STRING. */
        NESTED_SPKI_DER,
        /** Not applicable to a signature-only rule. */
        NOT_APPLICABLE
    }

    /**
     * Returns the stable namespaced rule identifier.
     *
     * @return immutable rule identifier
     */
    String id();

    /**
     * Returns the closed X.509 role.
     *
     * @return role owned by this rule
     */
    X509AlgorithmRole role();

    /**
     * Returns the OID domain owned by this rule.
     *
     * @return dotted-decimal OID
     */
    String oid();

    /**
     * Returns an immutable semantic fingerprint used for conflict diagnostics.
     *
     * @return provider-independent rule fingerprint
     */
    String semanticFingerprint();

    /**
     * Returns the exact signature-byte encoding rule.
     *
     * @return signature encoding or {@link SignatureEncoding#NOT_APPLICABLE}
     */
    SignatureEncoding signatureEncoding();

    /**
     * Returns the exact subject-public-key encoding rule.
     *
     * @return key encoding or {@link PublicKeyEncoding#NOT_APPLICABLE}
     */
    PublicKeyEncoding publicKeyEncoding();

    /**
     * Resolves an exact identity to its canonical X.509 representation.
     *
     * @param identity exact provider-independent identity
     * @return canonical representation, or empty outside this rule's domain
     */
    Optional<X509AlgorithmIdentifier> encode(AlgorithmIdentity identity);

    /**
     * Reverse-resolves an exact X.509 representation.
     *
     * @param identifier canonical structural representation
     * @return exact role-specific identity, or empty outside this rule's domain
     * @throws IllegalArgumentException when the OID is owned by this rule but its
     *                                  parameters are malformed or forbidden
     */
    Optional<AlgorithmIdentity> decode(X509AlgorithmIdentifier identifier);
}
