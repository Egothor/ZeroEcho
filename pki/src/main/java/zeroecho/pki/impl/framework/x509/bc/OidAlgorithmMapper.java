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
package zeroecho.pki.impl.framework.x509.bc;

import java.util.Objects;

import zeroecho.pkix.AlgorithmIdentifier;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;

/**
 * Internal mapper from X.509 and PKCS#10 signature algorithm identifiers to
 * ZeroEcho canonical signature algorithm ids.
 *
 * <p>
 * This utility bridges algorithm identification as used in ASN.1 based X.509
 * structures to the canonical algorithm identifier strings expected by ZeroEcho
 * signing and verification components. It is primarily used when parsing or
 * verifying externally supplied X.509 artifacts such as PKCS#10 certification
 * requests, certificates, or related signed objects whose signature algorithm
 * is expressed by an object identifier.
 * </p>
 *
 * <p>
 * The mapping table is intentionally explicit and immutable. This makes the
 * supported algorithm surface audit-friendly, deterministic, and easy to extend
 * when additional interoperable signature algorithms are introduced.
 * </p>
 *
 * <h2>Scope</h2>
 * <p>
 * The current mapping covers selected RSA, ECDSA, and EdDSA signature algorithm
 * identifiers known to have a direct ZeroEcho canonical representation. OIDs
 * not present in the table are treated as unsupported by this mapper.
 * </p>
 *
 * <h2>Null and unsupported handling</h2>
 * <ul>
 * <li>{@link #toZeroEchoAlgorithmId(AlgorithmIdentifier, X509AuthoritySnapshot)}
 * returns {@code null}
 * when the supplied identifier is {@code null}, when its embedded
 * object identifier is {@code null}, when the OID string is blank,
 * or when the OID is not present in the mapping table.</li>
 * <li>{@link #toZeroEchoAlgorithmId(String, X509AuthoritySnapshot)} requires a
 * non-{@code null} OID
 * string but still returns {@code null} for blank or unsupported values.</li>
 * </ul>
 *
 * <h2>Architectural note</h2>
 * <p>
 * This class performs identifier mapping only. It does not validate whether the
 * mapped algorithm is actually usable with a given key, whether the runtime has
 * the necessary provider support, or whether PKI policy permits the algorithm.
 * Those concerns remain the responsibility of higher layers.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Returning a mapped ZeroEcho algorithm id does not imply that the
 * algorithm is acceptable for the current policy or assurance level.</li>
 * <li>Unmapped OIDs should be treated as unsupported rather than guessed or
 * heuristically rewritten.</li>
 * <li>The mapping table should be extended deliberately and reviewed carefully,
 * especially for evolving PQC algorithm identifiers.</li>
 * </ul>
 */
public final class OidAlgorithmMapper {
    private static final java.util.Set<String> ABSENT_SIGNATURE_OIDS = java.util.Set.of(
            StandardX509Bindings.OID_ECDSA_SHA256,
            StandardX509Bindings.OID_ECDSA_SHA384,
            StandardX509Bindings.OID_ECDSA_SHA512,
            StandardX509Bindings.OID_ED25519,
            StandardX509Bindings.OID_ED448,
            StandardX509Bindings.OID_ML_DSA_44,
            StandardX509Bindings.OID_ML_DSA_65,
            StandardX509Bindings.OID_ML_DSA_87,
            StandardX509Bindings.OID_SLH_DSA_SHA2_128S,
            StandardX509Bindings.OID_SLH_DSA_SHA2_128F,
            StandardX509Bindings.OID_SLH_DSA_SHA2_192S,
            StandardX509Bindings.OID_SLH_DSA_SHA2_192F,
            StandardX509Bindings.OID_SLH_DSA_SHA2_256S,
            StandardX509Bindings.OID_SLH_DSA_SHA2_256F,
            StandardX509Bindings.OID_SLH_DSA_SHAKE_128S,
            StandardX509Bindings.OID_SLH_DSA_SHAKE_128F,
            StandardX509Bindings.OID_SLH_DSA_SHAKE_192S,
            StandardX509Bindings.OID_SLH_DSA_SHAKE_192F,
            StandardX509Bindings.OID_SLH_DSA_SHAKE_256S,
            StandardX509Bindings.OID_SLH_DSA_SHAKE_256F);

    /**
     * Immutable mapping from signature algorithm OID string to the corresponding
     * ZeroEcho canonical signature algorithm identifier.
     *
     * <p>
     * The table is intentionally expressed as a constant map rather than as a
     * procedural chain of conditions so that supported OIDs remain explicit,
     * reviewable, and easy to maintain.
     * </p>
     */
    /**
     * Creates no instances.
     */
    private OidAlgorithmMapper() {
    }

    /**
     * Maps an ASN.1 signature {@link AlgorithmIdentifier} to a ZeroEcho canonical
     * signature algorithm identifier.
     *
     * <p>
     * This method extracts the underlying object identifier, converts it to its
     * dotted-decimal string form, and resolves it through the injected authority.
     * </p>
     *
     * @param sigAlg ASN.1 signature algorithm identifier, possibly {@code null}
     * @param authority immutable algorithm authority
     * @return ZeroEcho canonical signature algorithm identifier, or {@code null}
     *         when the input is {@code null}, structurally incomplete, blank, or
     *         unsupported
     */
    public static String toZeroEchoAlgorithmId(AlgorithmIdentifier sigAlg, X509AuthoritySnapshot authority) {
        if (sigAlg == null) {
            return null;
        }
        try {
            AlgorithmIdentity identity = new BcX509AlgorithmAdapter(
                    Objects.requireNonNull(authority, "authority").bindings())
                    .decode(sigAlg, X509AlgorithmRole.SIGNATURE_ALGORITHM);
            return identity.canonicalForm();
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    /**
     * Maps a dotted-decimal signature algorithm OID string to a ZeroEcho canonical
     * signature algorithm identifier.
     *
     * <p>
     * This method is useful when the caller already extracted the OID string and
     * wants the same mapping behavior without constructing an
     * {@link AlgorithmIdentifier} wrapper.
     * </p>
     *
     * @param oid dotted-decimal signature algorithm OID string; must not be
     *            {@code null}
     * @param authority immutable algorithm authority
     * @return ZeroEcho canonical signature algorithm identifier, or {@code null}
     *         when the supplied OID string is blank or unsupported
     * @throws NullPointerException if {@code oid} is {@code null}
     */
    public static String toZeroEchoAlgorithmId(String oid, X509AuthoritySnapshot authority) {
        Objects.requireNonNull(oid, "oid");
        X509AlgorithmIdentifier identifier = null;
        if (StandardX509Bindings.OID_RSA_SHA256.equals(oid)
                || StandardX509Bindings.OID_RSA_SHA384.equals(oid)
                || StandardX509Bindings.OID_RSA_SHA512.equals(oid)) {
            identifier = X509AlgorithmIdentifier.derNull(oid);
        } else if (ABSENT_SIGNATURE_OIDS.contains(oid)) {
            identifier = X509AlgorithmIdentifier.absent(oid);
        }
        if (identifier == null) {
            return null;
        }
        try {
            return Objects.requireNonNull(authority, "authority").bindings()
                    .reverse(identifier, X509AlgorithmRole.SIGNATURE_ALGORITHM)
                    .canonicalForm();
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }
}
