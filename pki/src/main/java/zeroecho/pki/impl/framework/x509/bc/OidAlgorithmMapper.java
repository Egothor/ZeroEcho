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

import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

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
 * <li>{@link #toZeroEchoAlgorithmId(AlgorithmIdentifier)} returns {@code null}
 * when the supplied identifier is {@code null}, when its embedded
 * {@link ASN1ObjectIdentifier} is {@code null}, when the OID string is blank,
 * or when the OID is not present in the mapping table.</li>
 * <li>{@link #toZeroEchoAlgorithmId(String)} requires a non-{@code null} OID
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
    @SuppressWarnings("PMD.AvoidUsingHardCodedIP")
    private static final Map<String, String> OID_TO_ZEROECHO_ALG = Map.ofEntries(
            // RSA PKCS#1 v1.5 digests
            Map.entry("1.2.840.113549.1.1.11", "SHA256withRSA"), // sha256WithRSAEncryption
            Map.entry("1.2.840.113549.1.1.12", "SHA384withRSA"), // sha384WithRSAEncryption
            Map.entry("1.2.840.113549.1.1.13", "SHA512withRSA"), // sha512WithRSAEncryption
            Map.entry("1.2.840.113549.1.1.5", "SHA1withRSA"), // sha1WithRSAEncryption

            // ECDSA digests
            Map.entry("1.2.840.10045.4.3.2", "SHA256withECDSA"), // ecdsa-with-SHA256
            Map.entry("1.2.840.10045.4.3.3", "SHA384withECDSA"), // ecdsa-with-SHA384
            Map.entry("1.2.840.10045.4.3.4", "SHA512withECDSA"), // ecdsa-with-SHA512
            Map.entry("1.2.840.10045.4.1", "SHA1withECDSA"), // ecdsa-with-SHA1

            // EdDSA
            Map.entry("1.3.101.112", "Ed25519"), // Ed25519
            Map.entry("1.3.101.113", "Ed448") // Ed448

    // PQC OIDs vary by provider/standard; extend as needed.
    );

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
     * This method extracts the underlying {@link ASN1ObjectIdentifier}, converts it
     * to its dotted-decimal string form, and performs a lookup in the immutable
     * mapping table.
     * </p>
     *
     * @param sigAlg ASN.1 signature algorithm identifier, possibly {@code null}
     * @return ZeroEcho canonical signature algorithm identifier, or {@code null}
     *         when the input is {@code null}, structurally incomplete, blank, or
     *         unsupported
     */
    public static String toZeroEchoAlgorithmId(AlgorithmIdentifier sigAlg) {
        if (sigAlg == null) {
            return null;
        }
        ASN1ObjectIdentifier oid = sigAlg.getAlgorithm();
        if (oid == null) {
            return null;
        }
        String id = oid.getId();
        if (id == null || id.isBlank()) {
            return null;
        }
        return OID_TO_ZEROECHO_ALG.get(id);
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
     * @return ZeroEcho canonical signature algorithm identifier, or {@code null}
     *         when the supplied OID string is blank or unsupported
     * @throws NullPointerException if {@code oid} is {@code null}
     */
    public static String toZeroEchoAlgorithmId(String oid) {
        Objects.requireNonNull(oid, "oid");
        if (oid.isBlank()) {
            return null;
        }
        return OID_TO_ZEROECHO_ALG.get(oid);
    }
}
