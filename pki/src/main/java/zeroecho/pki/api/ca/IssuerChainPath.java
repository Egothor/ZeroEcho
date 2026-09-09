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
package zeroecho.pki.api.ca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import zeroecho.pki.api.PkiId;

/**
 * Immutable explicitly ordered issuer chain from selected issuer certificate to
 * its trust-anchor certificate.
 *
 * @param pathId deterministic identity derived from {@code pathCommitment}
 * @param authorityId logical authority that owns the path
 * @param issuerId exact issuer generation at the path leaf
 * @param orderedCredentialIds nonempty leaf-to-anchor credential identities
 * @param pathCommitment lowercase SHA-256 commitment to authority, issuer, and order
 */
public record IssuerChainPath(PkiId pathId, PkiId authorityId, PkiId issuerId,
        List<PkiId> orderedCredentialIds, String pathCommitment) {
    /** Maximum supported certificates in one explicit PKI path. */
    public static final int MAX_CERTIFICATES = 32;

    /** Creates and validates an immutable chain path. */
    public IssuerChainPath {
        Objects.requireNonNull(pathId, "pathId");
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(issuerId, "issuerId");
        if (orderedCredentialIds == null || orderedCredentialIds.isEmpty()
                || orderedCredentialIds.size() > MAX_CERTIFICATES
                || orderedCredentialIds.stream().anyMatch(Objects::isNull)
                || orderedCredentialIds.size() != new HashSet<>(orderedCredentialIds).size()) {
            throw new IllegalArgumentException("orderedCredentialIds must be nonempty, unique, and non-null");
        }
        orderedCredentialIds = List.copyOf(orderedCredentialIds);
        String expected = commitmentFor(authorityId, issuerId, orderedCredentialIds);
        if (!expected.equals(pathCommitment)) {
            throw new IllegalArgumentException("pathCommitment does not match the ordered path");
        }
        if (!pathId.equals(idFor(expected))) {
            throw new IllegalArgumentException("pathId does not match the path commitment");
        }
    }

    /**
     * Creates a canonical path from its exact ordered credential identities.
     * @param authorityId logical authority that owns the path
     * @param issuerId exact issuer generation at the path leaf
     * @param credentials nonempty leaf-to-anchor credential identities
     * @return validated path with deterministic identity and commitment
     */
    public static IssuerChainPath create(PkiId authorityId, PkiId issuerId, List<PkiId> credentials) {
        String commitment = commitmentFor(authorityId, issuerId, credentials);
        return new IssuerChainPath(idFor(commitment), authorityId, issuerId, credentials, commitment);
    }

    /**
     * Returns the canonical path identity for a path commitment.
     * @param commitment lowercase 64-hex-character SHA-256 commitment
     * @return deterministic path identifier
     */
    public static PkiId idFor(String commitment) {
        if (commitment == null || !commitment.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("commitment must be lowercase SHA-256 hexadecimal");
        }
        return new PkiId("path:" + commitment.substring(0, 32));
    }

    /**
     * Returns the canonical commitment to authority, generation, and order.
     * @param authorityId logical authority identifier
     * @param issuerId exact issuer-generation identifier
     * @param credentials exact ordered credential identifiers
     * @return lowercase SHA-256 hexadecimal commitment
     */
    public static String commitmentFor(PkiId authorityId, PkiId issuerId, List<PkiId> credentials) {
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(issuerId, "issuerId");
        Objects.requireNonNull(credentials, "credentials");
        StringBuilder canonical = new StringBuilder(authorityId.value()).append('\n').append(issuerId.value());
        credentials.forEach(id -> canonical.append('\n').append(Objects.requireNonNull(id, "credential").value()));
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }
}
