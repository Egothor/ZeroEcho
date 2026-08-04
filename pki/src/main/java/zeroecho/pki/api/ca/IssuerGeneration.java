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
import java.util.HexFormat;
import java.util.Objects;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;

/** Immutable authority record for one concrete CA issuer generation. */
public record IssuerGeneration(PkiId issuerId, PkiId authorityId, PkiId credentialId, KeyRef signingKeyRef,
        IssuerGenerationState state, String profilePolicyCommitment, String x509BindingCommitment) {

    /** Creates a validated issuer generation. */
    public IssuerGeneration {
        Objects.requireNonNull(issuerId, "issuerId");
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(credentialId, "credentialId");
        Objects.requireNonNull(signingKeyRef, "signingKeyRef");
        Objects.requireNonNull(state, "state");
        requireCommitment(profilePolicyCommitment, "profilePolicyCommitment");
        requireCommitment(x509BindingCommitment, "x509BindingCommitment");
        if (!issuerId.equals(idFor(authorityId, credentialId))) {
            throw new IllegalArgumentException("issuerId does not match the authority and credential");
        }
    }

    /** Returns the canonical identity for an authority credential generation. */
    public static PkiId idFor(PkiId authorityId, PkiId credentialId) {
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(credentialId, "credentialId");
        return new PkiId("issuer:" + sha256(authorityId.value() + "\n" + credentialId.value()).substring(0, 32));
    }

    private static void requireCommitment(String value, String field) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256 hexadecimal");
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }
}
