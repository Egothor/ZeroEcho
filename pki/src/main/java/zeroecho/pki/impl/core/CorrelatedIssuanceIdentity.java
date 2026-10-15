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

package zeroecho.pki.impl.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

import zeroecho.pki.api.Validity;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.profile.CertificateProfileRef;

/**
 * Pure identity derivation shared by issuance lookup and domain preparation.
 * This internal immutable value grants no authority and owns no runtime resource.
 *
 * @param correlationId namespaced key depending only on authority and external issuance ID
 * @param effectiveCommitment SHA-256 commitment to exact issuance semantics
 */
public record CorrelatedIssuanceIdentity(String correlationId, String effectiveCommitment) {
    /**
     * Hashes length-framed fields without constructing an aggregate command.
     * CSR parsing, signature verification and mutable store selection are excluded.
     * Local time is O(C + F) for CSR bytes C and frozen field bytes F. Hash state
     * is constant; defensive CSR and individual UTF-8 field snapshots use O(C + F)
     * transient memory under the public input bounds.
     *
     * @param correlated immutable bounded request
     * @return deterministic key and exact effective commitment
     * @throws NullPointerException if the request is null
     */
    public static CorrelatedIssuanceIdentity derive(CorrelatedEndEntityIssuanceRequest correlated) {
        Objects.requireNonNull(correlated, "correlated");
        EndEntityIssuanceRequest request = correlated.request();
        IssuanceIntent intent = correlated.intent();
        MessageDigest commitment = sha256();
        field(commitment, request.payload().kind() == zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10
                ? "zeroecho:pki:issuance-effective-command:v1" : "zeroecho:pki:issuance-effective-command:crmf:v1");
        field(commitment, intent.issuanceId());
        field(commitment, request.issuerCaId().value());
        field(commitment, intent.commandCommitment());
        CertificateProfileRef profile = intent.expectedProfile();
        field(commitment, profile.profileId());
        field(commitment, Long.toString(profile.profileVersion()));
        field(commitment, profile.canonicalSha256());
        field(commitment, intent.expectedIssuerId().value());
        field(commitment, intent.expectedChainPathId().value());
        field(commitment, intent.expectedChainPathCommitment());
        field(commitment, sha256().digest(request.payload().der()));
        field(commitment, request.validityOverride().isPresent() ? "present" : "absent");
        if (request.validityOverride().isPresent()) {
            Validity validity = request.validityOverride().orElseThrow();
            field(commitment, validity.notBefore().toString());
            field(commitment, validity.notAfter().toString());
        }
        return new CorrelatedIssuanceIdentity(correlationId(request.issuerCaId(), intent.issuanceId()),
                HexFormat.of().formatHex(commitment.digest()));
    }

    /**
     * Derives the existing correlation key from validated authority and external identity.
     * Uses the same domain separation and length-framed UTF-8 bytes as request derivation.
     * No CSR, store lookup or authorization is involved; work is linear in bounded text.
     * @param authorityId validated issuing authority from a request or retained binding
     * @param issuanceId validated stable external issuance identity
     * @return canonical namespaced SHA-256 correlation key
     * @throws NullPointerException if either coordinate is null
     */
    public static String correlationId(PkiId authorityId, String issuanceId) {
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(issuanceId, "issuanceId");
        MessageDigest key = sha256();
        field(key, "zeroecho:pki:issuance-correlation:v1");
        field(key, authorityId.value());
        field(key, issuanceId);
        return "issuance." + HexFormat.of().formatHex(key.digest());
    }

    /**
     * Derives a domain-separated renewal identity without store reads. Work and
     * transient memory are linear in the bounded frozen fields and optional original request.
     * @param renewal immutable predecessor binding and frozen selection
     * @return deterministic correlation key and exact renewal commitment
     * @throws NullPointerException if the request is null
     */
    public static CorrelatedIssuanceIdentity derive(CorrelatedEndEntityRenewalRequest renewal) {
        Objects.requireNonNull(renewal, "renewal");
        IssuanceIntent intent = renewal.intent();
        MessageDigest commitment = sha256();
        field(commitment, renewal.originalRequest().isPresent() ? "zeroecho:pki:renewal-original-command:v1" : "zeroecho:pki:renewal-effective-command:v1");
        field(commitment, intent.issuanceId());
        field(commitment, renewal.issuerCaId().value());
        field(commitment, intent.commandCommitment());
        field(commitment, intent.expectedProfile().profileId());
        field(commitment, Long.toString(intent.expectedProfile().profileVersion()));
        field(commitment, intent.expectedProfile().canonicalSha256());
        field(commitment, intent.expectedIssuerId().value());
        field(commitment, intent.expectedChainPathId().value());
        field(commitment, intent.expectedChainPathCommitment());
        field(commitment, renewal.request().existingCredentialId().value());
        field(commitment, renewal.predecessorSha256());
        field(commitment, renewal.request().validityOverride().isPresent() ? "present" : "absent");
        renewal.request().validityOverride().ifPresent(validity -> {
            field(commitment, validity.notBefore().toString());
            field(commitment, validity.notAfter().toString());
        });
        renewal.originalRequest().ifPresent(payload -> {
            field(commitment, payload.kind().name());
            field(commitment, payload.der());
        });
        return new CorrelatedIssuanceIdentity(correlationId(renewal.issuerCaId(), intent.issuanceId()),
                HexFormat.of().formatHex(commitment.digest()));
    }

    /**
     * Derives an exact replacement commitment without store reads or authorization.
     * Time and transient memory are linear in bounded input fields and request DER.
     * @param replacement exact predecessor, request and frozen selection
     * @return stable correlation key and domain-separated replacement commitment
     * @throws NullPointerException if the input is null
     */
    public static CorrelatedIssuanceIdentity derive(CorrelatedEndEntityReplacementRequest replacement) {
        Objects.requireNonNull(replacement, "replacement");
        IssuanceIntent intent = replacement.intent();
        MessageDigest commitment = sha256();
        field(commitment, "zeroecho:pki:replacement-effective-command:v1");
        field(commitment, intent.issuanceId());
        field(commitment, replacement.issuerCaId().value());
        field(commitment, intent.commandCommitment());
        field(commitment, intent.expectedProfile().profileId());
        field(commitment, Long.toString(intent.expectedProfile().profileVersion()));
        field(commitment, intent.expectedProfile().canonicalSha256());
        field(commitment, intent.expectedIssuerId().value());
        field(commitment, intent.expectedChainPathId().value());
        field(commitment, intent.expectedChainPathCommitment());
        field(commitment, replacement.request().existingCredentialId().value());
        field(commitment, replacement.predecessorSha256());
        field(commitment, replacement.request().payload().kind().name());
        field(commitment, replacement.request().payload().der());
        return new CorrelatedIssuanceIdentity(correlationId(replacement.issuerCaId(), intent.issuanceId()),
                HexFormat.of().formatHex(commitment.digest()));
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static void field(MessageDigest digest, String value) {
        field(digest, value.getBytes(StandardCharsets.UTF_8));
    }

    private static void field(MessageDigest digest, byte[] value) {
        digest.update((byte) (value.length >>> 24));
        digest.update((byte) (value.length >>> 16));
        digest.update((byte) (value.length >>> 8));
        digest.update((byte) value.length);
        digest.update(value);
    }
}
