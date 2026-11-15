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
package zeroecho.pki.api.ca;

import java.util.Objects;
import java.nio.charset.StandardCharsets;
import zeroecho.pki.api.PkiId;

/** Immutable completed root candidate; receipt existence alone determines activation.
 * @param version record version, one
 * @param transitionId deterministic originating-operation identity
 * @param caId logical root authority
 * @param expectedHead admitted original head fence
 * @param oldCredentialId retained original certificate
 * @param oldCertificateSha256 exact original certificate SHA-256
 * @param oldBindingCommitment exact original binding SHA-256
 * @param candidateIssuerId completed candidate generation
 * @param candidatePathId completed candidate path
 * @param candidateCredentialId completed candidate certificate
 * @param candidateCertificateSha256 exact candidate certificate SHA-256
 * @param candidateBindingCommitment exact candidate binding SHA-256
 * @param originatingSigningOperationId accepted signing operation
 * @param commandCommitment original immutable domain command commitment */
public record RootTrustAnchorTransition(int version, PkiId transitionId, PkiId caId, CaHeadSnapshot expectedHead,
        PkiId oldCredentialId, String oldCertificateSha256, String oldBindingCommitment,
        PkiId candidateIssuerId, PkiId candidatePathId, PkiId candidateCredentialId,
        String candidateCertificateSha256, String candidateBindingCommitment,
        PkiId originatingSigningOperationId, String commandCommitment) {
    /** Creates a complete immutable candidate without selecting it. */
    public RootTrustAnchorTransition {
        Objects.requireNonNull(transitionId, "transitionId"); Objects.requireNonNull(caId, "caId");
        Objects.requireNonNull(expectedHead, "expectedHead"); Objects.requireNonNull(oldCredentialId, "oldCredentialId");
        Objects.requireNonNull(candidateIssuerId, "candidateIssuerId"); Objects.requireNonNull(candidatePathId, "candidatePathId");
        Objects.requireNonNull(candidateCredentialId, "candidateCredentialId"); Objects.requireNonNull(originatingSigningOperationId, "originatingSigningOperationId");
        if (version != 1 || !caId.equals(expectedHead.caId()) || !transitionId.equals(idFor(originatingSigningOperationId))
                || !IssuerGeneration.idFor(caId, oldCredentialId).equals(expectedHead.issuerId())
                || !Objects.equals(oldBindingCommitment, expectedHead.bindingCommitment())
                || !candidateIssuerId.equals(IssuerGeneration.idFor(caId, candidateCredentialId))
                || commandCommitment == null || !commandCommitment.matches("domain:v1:[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Invalid root trust-anchor transition");
        }
        digest(oldCertificateSha256); digest(oldBindingCommitment); digest(candidateCertificateSha256); digest(candidateBindingCommitment);
    }
    /** @param operation originating signing operation @return deterministic transition identity */
    public static PkiId idFor(PkiId operation) {
        Objects.requireNonNull(operation, "operation");
        return new PkiId("root-transition:" + sha256(("zeroecho-root-transition-id-v1\0" + operation.value()).getBytes(StandardCharsets.UTF_8)));
    }
    /** @return domain-separated canonical SHA-256 of immutable old and completed candidate evidence */
    public String commitment() {
        try {
            var bytes = new java.io.ByteArrayOutputStream();
            try (var out = new java.io.DataOutputStream(bytes)) {
                for (String field : new String[] {"zeroecho-root-transition-v1", Integer.toString(version), transitionId.value(), caId.value(),
                        Integer.toString(expectedHead.version()), expectedHead.caId().value(), Long.toString(expectedHead.epoch()),
                        expectedHead.issuerId().value(), expectedHead.pathId().value(), expectedHead.bindingCommitment(), oldCredentialId.value(),
                        oldCertificateSha256, oldBindingCommitment, candidateIssuerId.value(), candidatePathId.value(), candidateCredentialId.value(),
                        candidateCertificateSha256, candidateBindingCommitment, originatingSigningOperationId.value(), commandCommitment}) {
                    byte[] encoded = field.getBytes(StandardCharsets.UTF_8);
                    if (encoded.length > 1_048_576) { throw new IllegalArgumentException("Transition coordinate exceeds its bound"); }
                    out.writeInt(encoded.length); out.write(encoded);
                }
            }
            return sha256(bytes.toByteArray());
        } catch (java.io.IOException impossible) { throw new IllegalStateException(impossible); }
    }
    private static void digest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) { throw new IllegalArgumentException("Invalid transition digest"); }
    }
    private static String sha256(byte[] value) {
        try { return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
