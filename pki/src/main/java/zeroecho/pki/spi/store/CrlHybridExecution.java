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
package zeroecho.pki.spi.store;

import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.orch.SigningSubmissionId;

/**
 * Immutable version-1 internal link between one public alternative CRL signing
 * workflow and its single native-signature child. Terminal outcome belongs to
 * the parent domain continuation, not to this link. Values are thread-safe;
 * construction uses bounded identifier and digest space and never reads content.
 * No private key material, whole CRL, or duplicated signing-key reference is retained.
 *
 * @param version execution payload version, exactly 1
 * @param parentId canonical public signing operation identity
 * @param parentCommandCommitment immutable parent domain command commitment
 * @param issuerBindingCommitment captured complete issuer-generation binding digest
 * @param roleTupleCommitment captured two-role CRL presentation tuple digest
 * @param nativeChildId distinct canonical child identity in the parent's namespace and creation time
 * @param phase whether alternative signing is awaited or the native child is linked
 * @param revision exactly 0 before adoption and 1 after adoption
 * @param nativeAcceptanceCommitment exact accepted native-child commitment, present only after adoption
 * @param nativeTbs retained DER operation content for the native child, present only after adoption
 * @param alternativeSignatureSha256 digest of the actual retained alternative signature, present only after adoption
 */
public record CrlHybridExecution(int version, PkiId parentId, String parentCommandCommitment,
        String issuerBindingCommitment, String roleTupleCommitment, PkiId nativeChildId,
        SignWorkflowStore.CrlHybridPhase phase, long revision,
        Optional<SignWorkflowStore.AcceptanceCommitment> nativeAcceptanceCommitment,
        Optional<DurableContentReference> nativeTbs, Optional<String> alternativeSignatureSha256) {
    /**
     * Validates version, canonical coordinates, and the all-or-none adoption shape.
     * @throws NullPointerException if a required coordinate or optional container is null
     * @throws IllegalArgumentException if a coordinate or phase is inconsistent
     * @param version execution payload version, exactly 1
     * @param parentId canonical public signing operation identity
     * @param parentCommandCommitment immutable parent domain command commitment
     * @param issuerBindingCommitment captured complete issuer-generation binding digest
     * @param roleTupleCommitment captured two-role CRL presentation tuple digest
     * @param nativeChildId distinct canonical child identity in the parent's namespace and creation time
     * @param phase whether alternative signing is awaited or the native child is linked
     * @param revision exactly 0 before adoption and 1 after adoption
     * @param nativeAcceptanceCommitment exact accepted native-child commitment, present only after adoption
     * @param nativeTbs retained DER operation content for the native child, present only after adoption
     * @param alternativeSignatureSha256 digest of the actual retained alternative signature, present only
     * after adoption
     */
    public CrlHybridExecution {
        Objects.requireNonNull(phase, "phase");
        Objects.requireNonNull(nativeAcceptanceCommitment, "nativeAcceptanceCommitment");
        Objects.requireNonNull(nativeTbs, "nativeTbs");
        Objects.requireNonNull(alternativeSignatureSha256, "alternativeSignatureSha256");
        SigningSubmissionId parent = canonical(parentId);
        SigningSubmissionId child = canonical(nativeChildId);
        digest(issuerBindingCommitment); digest(roleTupleCommitment);
        if (version != 1 || parentId.equals(nativeChildId) || !parent.namespace().equals(child.namespace())
                || !parent.createdAt().equals(child.createdAt()) || parentCommandCommitment == null
                || !parentCommandCommitment.matches("domain:v1:[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Hybrid CRL execution coordinates are invalid");
        }
        boolean linked = phase == SignWorkflowStore.CrlHybridPhase.NATIVE_LINKED;
        if (revision != (linked ? 1 : 0) || nativeAcceptanceCommitment.isPresent() != linked
                || nativeTbs.isPresent() != linked || alternativeSignatureSha256.isPresent() != linked) {
            throw new IllegalArgumentException("Hybrid CRL adoption state is inconsistent");
        }
        nativeTbs.ifPresent(value -> {
            if (value.encoding() != Encoding.DER || value.length() == 0 || value.lifecycle() != DurableContentReference.Lifecycle.OPERATION) {
                throw new IllegalArgumentException("Hybrid CRL native input must be DER operation content");
            }
        });
        alternativeSignatureSha256.ifPresent(CrlHybridExecution::digest);
    }

    private static SigningSubmissionId canonical(PkiId id) {
        SigningSubmissionId parsed = SigningSubmissionId.parse(Objects.requireNonNull(id, "id"));
        String nonce = id.value().substring(id.value().lastIndexOf(':') + 1);
        String expected = "zsign:v1:" + parsed.namespace() + ":" + parsed.createdAt().toEpochMilli() + ":" + nonce;
        if (!nonce.matches("[0-9a-f]{32}") || !expected.equals(id.value())) {
            throw new IllegalArgumentException("Hybrid CRL signing identity is not canonical");
        }
        return parsed;
    }

    private static void digest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Hybrid CRL commitment must be lowercase SHA-256");
        }
    }
}
