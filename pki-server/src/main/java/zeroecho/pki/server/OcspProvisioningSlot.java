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
package zeroecho.pki.server;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.issuance.ManagedOcspProvisioningIdentity;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;

/**
 * Retained uniqueness claim for one trusted-realm managed responder public-key tuple.
 *
 * @param realmId trusted server realm owning the claim
 * @param serverSlotId realm-bound SHA-256 slot identity
 * @param coreSlotId domain SHA-256 identity of the issuer and responder-key tuple
 * @param authorityId issuing authority identity
 * @param issuerId exact issuing credential identity
 * @param primarySpkiSha256 primary responder public-key SHA-256
 * @param alternativeSpkiSha256 distinct alternative responder public-key SHA-256
 * @param revision positive provisioning revision
 * @param state retained claim lifecycle state
 * @param canonicalRequestId deterministic administrative request identity for this revision
 * @param targetCommitment exact normalized provisioning target commitment
 * @param receipt accepted signing receipt, if any
 * @param credentialId issued X.509 credential identity, present only after completion
 * @param certificateSha256 issued certificate SHA-256, present only after completion
 * @param predecessorCredentialId predecessor credential for explicit renewal, absent for revision one
 */
record OcspProvisioningSlot(RealmId realmId, String serverSlotId, String coreSlotId,
        PkiId authorityId, PkiId issuerId, String primarySpkiSha256, String alternativeSpkiSha256,
        long revision, State state, String canonicalRequestId, String targetCommitment,
        Optional<SigningAcceptanceReceipt> receipt, Optional<PkiId> credentialId,
        Optional<String> certificateSha256, Optional<PkiId> predecessorCredentialId) {
    /**
     * Administrative operation identity permitted to own responder-provisioning claims.
     */
    static final String OPERATION = "ocsp.responder.issue-certificate";
    /**
     * Durable provisioning claim lifecycle.
     */
    enum State {
        /**
         * The canonical target is claimed without an accepted signing receipt.
         */
        CLAIMED,
        /**
         * The claim is bound to an accepted signing receipt.
         */
        ACCEPTED,
        /**
         * The claim retains the successfully issued certificate identity.
         */
        COMPLETED,
        /**
         * The administrative workflow terminated without a successful certificate result.
         */
        FAILED
    }

    /**
     * Validates canonical slot coordinates and state-dependent receipt/result invariants.
     *
     * @param realmId trusted server realm owning the claim
     * @param serverSlotId realm-bound SHA-256 slot identity
     * @param coreSlotId domain SHA-256 identity of the issuer and responder-key tuple
     * @param authorityId issuing authority identity
     * @param issuerId exact issuing credential identity
     * @param primarySpkiSha256 primary responder public-key SHA-256
     * @param alternativeSpkiSha256 distinct alternative responder public-key SHA-256
     * @param revision positive provisioning revision
     * @param state retained claim lifecycle state
     * @param canonicalRequestId deterministic administrative request identity for this revision
     * @param targetCommitment exact normalized provisioning target commitment
     * @param receipt accepted signing receipt, if any
     * @param credentialId issued X.509 credential identity, present only after completion
     * @param certificateSha256 issued certificate SHA-256, present only after completion
     * @param predecessorCredentialId predecessor credential for explicit renewal, absent for revision one
     * @throws NullPointerException if a required identity or optional container is null
     * @throws IllegalArgumentException if a digest, revision, derived identity or lifecycle invariant is
     *         inconsistent
     */
    OcspProvisioningSlot {
        Objects.requireNonNull(realmId); Objects.requireNonNull(authorityId); Objects.requireNonNull(issuerId);
        Objects.requireNonNull(state); Objects.requireNonNull(receipt); Objects.requireNonNull(credentialId);
        Objects.requireNonNull(certificateSha256); Objects.requireNonNull(predecessorCredentialId);
        digest(serverSlotId); digest(coreSlotId); digest(primarySpkiSha256); digest(alternativeSpkiSha256); digest(targetCommitment);
        certificateSha256.ifPresent(OcspProvisioningSlot::digest);
        if (revision < 1 || primarySpkiSha256.equals(alternativeSpkiSha256)
                || !coreSlotId.equals(coreIdentity(authorityId, issuerId, primarySpkiSha256, alternativeSpkiSha256))
                || !serverSlotId.equals(ManagedOcspProvisioningIdentity.serverSlotId(realmId.value(), coreSlotId))
                || !canonicalRequestId.equals(ManagedOcspProvisioningIdentity.serverRequestId(serverSlotId, revision))
                || (revision == 1) == predecessorCredentialId.isPresent()) throw invalid();
        boolean complete = state == State.COMPLETED;
        if (credentialId.isPresent() != complete || certificateSha256.isPresent() != complete
                || state == State.CLAIMED && receipt.isPresent()
                || (state == State.ACCEPTED || complete) && receipt.isEmpty()
                || complete && !credentialId.orElseThrow().value().equals("x509:" + certificateSha256.orElseThrow())) throw invalid();
    }

    /**
     * Validates a normal claim transition without permitting receipt replacement.
     *
     * @param previous exact retained prior slot, or empty for the initial claim
     * @throws IllegalArgumentException if coordinates change, renewal skips a revision,
     *         a receipt is replaced or a terminal state changes
     */
    void requireTransition(Optional<OcspProvisioningSlot> previous) { requireTransition(previous, false); }

    /**
     * Validates immutable slot coordinates and the sole permitted explicit renewal transition.
     *
     * @param previous exact retained prior slot, or empty for the initial claim
     * @param definiteAttachment whether the store's verified attachment path permits receipt replacement
     * @throws IllegalArgumentException if coordinates, revision or lifecycle invariants are violated
     */
    void requireTransition(Optional<OcspProvisioningSlot> previous, boolean definiteAttachment) {
        if (previous.isEmpty()) {
            if (revision != 1 || state != State.CLAIMED) throw invalid();
            return;
        }
        var old = previous.orElseThrow();
        if (!realmId.equals(old.realmId) || !serverSlotId.equals(old.serverSlotId) || !coreSlotId.equals(old.coreSlotId)
                || !authorityId.equals(old.authorityId) || !issuerId.equals(old.issuerId)
                || !primarySpkiSha256.equals(old.primarySpkiSha256) || !alternativeSpkiSha256.equals(old.alternativeSpkiSha256)) throw invalid();
        if (revision != old.revision) {
            if (old.state != State.COMPLETED || old.revision == Long.MAX_VALUE || revision != old.revision + 1
                    || state != State.CLAIMED || !predecessorCredentialId.equals(old.credentialId)) throw invalid();
            return;
        }
        if (!canonicalRequestId.equals(old.canonicalRequestId) || !targetCommitment.equals(old.targetCommitment)
                || !predecessorCredentialId.equals(old.predecessorCredentialId)
                || old.receipt.isPresent() && !receipt.equals(old.receipt) && !definiteAttachment
                || old.state == State.ACCEPTED && state == State.CLAIMED
                || (old.state == State.COMPLETED || old.state == State.FAILED) && !equals(old)) throw invalid();
    }

    /**
     * Checks exact scope, target, receipt and result consistency with the administrative request.
     *
     * @param request administrative request proposed for the same atomic mutation
     * @throws IllegalArgumentException if operation, request identity, scope, receipt,
     *         target, SDK-proof absence or terminal result differs
     */
    void requireRequest(AdministrativeRequest request) {
        if (!request.operation().equals(OPERATION) || !request.requestId().equals(canonicalRequestId)
                || !request.scope().realmId().equals(realmId) || !request.scope().authorityId().equals(Optional.of(authorityId))
                || !request.scope().issuerId().equals(Optional.of(issuerId)) || !request.targetCommitment().equals(targetCommitment)
                || !request.receipt().equals(receipt) || request.sdkProof().isPresent()) throw invalid();
        boolean terminalFailure = switch (request.state()) {
            case FAILED, REJECTED, EXPIRED -> true;
            default -> false;
        };
        if (state == State.COMPLETED && request.state() != AdministrativeRequest.State.SUCCEEDED
                || state == State.FAILED != terminalFailure
                || request.state() == AdministrativeRequest.State.SUCCEEDED && state != State.COMPLETED) throw invalid();
        if (state == State.COMPLETED) {
            var result = request.result().orElseThrow(OcspProvisioningSlot::invalid).fields();
            if (!(result.get("credentialId") instanceof zeroecho.pki.application.PkiOperationValue.Text id)
                    || !id.value().equals(credentialId.orElseThrow().value())) throw invalid();
        }
    }

    private static String coreIdentity(PkiId authority, PkiId issuer, String primary, String alternative) {
        try (var bytes = new ByteArrayOutputStream(); var out = new DataOutputStream(bytes)) {
            for (byte[] field : new byte[][] { "zeroecho:ocsp-responder-core-slot:v1".getBytes(StandardCharsets.UTF_8),
                    authority.value().getBytes(StandardCharsets.UTF_8), issuer.value().getBytes(StandardCharsets.UTF_8),
                    HexFormat.of().parseHex(primary), HexFormat.of().parseHex(alternative) }) {
                out.writeInt(field.length); out.write(field);
            }
            out.flush(); return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()));
        } catch (IOException | NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    private static void digest(String value) { if (value == null || !value.matches("[0-9a-f]{64}")) throw invalid(); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("OCSP provisioning slot is inconsistent"); }
}
