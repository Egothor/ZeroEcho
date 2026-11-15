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

import java.util.Optional;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest;
import zeroecho.pki.api.issuance.ManagedOcspProvisioningIdentity;

/** Purpose-specific canonical admission and projection; the coordinator retains actor and approval authority. */
final class OcspResponderProvisioningService {
    private final RealmId realm;
    private final ServerControlStore control;
    private final java.util.function.Supplier<SemanticSigningService> signing;
    OcspResponderProvisioningService(RealmId realm, ServerControlStore control,
            java.util.function.Supplier<SemanticSigningService> signing) {
        this.realm = realm; this.control = control; this.signing = signing;
    }
    record Selection(String coreSlotId, String serverSlotId, long revision, String requestId,
            String targetCommitment, PkiId authorityId, PkiId issuerId, String primarySpkiSha256,
            String alternativeSpkiSha256, Optional<PkiId> predecessor) { }

    Selection select(ManagedOcspResponderIssuanceRequest request) {
        var selected = signing.get().managedOcspResponderProvisioningBinding(request);
        var retained = selected.retainedBinding();
        var id = java.util.regex.Pattern.compile("ocsp-prov:([0-9a-f]{64}):r([1-9][0-9]{0,18})").matcher(retained.issuanceId());
        if (!id.matches()) throw new IllegalStateException("OCSP provisioning core identity invalid");
        String core = id.group(1), server = ManagedOcspProvisioningIdentity.serverSlotId(realm.value(), core);
        long revision = Long.parseLong(id.group(2));
        return new Selection(core, server, revision, ManagedOcspProvisioningIdentity.serverRequestId(server, revision),
                retained.effectiveCommitment(), retained.authorityId(), retained.expectedIssuerId(),
                selected.primarySpkiSha256(), selected.alternativeSpkiSha256(), request.expectedPredecessorCredentialId());
    }

    Optional<ServerControlStore.ProtocolRecord> record(Selection selection) {
        return control.protocolRecord(ServerControlStore.OCSP_PROVISIONING, selection.serverSlotId());
    }

    Optional<AdministrativeRequest> existing(Selection selection) {
        var record = record(selection);
        if (record.isEmpty()) return Optional.empty();
        var slot = OcspProvisioningSlotCodec.decode(record.orElseThrow());
        var request = requireRequest(slot);
        if (slot.revision() == selection.revision()) {
            if (!slot.targetCommitment().equals(selection.targetCommitment())) throw new TargetConflict(slot.canonicalRequestId());
            return Optional.of(request);
        }
        if (slot.state() != OcspProvisioningSlot.State.COMPLETED || slot.revision() == Long.MAX_VALUE
                || slot.revision() + 1 != selection.revision() || !slot.credentialId().equals(selection.predecessor())) {
            throw new TargetConflict(slot.canonicalRequestId());
        }
        return Optional.empty();
    }

    ServerControlStore.ProtocolMutation claim(Selection selected, AdministrativeRequest request) {
        var previous = record(selected);
        var slot = new OcspProvisioningSlot(realm, selected.serverSlotId(), selected.coreSlotId(), selected.authorityId(),
                selected.issuerId(), selected.primarySpkiSha256(), selected.alternativeSpkiSha256(), selected.revision(),
                OcspProvisioningSlot.State.CLAIMED, selected.requestId(), selected.targetCommitment(), Optional.empty(),
                Optional.empty(), Optional.empty(), selected.predecessor());
        slot.requireRequest(request);
        return new ServerControlStore.ProtocolMutation(OcspProvisioningSlotCodec.encode(slot), previous.map(ServerControlStore.ProtocolRecord::commitment));
    }

    ServerControlStore.ProtocolMutation transition(AdministrativeRequest old, AdministrativeRequest next) {
        var row = control.protocolRecord(ServerControlStore.OCSP_PROVISIONING, slotId(old.requestId()))
                .orElseThrow(() -> new IllegalStateException("OCSP provisioning claim unavailable"));
        var slot = OcspProvisioningSlotCodec.decode(row); slot.requireRequest(old);
        OcspProvisioningSlot.State state;
        Optional<PkiId> credential = Optional.empty(); Optional<String> digest = Optional.empty();
        switch (next.state()) {
            case SUCCEEDED -> {
                var value = next.result().orElseThrow().fields().get("credentialId");
                if (!(value instanceof zeroecho.pki.application.PkiOperationValue.Text id) || !id.value().matches("x509:[0-9a-f]{64}")) {
                    throw new IllegalStateException("OCSP provisioning credential result invalid");
                }
                credential = Optional.of(new PkiId(id.value())); digest = Optional.of(id.value().substring(5));
                state = OcspProvisioningSlot.State.COMPLETED;
            }
            case FAILED, REJECTED, EXPIRED -> state = OcspProvisioningSlot.State.FAILED;
            default -> state = next.receipt().isPresent() ? OcspProvisioningSlot.State.ACCEPTED : OcspProvisioningSlot.State.CLAIMED;
        }
        var changed = new OcspProvisioningSlot(slot.realmId(), slot.serverSlotId(), slot.coreSlotId(), slot.authorityId(), slot.issuerId(),
                slot.primarySpkiSha256(), slot.alternativeSpkiSha256(), slot.revision(), state, slot.canonicalRequestId(),
                slot.targetCommitment(), next.receipt(), credential, digest, slot.predecessorCredentialId());
        changed.requireRequest(next);
        return new ServerControlStore.ProtocolMutation(OcspProvisioningSlotCodec.encode(changed), Optional.of(row.commitment()));
    }

    /** Pure durable observation proves that only the losing, definitely unaccepted receipt is replaced. */
    Attachment attachment(AdministrativeRequest request, ManagedOcspResponderIssuanceRequest selected,
            zeroecho.pki.api.signing.SigningAcceptanceReceipt winner) {
        requireClaim(request);
        var previous = request.receipt().orElseThrow();
        var service = signing.get();
        if (previous.equals(winner)
                || service.resolve(previous) != zeroecho.pki.api.signing.SigningAcceptanceResolution.NOT_ACCEPTED
                || !service.findManagedOcspResponderReceipt(selected).equals(Optional.of(winner))
                || service.resolve(winner) != zeroecho.pki.api.signing.SigningAcceptanceResolution.MATCHED) {
            throw new IllegalStateException("OCSP provisioning receipt attachment is not definite");
        }
        return new Attachment(request.requestId(),request.targetCommitment(),previous,winner);
    }

    /** Unforgeable package-local token constructed only after authoritative receipt observations. */
    static final class Attachment {
        private final String requestId;
        private final String target;
        private final zeroecho.pki.api.signing.SigningAcceptanceReceipt previous;
        private final zeroecho.pki.api.signing.SigningAcceptanceReceipt winner;
        private Attachment(String requestId,String target,zeroecho.pki.api.signing.SigningAcceptanceReceipt previous,
                zeroecho.pki.api.signing.SigningAcceptanceReceipt winner) {
            this.requestId=requestId; this.target=target; this.previous=previous; this.winner=winner;
        }
        void require(Optional<OcspProvisioningSlot> old, OcspProvisioningSlot next) {
            var prior=old.orElseThrow();
            if (!requestId.equals(prior.canonicalRequestId()) || !requestId.equals(next.canonicalRequestId())
                    || !target.equals(prior.targetCommitment()) || !target.equals(next.targetCommitment())
                    || prior.state()!=OcspProvisioningSlot.State.ACCEPTED || next.state()!=OcspProvisioningSlot.State.ACCEPTED
                    || !prior.receipt().equals(Optional.of(previous)) || !next.receipt().equals(Optional.of(winner))) {
                throw new IllegalStateException("OCSP provisioning attachment changed");
            }
        }
    }

    void requireClaim(AdministrativeRequest request) {
        var row = control.protocolRecord(ServerControlStore.OCSP_PROVISIONING, slotId(request.requestId()))
                .orElseThrow(() -> new IllegalStateException("OCSP provisioning claim unavailable"));
        OcspProvisioningSlotCodec.decode(row).requireRequest(request);
    }
    private AdministrativeRequest requireRequest(OcspProvisioningSlot slot) {
        var request = control.protocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST, slot.canonicalRequestId())
                .map(AdministrativeRequestCodec::decode).orElseThrow(() -> new IllegalStateException("OCSP provisioning request unavailable"));
        slot.requireRequest(request); return request;
    }
    private static String slotId(String requestId) {
        if (!requestId.matches("ocsp-prov:[0-9a-f]{64}:r[1-9][0-9]{0,18}")) throw new IllegalStateException("OCSP provisioning request identity invalid");
        return requestId.substring(10, 74);
    }
    static final class TargetConflict extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        private final String canonicalRequestId;
        TargetConflict(String canonicalRequestId) { super("OCSP_PROVISIONING_TARGET_CONFLICT"); this.canonicalRequestId = canonicalRequestId; }
        String canonicalRequestId() { return canonicalRequestId; }
    }
}
