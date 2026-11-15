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

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.http.StrictJson;

/** Canonical closed version-one slot payload; no private keys or signing content are retained here. */
final class OcspProvisioningSlotCodec {
    private static final int MAXIMUM_BYTES = 16_384;
    private OcspProvisioningSlotCodec() { }
    static ServerControlStore.ProtocolRecord encode(OcspProvisioningSlot value) {
        var f = new LinkedHashMap<String, PkiOperationValue>();
        f.put("version", number(1)); f.put("realmId", text(value.realmId().value()));
        f.put("serverSlotId", text(value.serverSlotId())); f.put("coreSlotId", text(value.coreSlotId()));
        f.put("authorityId", text(value.authorityId().value())); f.put("issuerId", text(value.issuerId().value()));
        f.put("primarySpkiSha256", text(value.primarySpkiSha256())); f.put("alternativeSpkiSha256", text(value.alternativeSpkiSha256()));
        f.put("revision", number(value.revision())); f.put("state", text(value.state().name()));
        f.put("canonicalRequestId", text(value.canonicalRequestId())); f.put("targetCommitment", text(value.targetCommitment()));
        value.receipt().ifPresent(v -> f.put("receipt", new PkiOperationValue.ObjectValue(Map.of(
                "operationId", text(v.operationId().value()), "commitment", text(v.encodedCommitment())))));
        value.credentialId().ifPresent(v -> f.put("credentialId", text(v.value())));
        value.certificateSha256().ifPresent(v -> f.put("certificateSha256", text(v)));
        value.predecessorCredentialId().ifPresent(v -> f.put("predecessorCredentialId", text(v.value())));
        byte[] bytes = StrictJson.encode(new PkiOperationValue.ObjectValue(f));
        if (bytes.length > MAXIMUM_BYTES) throw invalid();
        return new ServerControlStore.ProtocolRecord(ServerControlStore.OCSP_PROVISIONING, value.serverSlotId(),
                ApprovalService.digest(java.util.Base64.getEncoder().encodeToString(bytes)), bytes);
    }
    static OcspProvisioningSlot decode(ServerControlStore.ProtocolRecord record) {
        if (!record.namespace().equals(ServerControlStore.OCSP_PROVISIONING)) throw invalid();
        var f = ((PkiOperationValue.ObjectValue)StrictJson.parse(record.payload(), MAXIMUM_BYTES)).fields();
        if (((PkiOperationValue.IntegerValue)f.get("version")).value() != 1) throw invalid();
        Optional<SigningAcceptanceReceipt> receipt = Optional.ofNullable(f.get("receipt")).map(v -> {
            var r = ((PkiOperationValue.ObjectValue)v).fields();
            if (!r.keySet().equals(Set.of("operationId", "commitment"))) throw invalid();
            return SigningAcceptanceReceipt.parse(new PkiId(string(r,"operationId")), string(r,"commitment"));
        });
        var value = new OcspProvisioningSlot(new RealmId(string(f,"realmId")), string(f,"serverSlotId"), string(f,"coreSlotId"),
                new PkiId(string(f,"authorityId")), new PkiId(string(f,"issuerId")), string(f,"primarySpkiSha256"), string(f,"alternativeSpkiSha256"),
                ((PkiOperationValue.IntegerValue)f.get("revision")).value(), OcspProvisioningSlot.State.valueOf(string(f,"state")),
                string(f,"canonicalRequestId"), string(f,"targetCommitment"), receipt, optional(f,"credentialId").map(PkiId::new),
                optional(f,"certificateSha256"), optional(f,"predecessorCredentialId").map(PkiId::new));
        var canonical = encode(value);
        if (!canonical.recordId().equals(record.recordId()) || !canonical.commitment().equals(record.commitment())
                || !Arrays.equals(canonical.payload(), record.payload())) throw invalid();
        return value;
    }
    private static String string(Map<String,PkiOperationValue> fields, String key) { return ((PkiOperationValue.Text)fields.get(key)).value(); }
    private static Optional<String> optional(Map<String,PkiOperationValue> fields, String key) { return Optional.ofNullable(fields.get(key)).map(v -> ((PkiOperationValue.Text)v).value()); }
    private static PkiOperationValue.Text text(String value) { return new PkiOperationValue.Text(value); }
    private static PkiOperationValue.IntegerValue number(long value) { return new PkiOperationValue.IntegerValue(value); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("OCSP provisioning slot encoding is invalid"); }
}
