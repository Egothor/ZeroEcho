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

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.application.PkiOperationValue;

/**
 * Closed public transport projection for dedicated managed responder provisioning.
 */
public final class OcspProvisioningProjection {
    private OcspProvisioningProjection() { }
    /**
     * Decodes public selections without trusting caller correlation identities or resolving managed keys.
     * @param fields exact operation argument object
     * @return immutable input requiring server normalization, pure validation and canonical admission
     * @throws IllegalArgumentException if the argument shape, identities or values are invalid
     */
    public static ManagedOcspResponderIssuanceRequest decode(Map<String,PkiOperationValue> fields) {
        var required = Set.of("authorityId", "primaryKeyRef", "alternativeKeyRef", "subject", "profileId", "profileVersion", "profileSha256",
                "issuerId", "chainPathId", "chainPathCommitment", "notBefore", "notAfter");
        var allowed = new java.util.HashSet<>(required); allowed.add("expectedPredecessorCredentialId");
        if (!fields.keySet().containsAll(required) || !allowed.containsAll(fields.keySet())) throw invalid();
        if (!(fields.get("subject") instanceof PkiOperationValue.ObjectValue subjectObject)
                || !subjectObject.fields().keySet().equals(Set.of("rdns"))
                || !(subjectObject.fields().get("rdns") instanceof PkiOperationValue.ListValue values)) throw invalid();
        List<SubjectRdn> subject = values.values().stream().map(value -> {
            if (!(value instanceof PkiOperationValue.ObjectValue object) || !object.fields().keySet().equals(Set.of("type","value"))) throw invalid();
            return new SubjectRdn(SubjectRdnType.valueOf(text(object.fields(),"type")), text(object.fields(),"value"));
        }).toList();
        if (!(fields.get("profileVersion") instanceof PkiOperationValue.IntegerValue version)) throw invalid();
        String profileHash = text(fields,"profileSha256");
        if (!profileHash.matches("[0-9a-f]{64}")) throw invalid();
        var profile = new CertificateProfileRef(text(fields,"profileId"), version.value(), java.util.HexFormat.of().parseHex(profileHash));
        var intent = new IssuanceIntent("ocsp-provision-input", "0".repeat(64), profile, new PkiId(text(fields,"issuerId")),
                new PkiId(text(fields,"chainPathId")), text(fields,"chainPathCommitment"));
        return new ManagedOcspResponderIssuanceRequest(new PkiId(text(fields,"authorityId")),new KeyRef(text(fields,"primaryKeyRef")),
                new KeyRef(text(fields,"alternativeKeyRef")),subject,new Validity(Instant.parse(text(fields,"notBefore")),Instant.parse(text(fields,"notAfter"))),
                intent,Optional.ofNullable(fields.get("expectedPredecessorCredentialId")).map(value -> {
                    if (!(value instanceof PkiOperationValue.Text predecessor)) throw invalid(); return new PkiId(predecessor.value());
                }));
    }
    /**
     * Projects the first normalized selection for durable replay; no private material is included.
     * @param value exact approved input including frozen actual key references
     * @return deterministic public operation arguments
     */
    public static PkiOperationValue.ObjectValue encode(ManagedOcspResponderIssuanceRequest value) {
        var fields = new LinkedHashMap<String,PkiOperationValue>();
        fields.put("authorityId", text(value.authorityId().value())); fields.put("primaryKeyRef",text(value.primaryKeyRef().value()));
        fields.put("alternativeKeyRef",text(value.alternativeKeyRef().value()));
        fields.put("subject",new PkiOperationValue.ObjectValue(Map.of("rdns",new PkiOperationValue.ListValue(value.subject().stream().map(r -> (PkiOperationValue)new PkiOperationValue.ObjectValue(
                Map.of("type",text(r.type().name()),"value",text(r.value())))).toList()))));
        fields.put("profileId",text(value.intent().expectedProfile().profileId())); fields.put("profileVersion",new PkiOperationValue.IntegerValue(value.intent().expectedProfile().profileVersion()));
        fields.put("profileSha256",text(java.util.HexFormat.of().formatHex(value.intent().expectedProfile().canonicalSha256())));
        fields.put("issuerId",text(value.intent().expectedIssuerId().value()));fields.put("chainPathId",text(value.intent().expectedChainPathId().value()));
        fields.put("chainPathCommitment",text(value.intent().expectedChainPathCommitment()));fields.put("notBefore",text(value.validity().notBefore().toString()));
        fields.put("notAfter",text(value.validity().notAfter().toString()));
        value.expectedPredecessorCredentialId().ifPresent(v -> fields.put("expectedPredecessorCredentialId",text(v.value())));
        return new PkiOperationValue.ObjectValue(fields);
    }
    private static String text(Map<String,PkiOperationValue> fields,String key) {
        if (!(fields.get(key) instanceof PkiOperationValue.Text value)) throw invalid(); return value.value();
    }
    private static PkiOperationValue.Text text(String value) { return new PkiOperationValue.Text(value); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Managed OCSP provisioning arguments invalid"); }
}
