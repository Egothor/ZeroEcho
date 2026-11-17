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
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.http.StrictJson;

/**
 * Strict private codec: ordinary records stay version one; SDK references require version two.
 */
final class AdministrativeRequestCodec {
    private static final String VERSION = "version";
    private static final String REALM_ID = "realmId";

    /**
     * Maximum retained administrative-request JSON payload size, in bytes.
     */
    /* default */ static final int MAXIMUM_BYTES = 524_288;
    private AdministrativeRequestCodec() { }
    /**
     * Encodes a private administrative request with version selected by its SDK-proof presence.
     *
     * @param value validated retained administrative request
     * @return namespace-bound protocol record with the exact payload commitment
     * @throws NullPointerException if value is null
     * @throws IllegalArgumentException if the encoded payload exceeds 524,288 bytes
     */
    /* default */ static ServerControlStore.ProtocolRecord encode(AdministrativeRequest value) {
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        fields.put(VERSION, number(value.sdkProof().isPresent() ? 2 : 1)); fields.put("requestId", text(value.requestId())); fields.put("revision", number(value.revision()));
        fields.put("operation", text(value.operation())); fields.put("envelope", value.envelope()); fields.put("scope", scope(value.scope()));
        fields.put("operationCommitment", text(value.operationCommitment())); fields.put("targetCommitment", text(value.targetCommitment()));
        fields.put("state", text(value.state().name())); fields.put("createdAt", text(value.createdAt().toString())); fields.put("updatedAt", text(value.updatedAt().toString()));
        fields.put("executionTimeoutMillis", number(value.executionTimeoutMillis()));
        value.profileCommitment().ifPresent(v -> fields.put("profileCommitment", text(v)));
        fields.put("actor", actor(value.actor())); value.approvalId().ifPresent(v -> fields.put("approvalId", text(v)));
        value.policyCommitment().ifPresent(v -> fields.put("policyCommitment", text(v)));
        value.receipt().ifPresent(v -> fields.put("receipt", object(Map.of("operationId", text(v.operationId().value()), "commitment", text(v.encodedCommitment())))));
        value.result().ifPresent(v -> fields.put("result", v)); value.failureCode().ifPresent(v -> fields.put("failureCode", text(v)));
        value.sdkProof().ifPresent(v -> fields.put("sdkProof", object(Map.of("intentId", text(v.intentId()), "proofCommitment", text(v.proofCommitment())))));
        byte[] encoded = StrictJson.encode(object(fields));
        if (encoded.length > MAXIMUM_BYTES) { throw new IllegalArgumentException("Administrative request is too large"); }
        return new ServerControlStore.ProtocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST, value.requestId(),
                ApprovalService.digest(java.util.Base64.getEncoder().encodeToString(encoded)), encoded);
    }
    /**
     * Decodes a retained request and verifies namespace, payload commitment and closed versioned fields.
     *
     * @param record private retained administrative-request protocol record
     * @return validated administrative lifecycle snapshot
     * @throws IllegalArgumentException if namespace, commitment, framing, fields or lifecycle coordinates are
     *         invalid
     * @throws NullPointerException if a required record or nested field is absent
     */
    /* default */ static AdministrativeRequest decode(ServerControlStore.ProtocolRecord record) {
        if (!ServerControlStore.ADMINISTRATIVE_REQUEST.equals(record.namespace())
                || !record.commitment().equals(ApprovalService.digest(java.util.Base64.getEncoder().encodeToString(record.payload())))) { throw new IllegalArgumentException("Request record commitment differs"); }
        Map<String,PkiOperationValue> f = fields(StrictJson.parse(record.payload(), MAXIMUM_BYTES));
        if (!f.keySet().containsAll(Set.of(VERSION,"requestId","revision","operation","envelope","actor","scope","operationCommitment","targetCommitment","state","createdAt","updatedAt","executionTimeoutMillis"))
                || !Set.of(VERSION,"requestId","revision","operation","envelope","actor","scope","operationCommitment","targetCommitment","state","createdAt","updatedAt","executionTimeoutMillis","approvalId","policyCommitment","receipt","result","failureCode","profileCommitment","sdkProof").containsAll(f.keySet())
                || (integer(f,VERSION) != 1 && integer(f,VERSION) != 2)
                || integer(f,VERSION) == 2 != f.containsKey("sdkProof")) { throw new IllegalArgumentException("Request record framing is invalid"); }
        Map<String,PkiOperationValue> a = fields(f.get("actor"));
        requireFields(a,Set.of("principalId","mode"),Set.of("principalId","mode","transportPrincipalId","evidence"));
        Optional<CertificateIdentityEvidence> evidence = Optional.ofNullable(a.get("evidence")).map(value -> {
            Map<String,PkiOperationValue> e = fields(value);
            Set<String> evidenceFields=Set.of(REALM_ID,"certificateSha256","canonicalKeySha256","issuerSerialSha256","legacySpkiSha256");
            requireFields(e,evidenceFields,evidenceFields);
            Set<String> spki = new TreeSet<>();
            ((PkiOperationValue.ListValue)e.get("legacySpkiSha256")).values().forEach(v -> spki.add(((PkiOperationValue.Text)v).value()));
            return new CertificateIdentityEvidence(new RealmId(string(e,REALM_ID)), string(e,"certificateSha256"), string(e,"canonicalKeySha256"), spki, string(e,"issuerSerialSha256"));
        });
        AdministrativeRequest.Actor actor = new AdministrativeRequest.Actor(string(a,"principalId"), AdministrativeAuthenticationMode.valueOf(string(a,"mode")), optional(a,"transportPrincipalId"), evidence);
        Map<String,PkiOperationValue> s = fields(f.get("scope"));
        requireFields(s,Set.of(REALM_ID),Set.of(REALM_ID,"authorityId","issuerId","profileId","responderId"));
        Permission.Scope scope = new Permission.Scope(new RealmId(string(s,REALM_ID)), optional(s,"authorityId").map(PkiId::new), optional(s,"issuerId").map(PkiId::new), optional(s,"profileId"), optional(s,"responderId"));
        Optional<SigningAcceptanceReceipt> receipt = Optional.ofNullable(f.get("receipt")).map(v -> { Map<String,PkiOperationValue> r=fields(v);requireFields(r,Set.of("operationId","commitment"),Set.of("operationId","commitment"));return SigningAcceptanceReceipt.parse(new PkiId(string(r,"operationId")),string(r,"commitment")); });
        Optional<AdministrativeRequest.SdkProof> sdkProof = Optional.ofNullable(f.get("sdkProof")).map(v -> {
            Map<String,PkiOperationValue> proof=fields(v); requireFields(proof,Set.of("intentId","proofCommitment"),Set.of("intentId","proofCommitment"));
            return new AdministrativeRequest.SdkProof(string(proof,"intentId"),string(proof,"proofCommitment"));
        });
        AdministrativeRequest result = new AdministrativeRequest(string(f,"requestId"), integer(f,"revision"), string(f,"operation"), (PkiOperationValue.ObjectValue)f.get("envelope"), actor, scope,
                string(f,"operationCommitment"),optional(f,"profileCommitment"),string(f,"targetCommitment"), AdministrativeRequest.State.valueOf(string(f,"state")),Instant.parse(string(f,"createdAt")),Instant.parse(string(f,"updatedAt")),integer(f,"executionTimeoutMillis"),
                optional(f,"approvalId"),optional(f,"policyCommitment"),receipt,Optional.ofNullable(f.get("result")).map(PkiOperationValue.ObjectValue.class::cast),optional(f,"failureCode"),sdkProof);
        if (!result.requestId().equals(record.recordId())) { throw new IllegalArgumentException("Request key differs"); }
        return result;
    }
    private static PkiOperationValue.ObjectValue scope(Permission.Scope scope) {
        Map<String,PkiOperationValue> values=new LinkedHashMap<>();values.put(REALM_ID,text(scope.realmId().value()));
        scope.authorityId().ifPresent(v->values.put("authorityId",text(v.value())));scope.issuerId().ifPresent(v->values.put("issuerId",text(v.value())));
        scope.profileId().ifPresent(v->values.put("profileId",text(v)));scope.responderId().ifPresent(v->values.put("responderId",text(v)));return object(values);
    }
    private static PkiOperationValue.ObjectValue actor(AdministrativeRequest.Actor actor) {
        Map<String,PkiOperationValue> values=new LinkedHashMap<>();values.put("principalId",text(actor.principalId()));values.put("mode",text(actor.mode().name()));actor.transportPrincipalId().ifPresent(v->values.put("transportPrincipalId",text(v)));
        actor.evidence().ifPresent(e -> values.put("evidence",object(Map.of(REALM_ID,text(e.realmId().value()),"certificateSha256",text(e.certificateSha256()),"canonicalKeySha256",text(e.canonicalKeySha256()),"issuerSerialSha256",text(e.issuerSerialSha256()),"legacySpkiSha256",new PkiOperationValue.ListValue(e.legacySpkiSha256().stream().sorted().map(v->(PkiOperationValue)text(v)).toList())))));
        return object(values);
    }
    private static void requireFields(Map<String,PkiOperationValue> fields,Set<String> required,Set<String> allowed) {
        if(!fields.keySet().containsAll(required)||!allowed.containsAll(fields.keySet())) { throw new IllegalArgumentException("Unexpected administrative request fields"); }
    }
    private static Map<String,PkiOperationValue> fields(PkiOperationValue value) { return ((PkiOperationValue.ObjectValue)value).fields(); }
    private static String string(Map<String,PkiOperationValue> values,String key) { return ((PkiOperationValue.Text)values.get(key)).value(); }
    private static long integer(Map<String,PkiOperationValue> values,String key) { return ((PkiOperationValue.IntegerValue)values.get(key)).value(); }
    private static Optional<String> optional(Map<String,PkiOperationValue> values,String key) { return Optional.ofNullable(values.get(key)).map(v->((PkiOperationValue.Text)v).value()); }
    private static PkiOperationValue.Text text(String value) { return new PkiOperationValue.Text(value); }
    private static PkiOperationValue.IntegerValue number(long value) { return new PkiOperationValue.IntegerValue(value); }
    private static PkiOperationValue.ObjectValue object(Map<String,PkiOperationValue> fields) { return new PkiOperationValue.ObjectValue(fields); }
}
