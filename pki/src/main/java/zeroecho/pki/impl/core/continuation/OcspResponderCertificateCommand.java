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

package zeroecho.pki.impl.core.continuation;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole;

/**
 * Strict private version-one, 25-field managed responder certificate carrier.
 * Structural validation grants no issuance, proof or provider authority.
 * @param fields exact ordered immutable contract fields
 */
public record OcspResponderCertificateCommand(List<String> fields) {
    /** Existing public operation name, with a separately versioned private carrier. */
    public static final String OPERATION = "ocsp.responder.issue-certificate";
    /** Exact current private field count. */
    public static final int FIELD_COUNT = 25;
    /** Validates closed field grammar and canonical nested public evidence. */
    public OcspResponderCertificateCommand {
        fields = List.copyOf(fields);
        if (fields.size() != FIELD_COUNT || !fields.getFirst().equals("1")) throw invalid();
        for (int index : new int[]{1,2,3,4}) identifier(fields.get(index));
        for (int index : new int[]{5,8,14,15,16,18}) digest(fields.get(index));
        if (!fields.get(7).matches("[1-9][0-9]{0,18}")) throw invalid();
        new CertificateProfileRef(fields.get(6), Long.parseLong(fields.get(7)), HexFormat.of().parseHex(fields.get(8)));
        decodeSubject(fields.get(9));
        DomainAttributeEncoding.decode(fields.get(19));
        Instant start = Instant.parse(fields.get(10)), end = Instant.parse(fields.get(11));
        if (!start.toString().equals(fields.get(10)) || !end.toString().equals(fields.get(11)) || !end.isAfter(start)) throw invalid();
        IssuerKeyBinding primary = decodeKey(fields.get(12)), alternative = decodeKey(fields.get(13));
        if (primary.keyRef().equals(alternative.keyRef()) || primary.subjectSpkiSha256().equals(alternative.subjectSpkiSha256())) throw invalid();
        if (!fields.get(17).matches("ocsp-prov:[0-9a-f]{64}:r[1-9][0-9]{0,18}")) throw invalid();
        for (int index : new int[]{20,22}) {
            PkiId id = new PkiId(fields.get(index)); var submission = SigningSubmissionId.parse(id);
            ManagedKeyProofChallenge.requireOperation(id, submission.namespace());
        }
        if (fields.get(20).equals(fields.get(22))) throw invalid();
        for (int index : new int[]{21,23}) ManagedKeyProofCommand.validateComplete(decodeNested(fields.get(index), ManagedKeyProofCommand.OPERATION, 14));
        if (!fields.get(24).matches("[1-9][0-9]{0,48}") || new java.math.BigInteger(fields.get(24)).bitLength() > 159) throw invalid();
        // Reuse the actual bounded domain encoder; this is not a new storage budget.
        DomainCommandEncoding.template(DomainContinuationStore.Kind.ISSUANCE, OPERATION, fields.toArray(String[]::new));
    }
    /** @return canonical complete internal command */
    public EncodedObject encode() { return encoded(OPERATION, fields); }
    /** @param encoded exact current carrier @return validated immutable command @throws IllegalArgumentException if malformed */
    public static OcspResponderCertificateCommand decode(EncodedObject encoded) {
        var command = DomainCommandEncoding.decode(encoded).requireFields(FIELD_COUNT);
        if (!command.operation().equals(OPERATION)) throw invalid();
        return new OcspResponderCertificateCommand(command.fields());
    }
    /** @return exact immutable profile reference */
    public CertificateProfileRef profile() { return new CertificateProfileRef(fields.get(6), Long.parseLong(fields.get(7)), HexFormat.of().parseHex(fields.get(8))); }
    /** @param role exact responder subject role @return captured public subject binding */
    public IssuerKeyBinding subjectBinding(SubjectKeyRole role) { return decodeKey(fields.get(role == SubjectKeyRole.PRIMARY ? 12 : 13)); }
    /** @param role required subject role @return exact retained nested proof command */
    public DomainCommandEncoding.Decoded proofCommand(SubjectKeyRole role) { return decodeNested(fields.get(role == SubjectKeyRole.PRIMARY ? 21 : 23), ManagedKeyProofCommand.OPERATION, 14); }
    /** @return exact frozen trusted execution attributes, without a current server lookup */
    public zeroecho.pki.api.attr.AttributeSet executionAttributes() { return DomainAttributeEncoding.decode(fields.get(19)); }
    /** @return SHA256 of the actual canonical retained execution-attribute bytes */
    public String executionEvidenceCommitment() { return hash(Base64.getUrlDecoder().decode(fields.get(19))); }
    /** @return domain-separated parent intent including serial, excluding both proof descriptor/ID pairs */
    public String intentCommitment() { return "ocsp-intent:v1:" + hash(encoded(OPERATION, parentFields()).bytes()); }
    /** @return domain-separated final candidate target, excluding proof descriptor circularity */
    public String frozenTargetCommitment() { return hash(encoded("OCSP_RESPONDER_FROZEN_TARGET_V1", parentFields()).bytes()); }
    private List<String> parentFields() { var selected = new ArrayList<>(fields.subList(0,20)); selected.add(fields.get(24)); return selected; }
    /** @param key captured immutable public role binding @return canonical private role encoding */
    public static String encodeKey(IssuerKeyBinding key) {
        return base64(encoded("OCSP_RESPONDER_SUBJECT_BINDING_V1", List.of(key.keyRef().value(), key.publicKeyAlgorithm().canonicalForm(),
                key.signatureAlgorithm().canonicalForm(), HexFormat.of().formatHex(key.signatureAlgorithmIdentifier().bytes()), key.subjectSpkiSha256())));
    }
    /** @param text canonical private role encoding @return structurally validated captured binding */
    public static IssuerKeyBinding decodeKey(String text) {
        var command = decodeNested(text, "OCSP_RESPONDER_SUBJECT_BINDING_V1", 5);
        byte[] algorithm = ManagedKeyProofCommand.hex(command.field(3), 1, ManagedKeyProofCommand.MAX_ALGORITHM_DER_BYTES);
        try {
            new zeroecho.pki.impl.framework.x509.StreamingDerReader().validate(algorithm, ManagedKeyProofCommand.MAX_ALGORITHM_DER_BYTES);
            if (!java.util.Arrays.equals(algorithm, zeroecho.pkix.Pkix.encodeAlgorithmIdentifier(zeroecho.pkix.Pkix.parseAlgorithmIdentifier(algorithm)))) throw invalid();
        } catch (java.io.IOException malformed) { throw invalid(); }
        var key = new IssuerKeyBinding(new KeyRef(command.field(0)), AlgorithmIdentity.parse(command.field(1), List.of()),
                AlgorithmIdentity.parse(command.field(2), List.of()), new EncodedObject(Encoding.DER, algorithm), command.field(4));
        if (!encodeKey(key).equals(text)) throw invalid(); return key;
    }
    /** @param subject exact ordered RDNs @return canonical private subject encoding */
    public static String encodeSubject(List<SubjectRdn> subject) {
        if (subject.isEmpty() || subject.size() > 32) throw invalid();
        var fields = new ArrayList<String>();
        for (var rdn : subject) { fields.add(rdn.type().name()); fields.add(rdn.value()); }
        return base64(encoded("OCSP_RESPONDER_SUBJECT_V1", fields));
    }
    /** @param text exact private subject encoding @return immutable canonical ordered RDNs */
    public static List<SubjectRdn> decodeSubject(String text) {
        var command = DomainCommandEncoding.decode(binary(text));
        if (!command.operation().equals("OCSP_RESPONDER_SUBJECT_V1") || command.fields().isEmpty()
                || command.fields().size() > 64 || command.fields().size() % 2 != 0) throw invalid();
        var subject = new ArrayList<SubjectRdn>();
        for (int index=0; index<command.fields().size(); index+=2) subject.add(new SubjectRdn(SubjectRdnType.valueOf(command.field(index)), command.field(index+1)));
        if (!encodeSubject(subject).equals(text)) throw invalid(); return List.copyOf(subject);
    }
    /** @param proof exact complete private proof command @return canonical descriptor text */
    public static String encodeProof(DomainCommandEncoding.Decoded proof) {
        ManagedKeyProofCommand.validateComplete(proof); return base64(encoded(proof.operation(), proof.fields()));
    }
    private static DomainCommandEncoding.Decoded decodeNested(String text, String operation, int count) {
        var command = DomainCommandEncoding.decode(binary(text)).requireFields(count);
        if (!command.operation().equals(operation)) throw invalid(); return command;
    }
    private static EncodedObject binary(String text) {
        if (text == null || text.length() > 4_194_304 || !text.matches("[A-Za-z0-9_-]+")) throw invalid();
        byte[] bytes = Base64.getUrlDecoder().decode(text);
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(text)) throw invalid();
        return new EncodedObject(Encoding.BINARY, bytes);
    }
    private static EncodedObject encoded(String operation, List<String> fields) { return DomainCommandEncoding.template(DomainContinuationStore.Kind.ISSUANCE, operation, fields.toArray(String[]::new)).command(); }
    private static String base64(EncodedObject encoded) { return Base64.getUrlEncoder().withoutPadding().encodeToString(encoded.bytes()); }
    private static String hash(byte[] bytes) { return zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment.sha256(bytes).sha256(); }
    private static void identifier(String text) { Objects.requireNonNull(text); ManagedKeyProofCommand.utf8Length(text,4096); if (text.isBlank()) throw invalid(); }
    private static void digest(String text) { if (text == null || !text.matches("[0-9a-f]{64}")) throw invalid(); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Managed responder certificate command invalid"); }
}
