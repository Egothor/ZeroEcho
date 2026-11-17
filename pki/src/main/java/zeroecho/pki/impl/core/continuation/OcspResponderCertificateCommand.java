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

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * Retains the strict internal version-one command for a managed responder certificate.
 *
 * <p>The 25 fields freeze issuer/profile/path selection, subject-key bindings,
 * requested subject and validity, final TBS commitment, execution evidence, two
 * distinct proof steps and the serial number. Construction snapshots the field
 * list and validates its grammar; it does not resolve live managed keys, prove
 * possession, authorize issuance or register an OCSP responder.
 *
 * @param fields exact ordered contract fields, with no null entries; copied on construction
 */
public record OcspResponderCertificateCommand(List<String> fields) {
    /**
     * Existing public operation name whose internal carrier is versioned separately.
     */
    public static final String OPERATION = "ocsp.responder.issue-certificate";
    /**
     * Exact number of fields in the current internal command schema.
     */
    public static final int FIELD_COUNT = 25;
    /**
     * Snapshots and validates the closed field grammar and canonical nested public evidence.
     *
     * <p>Both subject roles and child identities must be distinct, validity must
     * use canonical increasing instants, and the positive serial is bounded to
     * 159 bits. Nested descriptors and aggregate size are checked with the existing
     * domain codec. Cross-field proof-to-parent validation remains a separate duty of
     * {@link OcspResponderSubjectProofBindings}; no signature is verified here.
     *
     * @throws NullPointerException if the field list or an entry is null
     * @throws IllegalArgumentException if a field count, version, coordinate, time,
     *         role, nested descriptor or aggregate bound is invalid
     * @throws java.time.DateTimeException if a validity instant cannot be parsed
     * @param fields exact ordered contract fields, with no null entries; copied on construction
     */
    public OcspResponderCertificateCommand {
        fields = List.copyOf(fields);
        if (fields.size() != FIELD_COUNT || !"1".equals(fields.getFirst())) {
            throw invalid();
        }
        for (int index : new int[] {1, 2, 3, 4}) {
            identifier(fields.get(index));
        }
        for (int index : new int[] {5, 8, 14, 15, 16, 18}) {
            digest(fields.get(index));
        }
        if (!fields.get(7).matches("[1-9][0-9]{0,18}")) {
            throw invalid();
        }
        new CertificateProfileRef(fields.get(6), Long.parseLong(fields.get(7)), HexFormat.of().parseHex(fields.get(8)));
        decodeSubject(fields.get(9));
        DomainAttributeEncoding.decode(fields.get(19));
        Instant start = Instant.parse(fields.get(10));
        Instant end = Instant.parse(fields.get(11));
        if (!start.toString().equals(fields.get(10)) || !end.toString().equals(fields.get(11)) || !end.isAfter(start)) {
            throw invalid();
        }
        IssuerKeyBinding primary = decodeKey(fields.get(12));
        IssuerKeyBinding alternative = decodeKey(fields.get(13));
        if (primary.keyRef().equals(alternative.keyRef())
                || primary.subjectSpkiSha256().equals(alternative.subjectSpkiSha256())) {
            throw invalid();
        }
        if (!fields.get(17).matches("ocsp-prov:[0-9a-f]{64}:r[1-9][0-9]{0,18}")) {
            throw invalid();
        }
        for (int index : new int[] {20, 22}) {
            requireProofOperation(fields.get(index));
        }
        if (fields.get(20).equals(fields.get(22))) {
            throw invalid();
        }
        for (int index : new int[] {21, 23}) {
            ManagedKeyProofCommand.validateComplete(decodeNested(fields.get(index), ManagedKeyProofCommand.OPERATION, 14));
        }
        if (!fields.get(24).matches("[1-9][0-9]{0,48}")
                || new java.math.BigInteger(fields.get(24)).bitLength() > 159) {
            throw invalid();
        }
        // Reuse the actual bounded domain encoder; this is not a new storage budget.
        DomainCommandEncoding.template(DomainContinuationStore.Kind.ISSUANCE, OPERATION, fields.toArray(String[]::new));
    }
    /**
     * Encodes the complete retained command using the bounded issuance domain framing.
     *
     * @return independently owned immutable binary command bytes and encoding metadata
     */
    public EncodedObject encode() {
        return encoded(OPERATION, fields);
    }
    /**
     * Decodes the exact current operation and reconstructs its validated immutable fields.
     *
     * <p>Unknown operation discriminators, wrong field counts and invalid nested
     * coordinates fail closed. Decoding does not read a store or establish authorization.
     *
     * @param encoded complete bounded binary carrier
     * @return an independently owned immutable command
     * @throws NullPointerException if the carrier is null
     * @throws IllegalArgumentException if domain framing or command structure is malformed
     * @throws java.time.DateTimeException if a validity instant cannot be parsed
     */
    public static OcspResponderCertificateCommand decode(EncodedObject encoded) {
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(encoded).requireFields(FIELD_COUNT);
        if (!OPERATION.equals(command.operation())) {
            throw invalid();
        }
        return new OcspResponderCertificateCommand(command.fields());
    }
    /**
     * Reconstructs the exact retained profile reference without following an active pointer.
     *
     * @return independently constructed immutable profile identifier, version and digest
     */
    public CertificateProfileRef profile() {
        return new CertificateProfileRef(fields.get(6), Long.parseLong(fields.get(7)),
                HexFormat.of().parseHex(fields.get(8)));
    }
    /**
     * Reads the captured public signing-key binding for the requested subject role.
     *
     * <p>The primary constant selects the primary field; callers supply the explicit
     * alternative constant for the alternative field. No provider is consulted and
     * the binding itself does not prove key possession or grant signing permission.
     *
     * @param role explicit primary or alternative responder subject role
     * @return independently decoded immutable public subject-key binding
     */
    public IssuerKeyBinding subjectBinding(SubjectKeyRole role) {
        return decodeKey(fields.get(role == SubjectKeyRole.PRIMARY ? 12 : 13));
    }
    /**
     * Reads the exact nested proof command selected by an explicit subject role.
     *
     * <p>The primary constant selects the primary descriptor; callers supply the
     * alternative constant for the alternative descriptor. This accessor does not
     * compare the nested proof with its parent or verify its signature.
     *
     * @param role explicit primary or alternative subject role
     * @return independently decoded immutable proof-command metadata
     */
    public DomainCommandEncoding.Decoded proofCommand(SubjectKeyRole role) {
        return decodeNested(fields.get(role == SubjectKeyRole.PRIMARY ? 21 : 23), ManagedKeyProofCommand.OPERATION, 14);
    }

    /**
     * Decodes the frozen execution attributes without consulting current server state.
     *
     * <p>Trust in these attributes comes from the original authenticated preparation, not from the
     * act of decoding this public carrier.
     *
     * @return the exact retained immutable execution attributes
     */
    public zeroecho.pki.api.attr.AttributeSet executionAttributes() {
        return DomainAttributeEncoding.decode(fields.get(19));
    }
    /**
     * Commits the exact retained canonical execution-attribute bytes.
     *
     * @return their SHA-256 digest as 64 lowercase hexadecimal characters
     */
    public String executionEvidenceCommitment() {
        return hash(Base64.getUrlDecoder().decode(fields.get(19)));
    }
    /**
     * Derives the frozen parent intent without circular child-proof coordinates.
     *
     * <p>The first 20 fields and serial are committed; both proof step identities
     * and descriptors are excluded. The operation discriminator and domain framing
     * supply the retained parent-intent encoding.
     *
     * @return {@code ocsp-intent:v1:} followed by the canonical SHA-256 digest
     */
    public String intentCommitment() {
        return "ocsp-intent:v1:" + hash(encoded(OPERATION, parentFields()).bytes());
    }
    /**
     * Derives the final candidate-target commitment from the same noncircular parent fields.
     *
     * <p>A dedicated target discriminator separates this digest from the parent intent.
     * It binds the serial and final-TBS coordinate without incorporating child proof IDs.
     *
     * @return the target SHA-256 commitment as 64 lowercase hexadecimal characters
     */
    public String frozenTargetCommitment() {
        return hash(encoded("OCSP_RESPONDER_FROZEN_TARGET_V1", parentFields()).bytes());
    }
    private List<String> parentFields() {
        List<String> selected = new ArrayList<>(fields.subList(0, 20));
        selected.add(fields.get(24));
        return selected;
    }
    /**
     * Encodes the public coordinates of one captured managed subject-key role.
     *
     * @param key immutable role binding containing a managed reference, not private key bytes
     * @return canonical unpadded Base64url internal role descriptor
     * @throws NullPointerException if the binding is null
     * @throws IllegalArgumentException if the bounded domain encoding cannot represent the binding
     */
    public static String encodeKey(IssuerKeyBinding key) {
        return base64(
                encoded(
                        "OCSP_RESPONDER_SUBJECT_BINDING_V1",
                        List.of(
                                key.keyRef().value(),
                                key.publicKeyAlgorithm().canonicalForm(),
                                key.signatureAlgorithm().canonicalForm(),
                                HexFormat.of()
                                        .formatHex(key.signatureAlgorithmIdentifier().bytes()),
                                key.subjectSpkiSha256())));
    }

    /**
     * Decodes a canonical role descriptor and checks its public algorithm representation.
     *
     * <p>The exact AlgorithmIdentifier must be canonical DER and re-encoding the reconstructed
     * binding must reproduce the supplied descriptor. No managed key lookup, SPKI possession proof
     * or operation authorization occurs.
     *
     * @param text canonical unpadded Base64url role descriptor
     * @return independently reconstructed immutable public role binding
     * @throws IllegalArgumentException if text is null, oversized, noncanonical or malformed
     */
    // Malformed role descriptors must retain the stable safe diagnostic boundary.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public static IssuerKeyBinding decodeKey(String text) {
        DomainCommandEncoding.Decoded command =
                decodeNested(text, "OCSP_RESPONDER_SUBJECT_BINDING_V1", 5);
        byte[] algorithm = ManagedKeyProofCommand.hex(command.field(3), 1, ManagedKeyProofCommand.MAX_ALGORITHM_DER_BYTES);
        try {
            new zeroecho.pki.impl.framework.x509.StreamingDerReader()
                    .validate(algorithm, ManagedKeyProofCommand.MAX_ALGORITHM_DER_BYTES);
            if (!java.util.Arrays.equals(
                    algorithm,
                    zeroecho.pkix.Pkix.encodeAlgorithmIdentifier(zeroecho.pkix.Pkix.parseAlgorithmIdentifier(algorithm)))) {
                throw invalid();
            }
        } catch (java.io.IOException malformed) {
            throw invalid();
        }
        IssuerKeyBinding key = new IssuerKeyBinding(new KeyRef(command.field(0)), AlgorithmIdentity.parse(command.field(1), List.of()),
                AlgorithmIdentity.parse(command.field(2), List.of()), new EncodedObject(Encoding.DER, algorithm), command.field(4));
        if (!encodeKey(key).equals(text)) {
            throw invalid();
        }
        return key;
    }
    /**
     * Encodes the exact ordered responder subject RDNs without normalizing their values.
     *
     * @param subject between 1 and 32 non-null typed RDNs in subject order
     * @return canonical unpadded Base64url internal subject descriptor
     * @throws NullPointerException if the list or an RDN is null
     * @throws IllegalArgumentException if the RDN count or aggregate encoding is outside its bounds
     */
    public static String encodeSubject(List<SubjectRdn> subject) {
        if (subject.isEmpty() || subject.size() > 32) {
            throw invalid();
        }
        List<String> fields = new ArrayList<>();
        for (SubjectRdn rdn : subject) {
            fields.add(rdn.type().name());
            fields.add(rdn.value());
        }
        return base64(encoded("OCSP_RESPONDER_SUBJECT_V1", fields));
    }
    /**
     * Decodes an ordered subject and requires exact canonical descriptor re-encoding.
     *
     * @param text exact unpadded Base64url internal subject descriptor
     * @return an unmodifiable list containing 1 through 32 immutable ordered RDNs
     * @throws IllegalArgumentException if text is null, oversized, noncanonical or malformed
     */
    public static List<SubjectRdn> decodeSubject(String text) {
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(binary(text));
        if (!"OCSP_RESPONDER_SUBJECT_V1".equals(command.operation())
                || command.fields().isEmpty()
                || command.fields().size() > 64
                || command.fields().size() % 2 != 0) {
            throw invalid();
        }
        List<SubjectRdn> subject = new ArrayList<>();
        for (int index = 0; index < command.fields().size(); index += 2) {
            subject.add(new SubjectRdn(SubjectRdnType.valueOf(command.field(index)), command.field(index + 1)));
        }
        if (!encodeSubject(subject).equals(text)) {
            throw invalid();
        }
        return List.copyOf(subject);
    }
    /**
     * Validates and encodes one complete managed-key proof command descriptor.
     *
     * <p>Complete proof-command structure is checked; actual proof signatures and
     * parent/role bindings require the separate verifier and binding checks.
     *
     * @param proof exact complete managed-key proof command
     * @return canonical unpadded Base64url descriptor text
     * @throws NullPointerException if the proof is null
     * @throws IllegalArgumentException if proof metadata or bounded encoding is malformed
     */
    public static String encodeProof(DomainCommandEncoding.Decoded proof) {
        ManagedKeyProofCommand.validateComplete(proof);
        return base64(encoded(proof.operation(), proof.fields()));
    }
    private static DomainCommandEncoding.Decoded decodeNested(String text, String operation, int count) {
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(binary(text)).requireFields(count);
        if (!command.operation().equals(operation)) {
            throw invalid();
        }
        return command;
    }
    private static EncodedObject binary(String text) {
        if (text == null || text.length() > 4_194_304 || !text.matches("[A-Za-z0-9_-]+")) {
            throw invalid();
        }
        byte[] bytes = Base64.getUrlDecoder().decode(text);
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(text)) {
            throw invalid();
        }
        return new EncodedObject(Encoding.BINARY, bytes);
    }
    private static EncodedObject encoded(String operation, List<String> fields) {
        return DomainCommandEncoding.template(DomainContinuationStore.Kind.ISSUANCE, operation,
                fields.toArray(String[]::new)).command();
    }
    private static String base64(EncodedObject encoded) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encoded.bytes());
    }
    private static String hash(byte[] bytes) {
        return zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment.sha256(bytes).sha256();
    }
    private static void identifier(String text) {
        Objects.requireNonNull(text);
        ManagedKeyProofCommand.utf8Length(text, 4096);
        if (text.isBlank()) {
            throw invalid();
        }
    }
    private static void digest(String text) {
        if (text == null || !text.matches("[0-9a-f]{64}")) {
            throw invalid();
        }
    }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Managed responder certificate command invalid");
    }

    private static void requireProofOperation(String value) {
        PkiId id = new PkiId(value);
        SigningSubmissionId submission = SigningSubmissionId.parse(id);
        ManagedKeyProofChallenge.requireOperation(id, submission.namespace());
    }
}
