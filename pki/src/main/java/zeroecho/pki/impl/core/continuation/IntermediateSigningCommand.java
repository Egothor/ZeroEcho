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

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;

import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * Configuration-independent provenance for intermediate creation, additional
 * issuance and rollover. Fields 18 through
 * 20 freeze the proof submission ID, canonical unpadded base64url binary proof
 * command and canonical attributes. Attributes are provenance, not published
 * credential attributes. Fields 21 and 22 commit the exact TBS byte length and
 * SHA-256. Validation never resolves a retained proof or content. Attribute
 * canonical validation costs O(A² + A log A + bytes) for A identifiers; remaining
 * work and workspace are linear in the bounded command. Encoding is limited to
 * 1 MiB including framing before allocation of the outer command or staging.
 *
 * <p>The 23-field form retains the original proof provenance, the 25-field form
 * adds explicit outgoing subject and incoming parent bindings, and the 26-field
 * form additionally captures lifecycle context. Supporting a retained command
 * encoding does not provide an old-store migration procedure. Structural checks
 * do not replace live-candidate validation, proof verification or authorization.
 */
public final class IntermediateSigningCommand {
    private static final int EXTENDED_FIELDS = 25;
    private static final int LIFECYCLE_FIELDS = 26;
    private static final String SUBJECT_PROOFS_OPERATION = "CA_SUBJECT_PROOFS_V1";

    /**
     * Discriminator for creation of a new intermediate authority.
     */
    public static final String CREATE = "CREATE_INTERMEDIATE";
    /**
     * Discriminator for adding a credential to an existing intermediate authority.
     */
    public static final String ISSUE = "ISSUE_INTERMEDIATE";
    /**
     * Discriminator for advancing an existing intermediate to a new issuer generation.
     */
    public static final String ROLLOVER = "ROLLOVER_INTERMEDIATE";

    private IntermediateSigningCommand() {
    }

    /**
     * Identifies the closed operation set using the intermediate signing schemas.
     *
     * <p>Only the discriminator is checked here. A supported name does not establish
     * that its fields, proof provenance or lifecycle context are valid.
     *
     * @param operation discriminator to test, possibly null
     * @return true only for creation, additional issuance or rollover
     */
    public static boolean supports(String operation) {
        return CREATE.equals(operation) || ISSUE.equals(operation) || ROLLOVER.equals(operation);
    }

    /**
     * Validates frozen proof coordinates and canonical provenance only.
     *
     * <p>The primary and any alternative proof must bind the subject authority,
     * selected profile and outgoing subject key. Extended commands separately
     * capture the parent signing binding; an incoming certificate signature does
     * not choose the subject's future outgoing algorithm. No retained proof lookup,
     * content read or cryptographic signature verification occurs.
     *
     * @param command complete 23-, 25- or 26-field intermediate signing command
     * @return exact nested, complete canonical proof command
     * @throws IllegalStateException if frozen provenance is inconsistent
     * @throws IllegalArgumentException if an encoded binding or command field is malformed
     * @throws NullPointerException if the command is null
     */
    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    public static DomainCommandEncoding.Decoded validate(DomainCommandEncoding.Decoded command) {
        ProofValidation.requireContext(command);
        try {
            ManagedKeyProofCommand.utf8Length(command.field(18), 4096);
            PkiId proofId = new PkiId(command.field(18));
            String encoded = command.field(19);
            if (encoded.isEmpty() || encoded.length() > ManagedKeyProofCommand.MAX_COMMAND_BYTES) {
                throw invalid();
            }
            byte[] bytes = Base64.getUrlDecoder().decode(encoded);
            if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(encoded)) {
                throw invalid();
            }
            EncodedObject nested = new EncodedObject(Encoding.BINARY, bytes);
            DomainCommandEncoding.Decoded proofContainer = DomainCommandEncoding.decode(nested);
            if (SUBJECT_PROOFS_OPERATION.equals(proofContainer.operation())) {
                proofContainer.requireFields(4);
                if (!proofContainer.field(0).equals(command.field(18))) {
                    throw invalid();
                }
                nested = proofBytes(proofContainer.field(1));
                validateAlternative(command, proofContainer);
            }
            DomainCommandEncoding.Decoded proof = DomainContinuationValidation.validate(
                    DomainContinuationTemplate.create(DomainContinuationStore.Kind.KEY_PROOF, nested));
            ManagedKeyProofChallenge.requireOperation(proofId, proof.field(6));
            ManagedKeyProofRequest expected = new ManagedKeyProofRequest.CaSubject(new PkiId(command.field(1)),
                    CREATE.equals(command.operation()) ? Optional.empty() : Optional.of(new PkiId(command.field(2))),
                    command.field(7), new KeyRef(command.field(6)));
            if (!ManagedKeyProofCommand.decodePrefix(proof).equals(expected)
                    || !proof.field(11).equals(command.field(17))
                    || CREATE.equals(command.operation()) && command.field(6).equals(command.field(14))) {
                throw invalid();
            }
            DomainAttributeEncoding.decode(command.field(20));
            return proof;
        } catch (IllegalArgumentException malformed) {
            throw invalid();
        }
    }

    /**
     * Returns the optional independently bound alternative subject proof command.
     *
     * <p>The enclosing command supplies the outgoing alternative role, whose key,
     * algorithm identifier and SPKI commitment must match the nested proof. This
     * method validates retained metadata, not a signature or live candidate bytes.
     *
     * @param command complete intermediate continuation
     * @return alternative role command only for the explicit dual-proof container
     * @throws IllegalStateException if nested role evidence is inconsistent
     * @throws IllegalArgumentException if a nested encoding or required field is malformed
     * @throws NullPointerException if the command is null
     */
    public static Optional<DomainCommandEncoding.Decoded> alternativeProof(DomainCommandEncoding.Decoded command) {
        DomainCommandEncoding.Decoded container = DomainCommandEncoding.decode(proofBytes(command.field(19)));
        if (!SUBJECT_PROOFS_OPERATION.equals(container.operation())) {
            return Optional.empty();
        }
        container.requireFields(4);
        return Optional.of(validateAlternative(command, container));
    }

    /**
     * Returns the alternative provider step identity without consulting current state.
     *
     * <p>The caller must already have validated the enclosing command and dual-role
     * provenance. This accessor checks the container shape and extracts the identity;
     * it does not independently prove role distinctness or possession of the key.
     *
     * @param command exact validated intermediate command
     * @return retained alternative step identity, or an empty optional for a single proof
     * @throws IllegalStateException if the proof container cannot be represented safely
     * @throws IllegalArgumentException if its encoding, field count or identity is malformed
     * @throws NullPointerException if the command is null
     */
    public static Optional<PkiId> alternativeProofId(DomainCommandEncoding.Decoded command) {
        DomainCommandEncoding.Decoded container = DomainCommandEncoding.decode(proofBytes(command.field(19)));
        return SUBJECT_PROOFS_OPERATION.equals(container.operation())
                ? Optional.of(new PkiId(container.requireFields(4).field(2)))
                : Optional.empty();
    }

    /**
     * Encodes two separate subject proof commands in the existing excluded proof field.
     *
     * <p>Provider step identities must differ. The container retains exact binary
     * command bytes using canonical unpadded Base64url; semantic proof-role and
     * parent binding are checked when the enclosing command is validated, not by
     * interpreting a generated proof signature here.
     *
     * @param primaryId distinct primary provider-step identity
     * @param primary exact binary primary proof command
     * @param alternativeId distinct alternative provider-step identity
     * @param alternative exact binary alternative proof command
     * @return canonical explicit version-one proof container
     * @throws NullPointerException if a required argument is null
     * @throws IllegalStateException if identities coincide or a proof is not bounded binary content
     * @throws IllegalArgumentException if the complete domain encoding exceeds its bounds
     */
    public static String encodeProofs(PkiId primaryId, EncodedObject primary, PkiId alternativeId, EncodedObject alternative) {
        if (primaryId.equals(alternativeId)) {
            throw invalid();
        }
        return encodeProof(
                DomainCommandEncoding.template(
                                DomainContinuationStore.Kind.CA,
                                SUBJECT_PROOFS_OPERATION,
                                primaryId.value(),
                                encodeProof(primary),
                                alternativeId.value(),
                                encodeProof(alternative))
                        .command());
    }

    private static DomainCommandEncoding.Decoded validateAlternative(DomainCommandEncoding.Decoded command,
            DomainCommandEncoding.Decoded container) {
        if (command.fields().size() < EXTENDED_FIELDS
                || container.field(2).equals(command.field(18))) {
            throw invalid();
        }
        CaOutgoingBinding outgoing = CaOutgoingBinding.decodeForSubject(command.field(23), new KeyRef(command.field(6)));
        IssuerKeyBinding key = outgoing.alternative().orElseThrow(IntermediateSigningCommand::invalid);
        DomainCommandEncoding.Decoded proof = DomainContinuationValidation.validate(DomainContinuationTemplate.create(
                DomainContinuationStore.Kind.KEY_PROOF, proofBytes(container.field(3))));
        ManagedKeyProofChallenge.requireOperation(new PkiId(container.field(2)), proof.field(6));
        ManagedKeyProofRequest expected = new ManagedKeyProofRequest.CaSubject(new PkiId(command.field(1)),
                CREATE.equals(command.operation()) ? Optional.empty() : Optional.of(new PkiId(command.field(2))),
                command.field(7), key.keyRef());
        if (!ManagedKeyProofCommand.decodePrefix(proof).equals(expected)
                || !proof.field(8).equals(key.signatureAlgorithm().canonicalForm())
                || !proof.field(9).equals(HexFormat.of().formatHex(key.signatureAlgorithmIdentifier().bytes()))
                || !proof.field(11).equals(key.subjectSpkiSha256())) {
            throw invalid();
        }
        return proof;
    }

    private static EncodedObject proofBytes(String encoded) {
        if (encoded.isEmpty() || encoded.length() > ManagedKeyProofCommand.MAX_COMMAND_BYTES) {
            throw invalid();
        }
        byte[] bytes = Base64.getUrlDecoder().decode(encoded);
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(encoded)) {
            throw invalid();
        }
        return new EncodedObject(Encoding.BINARY, bytes);
    }

    /**
     * Requires the frozen proof's provider identity and the parent's
     * signing authority to match the consuming envelope. No proof lookup occurs.
     *
     * <p>The candidate must be operation-owned DER with the committed TBS length
     * and digest. The envelope's signing key belongs to the parent certificate
     * signature; the subject proof retains its separate outgoing role evidence.
     * No staged bytes are opened and no provider is invoked.
     *
     * @param envelope immutable intermediate signing acceptance
     * @throws NullPointerException if the envelope is null
     * @throws IllegalStateException if the outer operation, proof, provider, key or candidate binding differs
     * @throws IllegalArgumentException if an encoded command or binding is malformed
     */
    public static void requireEnvelope(SignWorkflowStore.AcceptanceEnvelope envelope) {
        SignWorkflowStore.OuterCommand outer = envelope.outer().orElseThrow(IntermediateSigningCommand::invalid);
        if (outer.kind() != DomainContinuationStore.Kind.CA) {
            throw invalid();
        }
        DomainCommandEncoding.Decoded command = DomainContinuationValidation.validate(new DomainContinuationTemplate(
                outer.kind(), Optional.of(outer.correlationId()), outer.command(), outer.commandCommitment()));
        DomainCommandEncoding.Decoded proof = validate(command);
        requireCandidate(command, envelope.candidate());
        if (!proof.field(6).equals(envelope.providerNamespace())
                || !proof.field(7).equals(HexFormat.of().formatHex(envelope.providerConfigurationCommitment().bytes()))
                || !command.field(14).equals(envelope.keyRef().value())
                || !command.field(1).equals(envelope.fairnessAuthorityId().value())
                || envelope.signatureEncoding() != Encoding.BINARY
                || envelope.candidate().encoding() != Encoding.DER
                || envelope.candidate().lifecycle() != DurableContentReference.Lifecycle.OPERATION) {
            throw invalid();
        }
    }

    /**
     * Binds immutable candidate metadata to the frozen exact TBS commitment.
     * Completed observations use retained metadata without opening retired bytes.
     *
     * @param command validated intermediate command
     * @param candidate exact immutable DER operation candidate
     * @throws NullPointerException if either argument is null
     * @throws IllegalStateException if encoding, lifecycle, length or digest differs
     * @throws IllegalArgumentException if a required length or command field is malformed
     */
    public static void requireCandidate(DomainCommandEncoding.Decoded command, DurableContentReference candidate) {
        if (candidate.encoding() != Encoding.DER || candidate.lifecycle() != DurableContentReference.Lifecycle.OPERATION
                || candidate.length() != ManagedKeyProofCommand.positiveLength(command.field(21), 1_048_576)
                || !candidate.sha256().equals(command.field(22))) {
            throw invalid();
        }
    }

    /**
     * Encodes a frozen proof command without changing its exact binary bytes.
     *
     * <p>The caller supplies an already validated semantic proof command. This
     * helper checks only binary encoding and size; it neither proves key possession
     * nor reinterprets command contents.
     *
     * @param command validated binary proof command
     * @return canonical unpadded base64url
     * @throws NullPointerException if the command is null
     * @throws IllegalStateException if its encoding is not binary or its size exceeds the command bound
     */
    public static String encodeProof(EncodedObject command) {
        if (command.encoding() != Encoding.BINARY || command.byteLength() > ManagedKeyProofCommand.MAX_COMMAND_BYTES) {
            throw invalid();
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(command.bytes());
    }

    /**
     * Bounds exact framed size before encoding a prospective command.
     * @param operation exact supported intermediate operation discriminator
     * @param correlation private stable operation correlation
     * @param fields exact canonical 23-, 25- or 26-field signing payload
     * @return complete validated template, with no staging or store activity
     * @throws NullPointerException if the field list or a required coordinate is null
     * @throws IllegalStateException if the discriminator, field count, aggregate bound
     *         or frozen proof provenance is inconsistent
     * @throws IllegalArgumentException if text, correlation or nested encoding is malformed
     */
    public static DomainContinuationTemplate template(String operation, String correlation, List<String> fields) {
        requireBound(operation, fields);
        DomainContinuationTemplate template = DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.CA,
                correlation, operation, fields.toArray(String[]::new));
        DomainContinuationValidation.validate(template);
        return template;
    }

    private static void requireBound(String operation, List<String> fields) {
        if (!supports(operation)
                || (fields.size() != 23
                        && fields.size() != EXTENDED_FIELDS
                        && fields.size() != LIFECYCLE_FIELDS)) {
            throw invalid();
        }
        long bytes = 13L + operation.length();
        for (String field : fields) {
            bytes += 4L + ManagedKeyProofCommand.utf8Length(field, ManagedKeyProofCommand.MAX_COMMAND_BYTES);
            if (bytes > ManagedKeyProofCommand.MAX_COMMAND_BYTES) {
                throw invalid();
            }
        }
    }

    private static IllegalStateException invalid() {
        return new IllegalStateException("Intermediate signing proof provenance is inconsistent");
    }

    /** Frozen context checks independent of retained proof decoding. */
    private static final class ProofValidation {
        private static void requireContext(DomainCommandEncoding.Decoded command) {
            if (!supports(command.operation())) {
                throw invalid();
            }
            if (command.fields().size() >= EXTENDED_FIELDS) {
                CaOutgoingBinding.decodeForSubject(command.field(23), new KeyRef(command.field(6)));
            } else {
                command.requireFields(23);
            }
            requireBound(command.operation(), command.fields());
            if (command.fields().size() == LIFECYCLE_FIELDS) {
                CaLifecycleContext context =
                        CaLifecycleContextCodec.decode(command.field(EXTENDED_FIELDS));
                if (CREATE.equals(command.operation())
                        || !context.expectedHead().caId().value().equals(command.field(2))
                        || ISSUE.equals(command.operation())
                                != (context.operation()
                                        == CaLifecycleContext.Operation.INTERMEDIATE_ISSUE)
                        || context.operation() == CaLifecycleContext.Operation.ROOT_CANDIDATE
                        || context.operation() == CaLifecycleContext.Operation.ROOT_ROLLOVER) {
                    throw invalid();
                }
            }
            if (command.fields().size() >= EXTENDED_FIELDS) {
                CaOutgoingBinding.decodeForSubject(
                        command.field(24), new KeyRef(command.field(14)));
            }
            ManagedKeyProofCommand.positiveLength(command.field(21), 1_048_576);
            ManagedKeyProofCommand.hex(command.field(22), 32, 32);
        }
    }
}
