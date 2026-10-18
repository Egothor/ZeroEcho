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

import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;

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
 */
public final class IntermediateSigningCommand {
    /** Creates a new intermediate authority. */
    public static final String CREATE = "CREATE_INTERMEDIATE";
    /** Adds a credential to an existing intermediate authority. */
    public static final String ISSUE = "ISSUE_INTERMEDIATE";
    /** Advances an existing intermediate authority to a new issuer generation. */
    public static final String ROLLOVER = "ROLLOVER_INTERMEDIATE";

    private IntermediateSigningCommand() { }

    /**
     * Identifies the closed set sharing this exact 23-field schema.
     * @param operation discriminator to test, possibly null
     * @return true only for creation, additional issuance or rollover
     */
    public static boolean supports(String operation) {
        return CREATE.equals(operation) || ISSUE.equals(operation) || ROLLOVER.equals(operation);
    }

    /**
     * Validates frozen proof coordinates and canonical provenance only.
     * @param command complete 23-field intermediate signing command
     * @return exact nested, complete canonical proof command
     * @throws IllegalStateException if frozen provenance is inconsistent
     */
    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    public static DomainCommandEncoding.Decoded validate(DomainCommandEncoding.Decoded command) {
        if (!supports(command.operation())) { throw invalid(); }
        command.requireFields(23);
        requireBound(command.operation(), command.fields());
        ManagedKeyProofCommand.positiveLength(command.field(21), 1_048_576);
        ManagedKeyProofCommand.hex(command.field(22), 32, 32);
        try {
            ManagedKeyProofCommand.utf8Length(command.field(18), 4096);
            PkiId proofId = new PkiId(command.field(18));
            String encoded = command.field(19);
            if (encoded.isEmpty() || encoded.length() > ManagedKeyProofCommand.MAX_COMMAND_BYTES) { throw invalid(); }
            byte[] bytes = Base64.getUrlDecoder().decode(encoded);
            if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(encoded)) { throw invalid(); }
            EncodedObject nested = new EncodedObject(Encoding.BINARY, bytes);
            DomainCommandEncoding.Decoded proof = DomainContinuationValidation.validate(
                    DomainContinuationTemplate.create(DomainContinuationStore.Kind.KEY_PROOF, nested));
            ManagedKeyProofChallenge.requireOperation(proofId, proof.field(6));
            ManagedKeyProofRequest expected = new ManagedKeyProofRequest.CaSubject(new PkiId(command.field(1)),
                    CREATE.equals(command.operation()) ? Optional.empty() : Optional.of(new PkiId(command.field(2))),
                    command.field(7), new KeyRef(command.field(6)));
            if (!ManagedKeyProofCommand.decodePrefix(proof).equals(expected)
                    || !proof.field(11).equals(command.field(17))
                    || CREATE.equals(command.operation()) && command.field(6).equals(command.field(14))) { throw invalid(); }
            DomainAttributeEncoding.decode(command.field(20));
            return proof;
        } catch (IllegalArgumentException malformed) { throw invalid(); }
    }

    /**
     * Requires the frozen proof's provider identity and the parent's
     * signing authority to match the consuming envelope. No proof lookup occurs.
     * @param envelope immutable intermediate signing acceptance
     */
    public static void requireEnvelope(SignWorkflowStore.AcceptanceEnvelope envelope) {
        SignWorkflowStore.OuterCommand outer = envelope.outer().orElseThrow(IntermediateSigningCommand::invalid);
        if (outer.kind() != DomainContinuationStore.Kind.CA) { throw invalid(); }
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
                || envelope.candidate().lifecycle() != DurableContentReference.Lifecycle.OPERATION) { throw invalid(); }
    }

    /**
     * Binds immutable candidate metadata to the frozen exact TBS commitment.
     * Completed observations use retained metadata without opening retired bytes.
     * @param command validated intermediate command
     * @param candidate exact immutable DER operation candidate
     */
    public static void requireCandidate(DomainCommandEncoding.Decoded command, DurableContentReference candidate) {
        if (candidate.encoding() != Encoding.DER || candidate.lifecycle() != DurableContentReference.Lifecycle.OPERATION
                || candidate.length() != ManagedKeyProofCommand.positiveLength(command.field(21), 1_048_576)
                || !candidate.sha256().equals(command.field(22))) { throw invalid(); }
    }

    /**
     * Encodes a frozen proof command without changing its exact binary bytes.
     * @param command validated binary proof command
     * @return canonical unpadded base64url
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
     * @param fields exact 23 canonical signing fields
     * @return complete validated template, with no staging or store activity
     */
    public static DomainContinuationTemplate template(String operation, String correlation, List<String> fields) {
        requireBound(operation, fields);
        DomainContinuationTemplate template = DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.CA,
                correlation, operation, fields.toArray(String[]::new));
        DomainContinuationValidation.validate(template);
        return template;
    }

    private static void requireBound(String operation, List<String> fields) {
        if (!supports(operation) || fields.size() != 23) { throw invalid(); }
        long bytes = 13L + operation.length();
        for (String field : fields) {
            bytes += 4L + ManagedKeyProofCommand.utf8Length(field, ManagedKeyProofCommand.MAX_COMMAND_BYTES);
            if (bytes > ManagedKeyProofCommand.MAX_COMMAND_BYTES) { throw invalid(); }
        }
    }

    private static IllegalStateException invalid() {
        return new IllegalStateException("Intermediate signing proof provenance is inconsistent");
    }
}
