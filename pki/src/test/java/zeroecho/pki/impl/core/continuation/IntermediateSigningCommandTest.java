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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.spi.crypto.SigningProvider.ConfigurationCommitment;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.IntermediateProofProvenanceFixture;

final class IntermediateSigningCommandTest {
    private static final String NAMESPACE = "store.provider";
    private static final ConfigurationCommitment CONFIGURATION = new ConfigurationCommitment(new byte[32]);
    private static final Instant NOW = Instant.EPOCH;
    private static final String HASH = "1".repeat(64);

    @ParameterizedTest
    @ValueSource(strings = {"CREATE_INTERMEDIATE", "ISSUE_INTERMEDIATE", "ROLLOVER_INTERMEDIATE"})
    void retainsExactCanonicalNestedProofWithoutLookup(String operation) {
        DomainContinuationTemplate template = valid(operation);
        DomainCommandEncoding.Decoded command = DomainContinuationValidation.validate(template);
        DomainCommandEncoding.Decoded nested = IntermediateSigningCommand.validate(command);
        assertEquals("CA_SUBJECT_KEY", nested.field(0));
        assertEquals("issuer", nested.field(1));
        assertEquals(IntermediateSigningCommand.CREATE.equals(operation) ? "" : "child", nested.field(2));
        assertEquals("profile", nested.field(3));
        assertEquals("child-key", nested.field(5));
        assertEquals(command.field(17), nested.field(11));
        IntermediateSigningCommand.requireEnvelope(envelope(template, NAMESPACE, CONFIGURATION, "parent-key", "issuer"));
        DomainContinuationTemplate encoded = IntermediateSigningCommand.template(operation, "creation", command.fields());
        assertEquals(template.commandCommitment(), encoded.commandCommitment());
    }

    @ParameterizedTest
    @ValueSource(strings = {"CREATE_INTERMEDIATE", "ISSUE_INTERMEDIATE", "ROLLOVER_INTERMEDIATE"})
    void rejectsChangedScopeSpkiProofIdentityAndNoncanonicalProvenance(String operation) {
        List<String> fields = DomainCommandEncoding.decode(valid(operation).command()).fields();
        for (int field : new int[] {1, 6, 7, 17, 18, 19, 20, 21, 22}) {
            List<String> changed = new ArrayList<>(fields);
            changed.set(field, field == 17 ? "2".repeat(64) : "changed");
            assertThrows(RuntimeException.class, () -> DomainContinuationValidation.validate(template(operation, changed)));
        }
        for (String malformed : List.of(fields.get(19) + "=", " ", "x".repeat(1_048_577))) {
            List<String> changed = new ArrayList<>(fields);
            changed.set(19, malformed);
            assertThrows(RuntimeException.class, () -> IntermediateSigningCommand.validate(
                    new DomainCommandEncoding.Decoded(operation, changed)));
        }
        List<String> foreignId = new ArrayList<>(fields);
        foreignId.set(18, "zsign:v1:other:0:" + "0".repeat(32));
        assertThrows(IllegalStateException.class, () -> DomainContinuationValidation.validate(template(operation, foreignId)));
        DomainCommandEncoding.Decoded proof = nested(fields);
        for (int field : new int[] {0, 1, 2, 3, 5, 11}) {
            List<String> changedProof = new ArrayList<>(proof.fields());
            changedProof.set(field, field == 11 ? "2".repeat(64) : "different");
            List<String> changed = new ArrayList<>(fields);
            changed.set(19, IntermediateSigningCommand.encodeProof(DomainCommandEncoding.template(
                    DomainContinuationStore.Kind.KEY_PROOF, ManagedKeyProofCommand.OPERATION,
                    changedProof.toArray(String[]::new)).command()));
            assertThrows(RuntimeException.class, () -> DomainContinuationValidation.validate(template(operation, changed)));
        }
        List<String> truncatedProof = new ArrayList<>(fields);
        truncatedProof.set(19, IntermediateSigningCommand.encodeProof(DomainCommandEncoding.template(
                DomainContinuationStore.Kind.KEY_PROOF, ManagedKeyProofCommand.OPERATION,
                proof.fields().subList(0, 6).toArray(String[]::new)).command()));
        assertThrows(RuntimeException.class, () -> DomainContinuationValidation.validate(template(operation, truncatedProof)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"CREATE_INTERMEDIATE", "ISSUE_INTERMEDIATE", "ROLLOVER_INTERMEDIATE"})
    void frozenTbsLengthAndDigestRejectCandidateSubstitution(String operation) {
        DomainCommandEncoding.Decoded original = DomainContinuationValidation.validate(valid(operation));
        DurableContentReference candidate = envelope(valid(operation), NAMESPACE, CONFIGURATION, "parent-key", "issuer").candidate();
        IntermediateSigningCommand.requireCandidate(original, candidate);
        for (int field : new int[] {21, 22}) {
            List<String> changed = new ArrayList<>(original.fields());
            changed.set(field, field == 21 ? "2" : "2".repeat(64));
            DomainContinuationTemplate substituted = template(operation, changed);
            assertThrows(IllegalStateException.class, () -> IntermediateSigningCommand.requireEnvelope(
                    envelope(substituted, NAMESPACE, CONFIGURATION, "parent-key", "issuer")));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"CREATE_INTERMEDIATE", "ISSUE_INTERMEDIATE", "ROLLOVER_INTERMEDIATE"})
    void rejectsConsumingProviderParentKeyAndFairnessMismatches(String operation) {
        DomainContinuationTemplate template = valid(operation);
        ConfigurationCommitment different = new ConfigurationCommitment(java.util.HexFormat.of().parseHex("2".repeat(64)));
        for (SignWorkflowStore.AcceptanceEnvelope invalid : List.of(
                envelope(template, "foreign.provider", CONFIGURATION, "parent-key", "issuer"),
                envelope(template, NAMESPACE, different, "parent-key", "issuer"),
                envelope(template, NAMESPACE, CONFIGURATION, "child-key", "issuer"),
                envelope(template, NAMESPACE, CONFIGURATION, "parent-key", "different"))) {
            assertThrows(IllegalStateException.class, () -> IntermediateSigningCommand.requireEnvelope(invalid));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"CREATE_INTERMEDIATE", "ISSUE_INTERMEDIATE", "ROLLOVER_INTERMEDIATE"})
    void exactAggregateBoundIncludesFramingBeforeEncoding(String operation) {
        DomainContinuationTemplate initial = valid(operation);
        List<String> fields = new ArrayList<>(DomainCommandEncoding.decode(initial.command()).fields());
        int remaining = ManagedKeyProofCommand.MAX_COMMAND_BYTES - initial.command().byteLength();
        fields.set(10, fields.get(10) + "x".repeat(remaining));
        assertEquals(ManagedKeyProofCommand.MAX_COMMAND_BYTES,
                IntermediateSigningCommand.template(operation, "creation", fields).command().byteLength());
        fields.set(10, fields.get(10) + "x");
        assertThrows(IllegalStateException.class, () -> IntermediateSigningCommand.template(operation, "creation", fields));
    }

    @ParameterizedTest
    @ValueSource(strings = {"CREATE_INTERMEDIATE", "ISSUE_INTERMEDIATE", "ROLLOVER_INTERMEDIATE"})
    void rejectsLegacy21FieldsAndRequiresOperationSpecificSubjectScope(String operation) {
        List<String> fields = DomainCommandEncoding.decode(valid(operation).command()).fields();
        assertThrows(IllegalArgumentException.class, () -> DomainContinuationValidation.validate(template(operation, fields.subList(0, 21))));
        List<String> changed = new ArrayList<>(fields);
        DomainCommandEncoding.Decoded proof = nested(fields);
        List<String> proofFields = new ArrayList<>(proof.fields());
        proofFields.set(2, IntermediateSigningCommand.CREATE.equals(operation) ? "child" : "");
        changed.set(19, IntermediateSigningCommand.encodeProof(DomainCommandEncoding.template(
                DomainContinuationStore.Kind.KEY_PROOF, ManagedKeyProofCommand.OPERATION, proofFields.toArray(String[]::new)).command()));
        assertThrows(RuntimeException.class, () -> DomainContinuationValidation.validate(template(operation, changed)));
        if (!IntermediateSigningCommand.CREATE.equals(operation)) {
            List<String> differentSubject = new ArrayList<>(fields);
            differentSubject.set(2, "another-subject");
            assertThrows(IllegalStateException.class, () -> DomainContinuationValidation.validate(template(operation, differentSubject)));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"CREATE_INTERMEDIATE", "ISSUE_INTERMEDIATE", "ROLLOVER_INTERMEDIATE"})
    void parentSubjectKeyInequalityAppliesOnlyToCreation(String operation) {
        List<String> fields = new ArrayList<>(DomainCommandEncoding.decode(valid(operation).command()).fields());
        fields.set(14, "child-key");
        if (IntermediateSigningCommand.CREATE.equals(operation)) {
            assertThrows(IllegalStateException.class, () -> DomainContinuationValidation.validate(template(operation, fields)));
        } else {
            DomainContinuationTemplate sameKey = template(operation, fields);
            DomainContinuationValidation.validate(sameKey);
            IntermediateSigningCommand.requireEnvelope(envelope(sameKey, NAMESPACE, CONFIGURATION, "child-key", "issuer"));
        }
    }

    @Test void rejectsDiscriminatorsOutsideTheThreeOperationSchema() {
        List<String> fields = DomainCommandEncoding.decode(valid(IntermediateSigningCommand.CREATE).command()).fields();
        assertThrows(IllegalStateException.class, () -> IntermediateSigningCommand.template("CREATE_ROOT", "creation", fields));
    }

    private static DomainCommandEncoding.Decoded nested(List<String> fields) {
        return DomainCommandEncoding.decode(new EncodedObject(Encoding.BINARY, Base64.getUrlDecoder().decode(fields.get(19))));
    }

    private static DomainContinuationTemplate valid(String operation) {
        return IntermediateProofProvenanceFixture.withProof(DomainCommandEncoding.correlatedTemplate(
                DomainContinuationStore.Kind.CA, "creation", operation,
                "x509", "issuer", "child", "generation", "path", HASH, "child-key", "profile", "1", HASH,
                "CN=Child", NOW.toString(), NOW.plusSeconds(60).toString(), "1", "parent-key", "issuer-content",
                HASH, HASH, "", "", ""), NAMESPACE, CONFIGURATION, 1, HASH);
    }

    private static DomainContinuationTemplate template(String operation, List<String> fields) {
        return DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.CA, "creation",
                operation, fields.toArray(String[]::new));
    }

    private static SignWorkflowStore.AcceptanceEnvelope envelope(DomainContinuationTemplate template,
            String namespace, ConfigurationCommitment configuration, String key, String fairness) {
        DurableContentReference candidate = new DurableContentReference() {
            @Override public String storeId() { return "store"; }
            @Override public String contentId() { return "candidate"; }
            @Override public Encoding encoding() { return Encoding.DER; }
            @Override public long length() { return 1; }
            @Override public String sha256() { return HASH; }
            @Override public Lifecycle lifecycle() { return Lifecycle.OPERATION; }
        };
        return SignWorkflowStore.AcceptanceEnvelope.from(new SignWorkflowStore.AcceptanceCommand(
                new PkiId("zsign:v1:" + namespace + ":0:" + "1".repeat(32)), namespace, configuration,
                new AccessContext(new Principal("TEST", "actor"), new Purpose("CREATE"), Optional.empty(), Optional.empty()),
                new KeyRef(key), new PkiId(fairness), BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm(),
                Encoding.BINARY, NOW, NOW.plusSeconds(60), candidate, Optional.of(new SignWorkflowStore.OuterCommand(
                        template.kind(), template.correlationId().orElseThrow(), template.command(), template.commandCommitment())),
                        SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty()));
    }
}
